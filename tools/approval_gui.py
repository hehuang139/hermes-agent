"""Approval classification for commands that can discard unsaved application work.

The shell text cannot establish who owns an open document or whether a process
has unsaved state. These operations need a human decision, even in smart mode.
"""

import os
import re


GUI_DATA_LOSS_DESCRIPTION = "AppleScript/JXA may discard unsaved work or delete application data"
PROCESS_DATA_LOSS_DESCRIPTION = "process termination (pkill/killall) may discard unsaved application work"
OPAQUE_APPLESCRIPT_DESCRIPTION = "AppleScript/JXA source is unavailable for approval review"
MANUAL_GUI_DESCRIPTIONS = frozenset({
    GUI_DATA_LOSS_DESCRIPTION, PROCESS_DATA_LOSS_DESCRIPTION, OPAQUE_APPLESCRIPT_DESCRIPTION,
})

_SCRIPT_STRINGS = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
_APPLESCRIPT_DATA = re.compile(_SCRIPT_STRINGS + r'|--[^\n]*|\(\*.*?\*\)', re.DOTALL)
_JAVASCRIPT_DATA = re.compile(_SCRIPT_STRINGS + r'|//[^\n]*|/\*.*?\*/', re.DOTALL)
_SCRIPT_ACTION = re.compile(
    r'(?:^|[;\r\n]|\b(?:to|then|else|try)\s+)\s*(?:close|quit|delete)\b'
    r'|\.\s*(?:close|quit|delete)\s*\(', re.IGNORECASE,
)
_UI_CLOSE_KEY = re.compile(
    r'\b(?:keystroke\s*(?:\(\s*)?["\'][wq]["\']|key\s*code\s*(?:\(\s*)?(?:12|13)\b)'
    r'[^\n;]*\bcommand\s+down\b', re.IGNORECASE,
)
_UI_DISCARD_LABEL = re.compile(r'\b(?:don[\'’]?t save|discard|delete|close|quit)\b', re.IGNORECASE)


def _script_discards_work(source: str, javascript: bool) -> bool:
    data = _JAVASCRIPT_DATA if javascript else _APPLESCRIPT_DATA
    code = data.sub(lambda match: "\n" * match.group().count("\n") + " ", source)
    if _SCRIPT_ACTION.search(code):
        return True
    uncommented = data.sub(
        lambda match: match.group() if match.group().startswith(('"', "'")) else " ", source,
    )
    if "system events" not in uncommented.lower():
        return False
    return bool(_UI_CLOSE_KEY.search(uncommented) or (
        re.search(r"\bclick\b", code, re.IGNORECASE) and _UI_DISCARD_LABEL.search(uncommented)
    ))


def _inline_osascript_source(args: list[str]) -> tuple[str, bool] | None:
    """Join repeated -e statements; file/stdin source cannot be inspected here."""
    statements = []
    language = "applescript"
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"-e", "-l", "-s"}:
            if index + 1 >= len(args):
                return None
            if token == "-e":
                statements.append(args[index + 1])
            elif token == "-l":
                language = args[index + 1].lower()
            index += 2
        elif token.startswith("-e"):
            statements.append(token[2:])
            index += 1
        elif token.startswith("-l"):
            language = token[2:].lower()
            index += 1
        elif token == "-i" or token.startswith("-s"):
            index += 1
        else:
            break
    return ("\n".join(statements), language == "javascript") if statements else None


def _process_signal_option(name: str, token: str, following: str) -> str | None:
    if token == "--signal" or (name == "killall" and token == "-s"):
        return following
    if token.startswith("--signal="):
        return token.partition("=")[2]
    if name == "killall" and token.startswith("-s"):
        return token[2:]
    if re.fullmatch(r"-(?:\d+|[A-Z][A-Z0-9+_-]+)", token):
        return token[1:]
    return None


def _terminates_named_process(name: str, args: list[str]) -> bool:
    """Keep signal listing/version/help and signal-zero liveness probes read-only."""
    options = args[:args.index("--")] if "--" in args else args
    queries = {"--help", "--version", "-V"}
    if name == "killall":
        queries.update({"-l", "--list"})
    if queries.intersection(options):
        return False
    signals = {
        value for token, following in zip(options, [*options[1:], ""])
        if (value := _process_signal_option(name, token, following)) is not None
    }
    # An earlier signal-zero option does not make a later terminating signal harmless.
    return bool(args) and signals != {"0"}


def gui_data_loss_description(command: str) -> str | None:
    """Inspect actual command words and shell -c payloads, never quoted examples.

    Reuse the approval parser so wrapper handling and shell quoting stay aligned
    with the other command guards. No script or process is executed.
    """
    from tools.approval_detection import (
        _deobfuscate_shell_word_for_detection, _execution_flag_findings,
        _iter_shell_command_word_spans, _iter_top_level_shell_segments, _shell_segment_tokens,
    )
    from tools.shell_heredoc import strip_inert_heredoc_bodies

    pending, seen = [command], set()
    while pending:
        source = strip_inert_heredoc_bodies(pending.pop())
        if source in seen:
            continue
        seen.add(source)
        for segment in _iter_top_level_shell_segments(source):
            for start, _, word in _iter_shell_command_word_spans(segment):
                name = os.path.basename(_deobfuscate_shell_word_for_detection(word)).lower()
                if name not in {"osascript", "killall", "pkill"}:
                    continue
                tokens = _shell_segment_tokens(segment, start)
                if tokens is None:
                    return GUI_DATA_LOSS_DESCRIPTION
                args = tokens[1:]
                if name == "osascript":
                    script = _inline_osascript_source(args)
                    if script is None:
                        return OPAQUE_APPLESCRIPT_DESCRIPTION
                    if _script_discards_work(*script):
                        return GUI_DATA_LOSS_DESCRIPTION
                elif _terminates_named_process(name, args):
                    return PROCESS_DATA_LOSS_DESCRIPTION
        pending.extend(payload for _, payload in _execution_flag_findings(source) if payload)
    return None
