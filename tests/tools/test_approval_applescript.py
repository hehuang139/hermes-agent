"""Regression for #141346: GUI automation must not silently discard user work.

Commands are approval inputs only; these tests never launch osascript or a GUI.
"""

import shlex
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from hermes_cli import config
from tools import approval, approval_context


def _osascript(source, *, javascript=False):
    language = " -l JavaScript" if javascript else ""
    return f"/usr/bin/osascript{language} -e {shlex.quote(source)}"


@pytest.fixture
def smart_session(tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    home.mkdir()
    (home / "config.yaml").write_text(
        "approvals:\n  mode: smart\ncommand_allowlist: []\n", encoding="utf-8"
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_EXEC_ASK", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
    monkeypatch.delenv("HERMES_CRON_SESSION", raising=False)
    config._LOAD_CONFIG_CACHE.clear()
    session_key = "test:applescript:approval"
    session_token = approval_context.set_current_session_key(session_key)
    interactive_token = approval_context.set_hermes_interactive_context(True)
    approval.clear_session(session_key)
    guardian = Mock(return_value=SimpleNamespace(choices=[SimpleNamespace(
        message=SimpleNamespace(content="APPROVE")
    )]))
    monkeypatch.setattr("agent.auxiliary_client.call_llm", guardian)
    yield guardian
    approval.clear_session(session_key)
    approval_context.reset_hermes_interactive_context(interactive_token)
    approval_context.reset_current_session_key(session_token)
    config._LOAD_CONFIG_CACHE.clear()


@pytest.mark.parametrize("human_choice", ["deny", "once"])
@pytest.mark.parametrize("command", [
    _osascript('tell application "Microsoft PowerPoint" to close active presentation saving no'),
    _osascript('tell application "Microsoft PowerPoint" to close presentation 1 saving no'),
    _osascript('tell application "TextEdit" to quit saving no'),
    "osascript -e 'tell application \"Microsoft Word\"' -e 'delete document 1' -e 'end tell'",
    _osascript("Application('Microsoft Excel').workbooks[0].close({saving: 'no'})", javascript=True),
    _osascript("Application('Pages').documents[0].delete()", javascript=True),
    _osascript('var docs = Application("TextEdit").documents; '
               'for (var i = docs.length - 1; i >= 0; i--) docs[i].close({saving: "no"});', javascript=True),
    _osascript('tell application "System Events" to keystroke "w" using command down'),
    _osascript('tell application "System Events" to click button "Don\'t Save" of window 1 of process "TextEdit"'),
    "bash -c " + shlex.quote(_osascript('tell application "TextEdit" to quit saving no')),
    "osascript <<'APPLESCRIPT'\ntell application \"TextEdit\" to quit saving no\nAPPLESCRIPT",
    "osascript /tmp/render-presentation.scpt",
    'killall "Microsoft Word"',
    "pkill -f TextEdit",
    "pkill -9 Pages",
    "pkill -- -0",
    "killall -s 0 -s TERM TextEdit",
    "killall --signal=0 --signal=TERM TextEdit",
])
def test_gui_data_loss_requires_human_even_when_guardian_would_approve(
        smart_session, command, human_choice):
    decide = Mock(return_value=human_choice)

    result = approval.check_all_command_guards(command, "local", approval_callback=decide)

    assert decide.call_count == 1, result
    assert result["approved"] is (human_choice == "once")
    smart_session.assert_not_called()


@pytest.mark.parametrize("command", [
    _osascript('tell application "Microsoft PowerPoint" to get name of active presentation'),
    _osascript('tell application "Microsoft PowerPoint" to activate'),
    _osascript('tell application "System Events" to get name of every process'),
    _osascript('tell application "System Events" to get name of every process '
               '-- keystroke "w" using command down'),
    _osascript("Application('TextEdit').documents.length", javascript=True),
    _osascript('return "close active presentation saving no"'),
    "printf '%s\\n' " + shlex.quote('osascript -e \'tell application "TextEdit" to quit saving no\''),
    "killall -l",
    "killall -V",
    "pkill -0 -f TextEdit",
    "pkill --signal 0 TextEdit",
    "killall -s 0 TextEdit",
    "killall -s0 TextEdit",
    'cat <<\'END\'\nosascript -e \'tell application "TextEdit" to quit saving no\'\nEND',
])
def test_read_only_automation_and_quoted_command_examples_stay_allowed(smart_session, command):
    deny = Mock(return_value="deny")

    result = approval.check_all_command_guards(command, "local", approval_callback=deny)

    assert result["approved"] is True, result
    deny.assert_not_called()
    smart_session.assert_not_called()
