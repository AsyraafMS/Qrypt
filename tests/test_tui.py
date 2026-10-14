import asyncio
import copy
import importlib
import json

import pytest
from textual.widgets import DataTable, Input, Static

from qrypt.cli import main

ENTRY = {
    "rule_id": "qrypt.javascript.rsa-keygen",
    "path": "app.js",
    "line": 2,
    "column": 1,
    "algorithm": "RSA",
    "operation": "key-generation",
    "confidence": "high",
    "guidance": "Review key purpose before migration.",
    "migration_candidate": True,
}
REPORT = {
    "schema_version": 1,
    "status": "completed",
    "scanned_files": 1,
    "skipped_files": 0,
    "coverage": "Zero findings does not establish PQC readiness.",
    "findings": [{k: v for k, v in ENTRY.items() if k != "migration_candidate"}],
    "inventory": [ENTRY],
    "errors": [],
}


def _text(app, widget):
    return str(app.query_one(widget, Static).content)


def test_no_arguments_launches_only_on_interactive_streams(monkeypatch):
    tui = importlib.import_module("qrypt.tui")
    monkeypatch.setattr("qrypt.cli.sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("qrypt.cli.sys.stdout.isatty", lambda: True)
    monkeypatch.setattr(tui, "launch", lambda: 7)
    assert main([]) == 7


@pytest.mark.parametrize("stdin,stdout", [(False, True), (True, False), (False, False)])
def test_redirected_no_arguments_print_usage(monkeypatch, capsys, stdin, stdout):
    monkeypatch.setattr("qrypt.cli.sys.stdin.isatty", lambda: stdin)
    monkeypatch.setattr("qrypt.cli.sys.stdout.isatty", lambda: stdout)
    assert main([]) == 2
    captured = capsys.readouterr()
    assert "usage:" in captured.err
    assert "\x1b" not in captured.err + captured.out


@pytest.mark.parametrize("size", [(120, 42), (48, 22)])
def test_prompt_help_history_and_narrow_layout(size):
    tui = importlib.import_module("qrypt.tui")

    async def exercise():
        app = tui.QryptApp()
        async with app.run_test(size=size) as pilot:
            prompt = app.query_one("#command", Input)
            assert app.focused is prompt
            assert prompt.region.bottom <= size[1]
            if size[0] < 70:
                assert _text(app, "#banner") == "QRYPT"
            prompt.value = "/help"
            await pilot.press("enter")
            assert "/scan" in _text(app, "#details")
            assert prompt.value == ""
            await pilot.press("up")
            assert prompt.value == "/help"
            await pilot.press("down")
            assert prompt.value == ""
            await pilot.press("tab")
            assert app.focused is not prompt

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "command,expected",
    [
        ("/wat", "Unknown command"),
        ('/scan "unterminated', "No closing quotation"),
        ("/scan a b", "Usage: /scan"),
        ("/help extra", "Usage: /help"),
        ("/quit extra", "Usage: /quit"),
        ("/export json", "Usage: /export"),
        ("/export html report.html", "format"),
        ("/export json report.json", "Scan first"),
    ],
)
def test_invalid_commands_are_recoverable(command, expected):
    tui = importlib.import_module("qrypt.tui")

    async def exercise():
        app = tui.QryptApp()
        async with app.run_test():
            await app.submit_command(command)
            assert expected in _text(app, "#message")
            assert app.report is None
            await app.submit_command("/help")
            assert "/export" in _text(app, "#details")

    asyncio.run(exercise())


def test_results_details_and_literal_untrusted_display(monkeypatch, tmp_path):
    tui = importlib.import_module("qrypt.tui")
    report = copy.deepcopy(REPORT)
    report["inventory"][0]["path"] = "[bold]clé\x1b[2J.js"
    report["inventory"][0]["guidance"] = "[link=https://evil]Review\x07"
    report["inventory"].append(
        {**ENTRY, "algorithm": "ML-KEM-768", "migration_candidate": False}
    )

    async def scan(target):
        assert target == tmp_path / "project with spaces"
        return report

    monkeypatch.setattr(tui, "run_scan", scan)
    monkeypatch.chdir(tmp_path)

    async def exercise():
        app = tui.QryptApp()
        async with app.run_test() as pilot:
            await app.submit_command('/scan "project with spaces"')
            await app.scan_task
            await pilot.pause()
            table = app.query_one("#results", DataTable)
            assert table.row_count == 2
            assert str(table.get_row_at(0)[0]) == "Candidate"
            assert str(table.get_row_at(1)[0]) == "PQC inventory"
            table.focus()
            table.move_cursor(row=0)
            await pilot.press("enter")
            assert "[bold]clé[2J.js" in _text(app, "#details")
            assert "[link=https://evil]Review" in _text(app, "#details")
            assert "\x1b" not in _text(app, "#details")
            assert "\x07" not in _text(app, "#details")
            assert "requiring verification" in _text(app, "#status")

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "format,suffix",
    [("text", "txt"), ("json", "json"), ("sarif", "sarif"), ("cbom", "json")],
)
def test_export_reuses_safe_reports(monkeypatch, tmp_path, format, suffix):
    tui = importlib.import_module("qrypt.tui")

    async def scan(target):
        return copy.deepcopy(REPORT)

    monkeypatch.setattr(tui, "run_scan", scan)
    monkeypatch.chdir(tmp_path)

    async def exercise():
        app = tui.QryptApp()
        async with app.run_test():
            await app.submit_command("/scan")
            await app.scan_task
            await app.submit_command(f'/export {format} "report with spaces.{suffix}"')
            content = (tmp_path / f"report with spaces.{suffix}").read_text()
            if format == "text":
                assert "RSA" in content
            elif format == "json":
                assert json.loads(content) == REPORT
            elif format == "sarif":
                assert len(json.loads(content)["runs"][0]["results"]) == 1
            else:
                assert len(json.loads(content)["components"]) == 1
            source = tmp_path / "app.py"
            source.write_text("do not overwrite")
            await app.submit_command("/export json app.py")
            assert source.read_text() == "do not overwrite"
            assert "regular .json" in _text(app, "#message")
            link = tmp_path / "link.json"
            link.symlink_to(source)
            await app.submit_command("/export json link.json")
            assert source.read_text() == "do not overwrite"

    asyncio.run(exercise())


def test_busy_and_failed_scan_preserve_labeled_results(monkeypatch, tmp_path):
    tui = importlib.import_module("qrypt.tui")

    async def exercise():
        gate = asyncio.Event()

        async def scan(target):
            if target.name == "good":
                return copy.deepcopy(REPORT)
            await gate.wait()
            raise ValueError("No valid report")

        monkeypatch.setattr(tui, "run_scan", scan)
        monkeypatch.chdir(tmp_path)
        app = tui.QryptApp()
        async with app.run_test():
            await app.submit_command("/scan good")
            await app.scan_task
            await app.submit_command("/scan bad")
            active = app.scan_task
            await app.submit_command("/scan other")
            assert app.scan_task is active
            await app.submit_command("/export json forbidden.json")
            assert not (tmp_path / "forbidden.json").exists()
            assert "Scan in progress" in _text(app, "#message")
            gate.set()
            await active
            assert app.report == REPORT
            assert "good" in _text(app, "#status")
            assert "bad" in _text(app, "#message")
            assert "No valid report" in _text(app, "#message")

    asyncio.run(exercise())


def test_real_incomplete_scan_and_export(tmp_path, monkeypatch):
    tui = importlib.import_module("qrypt.tui")
    (tmp_path / "nginx.conf").write_text("ssl_ecdh_curve X25519:$groups;\n")
    monkeypatch.chdir(tmp_path)

    async def exercise():
        app = tui.QryptApp()
        async with app.run_test():
            await app.submit_command("/scan .")
            await asyncio.wait_for(app.scan_task, 20)
            assert app.report["status"] == "incomplete"
            assert app.query_one("#results", DataTable).row_count == 1
            assert "incomplete" in _text(app, "#status")
            assert "TLSUnresolvedSetting" in _text(app, "#details")
            await app.submit_command("/export json report.json")
            assert json.loads((tmp_path / "report.json").read_text())["errors"]

    asyncio.run(exercise())


def test_quit_cancels_active_scan_before_exit(monkeypatch):
    tui = importlib.import_module("qrypt.tui")

    async def exercise():
        started = asyncio.Event()
        stopped = asyncio.Event()

        async def scan(target):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        monkeypatch.setattr(tui, "run_scan", scan)
        app = tui.QryptApp()
        async with app.run_test() as pilot:
            await app.submit_command("/scan")
            await started.wait()
            await pilot.press("ctrl+c")
            assert stopped.is_set()
            assert app.scan_task.done()

    asyncio.run(exercise())


def test_empty_report_replaces_old_rows(monkeypatch):
    tui = importlib.import_module("qrypt.tui")
    empty = {**copy.deepcopy(REPORT), "findings": [], "inventory": []}

    async def scan(target):
        return copy.deepcopy(REPORT) if target.name == "first" else empty

    monkeypatch.setattr(tui, "run_scan", scan)

    async def exercise():
        app = tui.QryptApp()
        async with app.run_test():
            await app.submit_command("/scan first")
            await app.scan_task
            assert app.query_one("#results", DataTable).row_count == 1
            await app.submit_command("/scan empty")
            await app.scan_task
            assert app.query_one("#results", DataTable).row_count == 0
            assert "No observations" in _text(app, "#details")
            assert "does not establish PQC readiness" in _text(app, "#details")
            assert "empty" in _text(app, "#status")

    asyncio.run(exercise())


@pytest.mark.parametrize("empty", [True, False])
def test_queued_row_selection_does_not_use_replacement_report(monkeypatch, empty):
    tui = importlib.import_module("qrypt.tui")

    async def exercise():
        gate = asyncio.Event()

        async def scan(target):
            if target.name == "first":
                return copy.deepcopy(REPORT)
            await gate.wait()
            replacement = copy.deepcopy(REPORT)
            if empty:
                replacement.update(findings=[], inventory=[])
            else:
                replacement["inventory"][0]["path"] = "replacement.js"
            return replacement

        monkeypatch.setattr(tui, "run_scan", scan)
        app = tui.QryptApp()
        async with app.run_test() as pilot:
            await app.submit_command("/scan first")
            await app.scan_task
            await pilot.pause()
            table = app.query_one("#results", DataTable)
            await app.submit_command("/scan empty")
            gate.set()
            table.action_select_cursor()
            await app.scan_task
            await pilot.pause()
            assert app.is_running
            assert table.row_count == (0 if empty else 1)
            if empty:
                assert "No observations" in _text(app, "#details")
            else:
                assert "Select a finding" in _text(app, "#details")
                table.action_select_cursor()
                await pilot.pause()
                assert "replacement.js" in _text(app, "#details")

    asyncio.run(exercise())
