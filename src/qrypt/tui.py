"""Interactive commands over the existing local scanner and report exporters."""

import asyncio
import os
import shlex
import sys
import unicodedata
from pathlib import Path

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Input, Static

from qrypt.banner import BANNER
from qrypt.cli import _validate_output, _write_report, render_report
from qrypt.tui_process import run_scan

HELP = """/scan [path]                 Scan a project or supported file (default: .)
/export <format> <path>       Save text, json, sarif or cbom; may replace a report
/help                        Show this help
/quit                        Stop the active scan and exit

Quote paths containing spaces. Paths use the startup directory.
Tab: move focus · Arrow keys: navigate results/history · Enter: finding details
Ctrl+C: quit safely. Reports and command history are never saved automatically.

Findings require verification. Zero findings does not establish PQC readiness.
Supported PQC identifiers do not establish deployed support or system readiness."""


def _literal(value: str) -> Text:
    return Text(
        "".join(
            char
            for char in value
            if char in "\n\t" or not unicodedata.category(char).startswith("C")
        )
    )


class QryptApp(App[int]):
    TITLE = "QRYPT"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [Binding("ctrl+c", "quit", "Quit", priority=True)]
    CSS = """
    Screen { background: #0d1117; color: #e6edf3; padding: 0 1; }
    #banner { height: auto; color: #67e8f9; }
    #workspace, #status, #coverage, #message { height: auto; }
    #workspace, #coverage { color: #9ca3af; }
    #status { color: #67e8f9; margin-top: 1; }
    #results { height: 1fr; min-height: 4; border: solid #334155; }
    #detail-panel { height: 1fr; min-height: 4; border: solid #334155; }
    #details { height: auto; }
    #message { color: #fbbf24; }
    #command { dock: bottom; margin: 0; }
    #short-help { dock: bottom; height: 1; color: #9ca3af; }
    """

    def __init__(self):
        super().__init__()
        self.directory = Path.cwd()
        self.report = None
        self.report_target = None
        self._row_entries = {}
        self.scan_task = None
        self.busy = False
        self.history = []
        self.history_index = 0
        self.draft = ""
        self._quitting = False

    def compose(self) -> ComposeResult:
        yield Static(BANNER, id="banner", markup=False)
        yield Static(_literal(f"Project: {self.directory}"), id="workspace")
        yield Static("Ready — enter /scan to scan the current project", id="status")
        yield Static(
            "Evidence requires verification; "
            "zero findings does not establish PQC readiness.",
            id="coverage",
        )
        yield DataTable(id="results", cursor_type="row")
        with VerticalScroll(id="detail-panel", can_focus=True):
            yield Static(_literal(HELP), id="details")
        yield Static("", id="message")
        yield Input(placeholder="qrypt > /scan .", id="command")
        yield Static(
            "/scan · /export · /help · /quit    Tab: focus · Ctrl+C: quit",
            id="short-help",
            markup=False,
        )

    def on_mount(self) -> None:
        self.query_one("#results", DataTable).add_columns(
            "Classification", "Algorithm", "Operation", "File", "Line"
        )
        self.query_one("#command", Input).focus()
        self._resize_banner()

    def on_resize(self) -> None:
        if self.is_mounted:
            self._resize_banner()

    def _resize_banner(self) -> None:
        full = self.size.width >= 70 and self.size.height >= 36
        self.query_one("#banner", Static).update(BANNER if full else "QRYPT")

    def _update(self, widget: str, value: str) -> None:
        self.query_one(widget, Static).update(_literal(value))

    def on_key(self, event) -> None:
        prompt = self.query_one("#command", Input)
        if self.focused is not prompt or event.key not in ("up", "down"):
            return
        if self.history_index == len(self.history):
            self.draft = prompt.value
        direction = -1 if event.key == "up" else 1
        self.history_index = min(
            len(self.history), max(0, self.history_index + direction)
        )
        prompt.value = (
            self.history[self.history_index]
            if self.history_index < len(self.history)
            else self.draft
        )
        prompt.cursor_position = len(prompt.value)
        event.stop()
        event.prevent_default()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        command = event.value.strip()
        event.input.value = ""
        if command:
            if not self.history or self.history[-1] != command:
                self.history.append(command)
            self.history_index = len(self.history)
            self.draft = ""
            await self.submit_command(command)

    async def submit_command(self, command: str) -> None:
        try:
            parts = shlex.split(command)
            if not parts:
                return
            name, *args = parts
            if name == "/quit":
                if args:
                    raise ValueError("Usage: /quit")
                await self.action_quit()
            elif name == "/help":
                if args:
                    raise ValueError("Usage: /help")
                self._update("#details", HELP)
                self._update("#message", "Commands ready.")
            elif name == "/scan":
                if len(args) > 1:
                    raise ValueError("Usage: /scan [path]")
                if self.busy:
                    raise ValueError(
                        "Scan in progress; wait before scanning or exporting."
                    )
                target = self.directory / (args[0] if args else ".")
                self.busy = True
                previous = (
                    f"; previous results: {self.report_target}" if self.report else ""
                )
                self._update("#status", f"Scanning {target}{previous}")
                self._update("#message", "Scanning… /help and /quit remain available.")
                self.scan_task = asyncio.create_task(self._scan(target))
            elif name == "/export":
                if len(args) != 2:
                    raise ValueError("Usage: /export <text|json|sarif|cbom> <path>")
                format, path = args
                if format not in ("text", "json", "sarif", "cbom"):
                    raise ValueError(
                        "Unknown export format: use text, json, sarif or cbom."
                    )
                if self.busy:
                    raise ValueError(
                        "Scan in progress; wait before scanning or exporting."
                    )
                if self.report is None:
                    raise ValueError("Scan first before exporting a report.")
                destination = self.directory / path
                _validate_output(destination, format)
                _write_report(destination, render_report(self.report, format))
                self._update("#message", f"Saved {format} report to {destination}")
            else:
                raise ValueError("Unknown command. Enter /help for available commands.")
        except (ValueError, OSError) as error:
            self._update("#message", str(error))

    async def _scan(self, target: Path) -> None:
        try:
            report = await run_scan(target)
            if not self._quitting:
                self.report, self.report_target = report, target
                self._show_report()
                self._update(
                    "#message",
                    "Scan finished. Select a row for details; /export saves a report.",
                )
        except (OSError, ValueError) as error:
            if not self._quitting:
                self._show_status()
                self._update("#message", f"Scan failed for {target}: {error}")
        finally:
            self.busy = False

    def _show_status(self) -> None:
        if self.report is None:
            self._update("#status", "No scan report available.")
            return
        report = self.report
        self._update(
            "#status",
            f"Results: {self.report_target} — {report['status']}\n"
            f"{report['scanned_files']} scanned / {report['skipped_files']} skipped · "
            f"{len(report['findings'])} candidates requiring verification · "
            f"{len(report['inventory'])} inventory observations",
        )

    def _show_report(self) -> None:
        self._show_status()
        self._update("#coverage", self.report["coverage"])
        table = self.query_one("#results", DataTable)
        self._row_entries.clear()
        table.clear()
        for entry in self.report["inventory"]:
            key = table.add_row(
                _literal(
                    "Candidate" if entry["migration_candidate"] else "PQC inventory"
                ),
                _literal(entry["algorithm"]),
                _literal(entry["operation"]),
                _literal(entry["path"]),
                str(entry["line"]),
            )
            self._row_entries[key] = entry
        hint = (
            "Select a finding to inspect its evidence and guidance."
            if table.row_count
            else "No observations. This does not establish PQC readiness."
        )
        self._update("#details", self._diagnostics() or hint)

    def _diagnostics(self) -> str:
        return "\n".join(
            f"{error['type']}: {error.get('path', 'scan')}"
            + (f":{error['line']}" if "line" in error else "")
            + (f" — {error['reason']}" if "reason" in error else "")
            for error in self.report["errors"]
        )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        entry = self._row_entries.get(event.row_key)
        if entry is None:
            return
        classification = (
            "Migration candidate requiring verification"
            if entry["migration_candidate"]
            else "PQC inventory observation; readiness unverified"
        )
        details = (
            f"{classification}\n{entry['algorithm']} / {entry['operation']}\n"
            f"{entry['path']}:{entry['line']}:{entry['column']}\n"
            f"{entry['rule_id']} · {entry['confidence']} confidence\n\n"
            f"{entry['guidance']}"
        )
        diagnostics = self._diagnostics()
        self._update(
            "#details",
            details + ("\n\nDiagnostics:\n" + diagnostics if diagnostics else ""),
        )

    async def _cancel_scan(self) -> None:
        if self.scan_task is not None and not self.scan_task.done():
            self.scan_task.cancel()
            try:
                await self.scan_task
            except asyncio.CancelledError:
                pass

    async def action_quit(self) -> None:
        if self._quitting:
            return
        self._quitting = True
        self._update("#message", "Stopping the scan and restoring the terminal…")
        await self._cancel_scan()
        self.exit(0)

    async def on_unmount(self) -> None:
        await self._cancel_scan()


def launch() -> int:
    if os.name != "posix":
        print(
            "QRYPT interactive mode currently requires a POSIX terminal. "
            "Use qrypt scan <path>.",
            file=sys.stderr,
        )
        return 2
    return QryptApp().run() or 0
