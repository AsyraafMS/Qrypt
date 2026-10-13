import io
import json

import pytest

from qrypt.banner import BANNER
from qrypt.cli import main

REPORT = {
    "status": "completed",
    "scanned_files": 1,
    "skipped_files": 0,
    "coverage": "Zero findings does not establish PQC readiness.",
    "findings": [],
    "errors": [],
}


@pytest.mark.parametrize(
    "tty,format,banner",
    [
        (True, "text", True),
        (False, "text", False),
        (True, "json", False),
        (True, "sarif", False),
    ],
)
def test_banner_is_only_for_interactive_text(
    tmp_path, monkeypatch, tty, format, banner
):
    output = io.StringIO()
    monkeypatch.setattr(output, "isatty", lambda: tty)
    monkeypatch.setattr("qrypt.cli.sys.stdout", output)
    monkeypatch.setattr("qrypt.cli.scan", lambda path: REPORT)
    assert main(["scan", str(tmp_path), "--format", format]) == 0
    content = output.getvalue()
    assert (BANNER in content) == banner
    if format != "text":
        json.loads(content)


def test_interactive_report_file_has_no_banner(tmp_path, monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(output, "isatty", lambda: True)
    monkeypatch.setattr("qrypt.cli.sys.stdout", output)
    monkeypatch.setattr("qrypt.cli.scan", lambda path: REPORT)
    destination = tmp_path / "report.txt"
    assert main(["scan", str(tmp_path), "--output", str(destination)]) == 0
    assert output.getvalue() == ""
    assert BANNER not in destination.read_text()


def test_incomplete_interactive_scan_has_no_banner(tmp_path, monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(output, "isatty", lambda: True)
    monkeypatch.setattr("qrypt.cli.sys.stdout", output)
    monkeypatch.setattr(
        "qrypt.cli.scan",
        lambda path: {
            **REPORT,
            "status": "incomplete",
            "errors": [{"type": "TLSUnresolvedSetting"}],
        },
    )
    assert main(["scan", str(tmp_path)]) == 2
    assert BANNER not in output.getvalue()
