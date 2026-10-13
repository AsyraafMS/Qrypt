import subprocess

import pytest

from qrypt.cli import _write_report, main


def test_failed_atomic_replace_preserves_existing_report(tmp_path, monkeypatch):
    destination = tmp_path / "report.json"
    destination.write_text("previous complete report")

    def fail_replace(source, target):
        raise PermissionError("simulated replacement failure")

    monkeypatch.setattr("qrypt.cli.os.replace", fail_replace)
    with pytest.raises(PermissionError):
        _write_report(destination, "new report")
    assert destination.read_text() == "previous complete report"
    assert list(tmp_path.iterdir()) == [destination]


def test_engine_timeout_returns_error_without_traceback(tmp_path, monkeypatch, capsys):
    (tmp_path / "source.py").write_text("value = 1\n")

    def time_out(*arguments, **options):
        raise subprocess.TimeoutExpired("semgrep", 120)

    monkeypatch.setattr("qrypt.scanner.subprocess.run", time_out)
    assert main(["scan", str(tmp_path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "120-second" in output.err
    assert "Traceback" not in output.err
