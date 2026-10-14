import asyncio
import copy
import importlib
import json
import os
import signal
import sys
from pathlib import Path

import pytest

from qrypt import cli

REPORT = {
    "schema_version": 1,
    "status": "completed",
    "scanned_files": 1,
    "skipped_files": 0,
    "coverage": "Zero findings does not establish PQC readiness.",
    "findings": [],
    "inventory": [],
    "errors": [],
}


def test_shared_report_rendering_has_no_terminal_banner():
    render = getattr(cli, "render_report", None)
    assert callable(render), "CLI needs one shared report renderer"
    assert render(REPORT, "text").startswith("QRYPT scan: completed\n")
    assert json.loads(render(REPORT, "json")) == REPORT
    assert json.loads(render(REPORT, "sarif"))["runs"][0]["results"] == []
    assert json.loads(render(REPORT, "cbom"))["components"] == []


def test_real_child_scan_retains_pqc_and_incomplete_evidence(tmp_path):
    process = importlib.import_module("qrypt.tui_process")
    (tmp_path / "app.js").write_text(
        'const crypto = require("node:crypto");\n'
        'crypto.generateKeyPairSync("ml-kem-768", {});\n'
    )
    (tmp_path / "nginx.conf").write_text("ssl_ecdh_curve $groups;\n")
    report = asyncio.run(process.run_scan(tmp_path))
    assert report["status"] == "incomplete"
    assert report["findings"] == []
    assert report["inventory"][0]["algorithm"] == "ML-KEM-768"
    assert report["errors"]


def test_child_scan_failure_is_readable(tmp_path):
    process = importlib.import_module("qrypt.tui_process")
    with pytest.raises(ValueError, match="QRYPT error"):
        asyncio.run(process.run_scan(tmp_path / "missing"))


@pytest.mark.parametrize(
    "change,code",
    [
        ({"status": "completed"}, 2),
        ({"status": "incomplete"}, 0),
        ({"schema_version": 99}, 0),
        ({"scanned_files": -1}, 0),
        ({"skipped_files": True}, 0),
        ({"coverage": []}, 0),
        ({"inventory": [{"path": "x"}]}, 0),
        ({"findings": [{}]}, 0),
        ({"errors": [{"type": []}]}, 2),
        ({}, 1),
    ],
)
def test_invalid_child_report_is_rejected(change, code):
    process = importlib.import_module("qrypt.tui_process")
    report = {**copy.deepcopy(REPORT), **change}
    with pytest.raises(ValueError, match="Invalid scan report"):
        process._decode_report(json.dumps(report).encode(), code, b"")


@pytest.mark.parametrize("payload", [b"not json", b"[]", b"null"])
def test_malformed_child_output_is_rejected(payload):
    process = importlib.import_module("qrypt.tui_process")
    with pytest.raises(ValueError):
        process._decode_report(payload, 0, b"engine failed")


def _running(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except FileNotFoundError:
        return False


@pytest.mark.parametrize("wrapper_exits", [False, True])
def test_cleanup_stops_term_ignoring_descendant(tmp_path, wrapper_exits):
    process = importlib.import_module("qrypt.tui_process")
    ready = tmp_path / "child.pid"
    child = (
        "import os,signal,time,pathlib; "
        "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
        f"pathlib.Path({str(ready)!r}).write_text(str(os.getpid())); "
        "time.sleep(60)"
    )
    wrapper = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable,'-c',{child!r}], "
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        + ("sys.exit(0)" if wrapper_exits else "time.sleep(60)")
    )

    async def exercise():
        owned = await asyncio.create_subprocess_exec(
            sys.executable, "-c", wrapper, start_new_session=True
        )
        try:
            async with asyncio.timeout(5):
                while not ready.exists():
                    await asyncio.sleep(0.01)
            if wrapper_exits:
                await owned.wait()
            await asyncio.wait_for(process._stop_process(owned), 4)
            pid = int(ready.read_text())
            async with asyncio.timeout(2):
                while _running(pid):
                    await asyncio.sleep(0.01)
            assert owned.returncode is not None
        finally:
            try:
                os.killpg(owned.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await owned.wait()

    asyncio.run(exercise())


def test_cancellation_during_spawn_cleans_owned_process(monkeypatch, tmp_path):
    process = importlib.import_module("qrypt.tui_process")
    real_spawn = asyncio.create_subprocess_exec

    async def exercise():
        started = asyncio.Event()
        release = asyncio.Event()
        children = []

        async def delayed_spawn(*args, **kwargs):
            child = await real_spawn(
                sys.executable, "-c", "import time; time.sleep(60)", **kwargs
            )
            children.append(child)
            started.set()
            await release.wait()
            return child

        monkeypatch.setattr(process.asyncio, "create_subprocess_exec", delayed_spawn)
        task = asyncio.create_task(process.run_scan(tmp_path))
        await asyncio.wait_for(started.wait(), 3)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 4)
        assert children[0].returncode is not None

    asyncio.run(exercise())


def test_validation_also_runs_with_python_optimization():
    import subprocess

    invalid = {**REPORT, "scanned_files": -1}
    result = subprocess.run(
        [
            sys.executable,
            "-O",
            "-c",
            "import json; from qrypt.tui_process import _decode_report; "
            f"_decode_report({json.dumps(invalid).encode()!r}, 0, b'')",
        ],
        capture_output=True,
    )
    assert result.returncode != 0
    assert b"Invalid scan report" in result.stderr


def test_project_cannot_shadow_scanner_module(tmp_path, monkeypatch):
    process = importlib.import_module("qrypt.tui_process")
    marker = tmp_path / "executed"
    (tmp_path / "qrypt.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('project code executed')\n"
    )
    (tmp_path / "app.js").write_text(
        'const crypto = require("node:crypto"); '
        'crypto.generateKeyPairSync("ml-kem-768", {});\n'
    )
    monkeypatch.chdir(tmp_path)
    try:
        report = asyncio.run(process.run_scan(tmp_path))
    finally:
        assert not marker.exists(), "Scanning must not execute project-local qrypt.py"
    assert report["status"] == "completed"
    assert report["inventory"][0]["algorithm"] == "ML-KEM-768"
