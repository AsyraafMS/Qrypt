"""Own a cancellable CLI subprocess without changing scan semantics."""

import asyncio
import json
import os
import signal
import sys
from pathlib import Path


def _decode_report(output: bytes, code: int, stderr: bytes) -> dict:
    try:
        report = json.loads(output)
    except (ValueError, UnicodeError) as error:
        raise ValueError(
            stderr.decode("utf-8", errors="replace").strip()
            or "Scanner returned no valid JSON report."
        ) from error
    try:
        if not (isinstance(report, dict) and report["schema_version"] == 1):
            raise ValueError("Invalid scan report from child process.")
        if report["status"] not in ("completed", "incomplete"):
            raise ValueError("Invalid scan report from child process.")
        if not (isinstance(report["coverage"], str)):
            raise ValueError("Invalid scan report from child process.")
        for name in ("scanned_files", "skipped_files"):
            if not (type(report[name]) is int and report[name] >= 0):
                raise ValueError("Invalid scan report from child process.")
        for name in ("findings", "inventory", "errors"):
            if not (isinstance(report[name], list)):
                raise ValueError("Invalid scan report from child process.")
        if not (code == (2 if report["errors"] else 0)):
            raise ValueError("Invalid scan report from child process.")
        if not ((report["status"] == "incomplete") == bool(report["errors"])):
            raise ValueError("Invalid scan report from child process.")
        for entry in report["findings"] + report["inventory"]:
            if not (isinstance(entry, dict)):
                raise ValueError("Invalid scan report from child process.")
            for name in (
                "path",
                "rule_id",
                "algorithm",
                "operation",
                "confidence",
                "guidance",
            ):
                if not (isinstance(entry[name], str)):
                    raise ValueError("Invalid scan report from child process.")
            for name in ("line", "column"):
                if not (type(entry[name]) is int and entry[name] > 0):
                    raise ValueError("Invalid scan report from child process.")
        for entry in report["inventory"]:
            if type(entry["migration_candidate"]) is not bool:
                raise ValueError("Invalid scan report from child process.")
        for error in report["errors"]:
            if not (isinstance(error, dict) and isinstance(error["type"], str)):
                raise ValueError("Invalid scan report from child process.")
            for name in ("path", "reason"):
                if not (name not in error or isinstance(error[name], str)):
                    raise ValueError("Invalid scan report from child process.")
            if not (
                "line" not in error
                or (type(error["line"]) is int and error["line"] > 0)
            ):
                raise ValueError("Invalid scan report from child process.")
    except (KeyError, TypeError) as error:
        raise ValueError("Invalid scan report from child process.") from error
    return report


async def _stop_process(process: asyncio.subprocess.Process) -> None:
    # The wrapper may have exited while a descendant still owns this group.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        await process.wait()
        return
    for _ in range(10):
        await asyncio.sleep(0.05)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    await process.wait()


async def run_scan(target: Path) -> dict:
    spawning = asyncio.create_task(
        asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-m",
            "qrypt",
            "scan",
            str(target),
            "--format",
            "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    )
    process = None
    try:
        process = await asyncio.shield(spawning)
        # Allow engine timeout plus CLI normalization, but bound hung wrappers too.
        output, stderr = await asyncio.wait_for(process.communicate(), 130)
        return _decode_report(output, process.returncode, stderr)
    except TimeoutError as error:
        raise ValueError("Scan exceeded the 130-second interactive limit.") from error
    finally:
        if process is None:
            process = await spawning
        cleanup = asyncio.create_task(_stop_process(process))
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            await cleanup
            raise
