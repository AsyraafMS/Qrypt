"""Command-line reports for supported cryptographic API usage."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from qrypt.banner import BANNER
from qrypt.sarif import sarif_report
from qrypt.scanner import scan


def _text_report(report: dict) -> str:
    lines = [
        f"QRYPT scan: {report['status']}",
        f"Scanned {report['scanned_files']} supported files; "
        f"skipped {report['skipped_files']} files.",
        f"{len(report['findings'])} migration candidates requiring verification.",
    ]
    for finding in report["findings"]:
        lines.extend(
            [
                f"\n{finding['path']}:{finding['line']}:{finding['column']} "
                f"{finding['algorithm']} / {finding['operation']} "
                f"[{finding['rule_id']}, {finding['confidence']} confidence]",
                finding["guidance"],
            ]
        )
    lines.extend(["", report["coverage"]])
    return "\n".join(lines) + "\n"


def _validate_output(path: Path, output_format: str) -> None:
    suffix = {"json": ".json", "text": ".txt", "sarif": ".sarif"}[output_format]
    if path.suffix != suffix or path.is_symlink() or path.is_dir():
        raise ValueError(
            f"Output must be a regular {suffix} report path, not a symlink."
        )
    if not path.parent.is_dir():
        raise ValueError("Output directory does not exist.")


def _write_report(path: Path, content: str) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".qrypt-",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(content)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Review PQC migration candidates locally."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser(
        "scan", help="Scan supported Python/Node.js and local TLS config files."
    )
    scan_parser.add_argument("path", type=Path)
    scan_parser.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text"
    )
    scan_parser.add_argument(
        "--output", type=Path, help="Write a .txt, .json, or .sarif report."
    )
    scan_parser.add_argument("--fail-on-findings", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        if arguments.output:
            _validate_output(arguments.output, arguments.format)
        report = scan(arguments.path)
        if arguments.format == "sarif":
            content = json.dumps(sarif_report(report), indent=2) + "\n"
        elif arguments.format == "json":
            content = json.dumps(report, indent=2) + "\n"
        else:
            content = _text_report(report)
        if (
            arguments.format == "text"
            and not arguments.output
            and report["status"] == "completed"
            and sys.stdout.isatty()
        ):
            content = BANNER + "\n\n" + content
        if arguments.output:
            _write_report(arguments.output, content)
        else:
            sys.stdout.write(content)
        if report["errors"]:
            print("QRYPT scan incomplete:", file=sys.stderr)
            for error in report["errors"]:
                print(
                    f"  {error.get('reason', error['type'])}: "
                    f"{error.get('path', 'scan')}",
                    file=sys.stderr,
                )
            return 2
        return int(arguments.fail_on_findings and bool(report["findings"]))
    except (OSError, ValueError) as error:
        print(f"QRYPT error: {error}", file=sys.stderr)
        return 2
    except subprocess.TimeoutExpired:
        print(
            "QRYPT error: Semgrep exceeded the 120-second scan limit.", file=sys.stderr
        )
        return 2
