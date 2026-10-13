"""Run bundled rules and retain only migration evidence, never source text."""

import ast
import json
import os
import shutil
import subprocess
import sys
import tokenize
from pathlib import Path

from qrypt.tls import scan_config

EXTENSIONS = (".py", ".js", ".mjs", ".cjs", ".conf", ".cnf")
EXCLUDED_DIRECTORIES = (
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "build",
    "dist",
)
IGNORE_REASONS = {
    "always_skipped",
    "semgrepignore_patterns_match",
    "cli_include_flags_do_not_match",
    "cli_exclude_flags_match",
    "excluded_by_config",
    "wrong_language",
    "irrelevant_rule",
    "Gitignore_patterns_match",
    "Dotfile",
}


def _relative_path(value: str, root: Path) -> str:
    return (root / value).resolve().relative_to(root).as_posix()


def scan(target: Path) -> dict:
    target = target.resolve(strict=True)
    if not target.is_dir() and not (target.is_file() and target.suffix in EXTENSIONS):
        raise ValueError(
            "Target must be a directory or a .py, .js, .mjs, .cjs, .conf, or .cnf file."
        )
    root = target if target.is_dir() else target.parent
    installed_engine = Path(sys.executable).with_name(
        "semgrep.exe" if os.name == "nt" else "semgrep"
    )
    engine = (
        str(installed_engine) if installed_engine.is_file() else shutil.which("semgrep")
    )
    if not engine:
        raise FileNotFoundError(
            "Semgrep is not installed or not on PATH; reinstall QRYPT."
        )
    command = [
        engine,
        "scan",
        "--config",
        str(Path(__file__).with_name("rules")),
        "--json",
        "--verbose",
        "--strict",
        "--oss-only",
        "--metrics=off",
        "--disable-version-check",
        "--no-rewrite-rule-ids",
    ]
    for extension in EXTENSIONS:
        command.extend(["--include", f"*{extension}"])
    for directory in EXCLUDED_DIRECTORIES:
        command.extend(["--exclude", directory])
    command.append(str(target))
    # shortcut: total scans time out after 120 seconds; expose a limit for large repos.
    result = subprocess.run(
        command,
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    try:
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict) or not all(
            isinstance(payload.get(field), list) for field in ("results", "errors")
        ):
            raise ValueError
        paths = payload["paths"]
        if not isinstance(paths["scanned"], list):
            raise ValueError
        findings, inventory_only = [], []
        for item in payload["results"]:
            metadata = item["extra"]["metadata"]
            if metadata.get("internal"):
                continue
            entry = {
                "rule_id": item["check_id"],
                "path": _relative_path(item["path"], root),
                "line": item["start"]["line"],
                "column": item["start"]["col"],
                "algorithm": metadata["algorithm"],
                "operation": metadata["operation"],
                "confidence": metadata["confidence"],
                "guidance": metadata["guidance"],
            }
            if metadata.get("inventory_only"):
                inventory_only.append({**entry, "migration_candidate": False})
            else:
                findings.append(entry)
        errors = []
        for item in payload["errors"]:
            error = {"type": item["type"]}
            span = next(iter(item.get("spans", [])), {})
            path = item.get("path") or span.get("file")
            if isinstance(path, dict):
                path = path.get("value")
            if path:
                error["path"] = _relative_path(path, root)
            if span.get("start"):
                error["line"] = span["start"]["line"]
            errors.append(error)
        if result.returncode != 0 and not errors:
            errors.append({"type": "EngineError", "exit_code": result.returncode})
        if payload.get("skipped_rules"):
            errors.append({"type": "SkippedRules"})
        for item in paths.get("skipped", []):
            if (
                Path(item["path"]).suffix in EXTENSIONS
                and item.get("reason") not in IGNORE_REASONS
            ):
                errors.append(
                    {
                        "type": "SkippedSource",
                        "path": _relative_path(item["path"], root),
                        "reason": item.get("reason", "unknown"),
                    }
                )
        for path in paths["scanned"]:
            relative = _relative_path(path, root)
            if Path(relative).suffix in (".conf", ".cnf"):
                tls_findings, tls_errors = scan_config(root / relative, relative)
                findings.extend(tls_findings)
                errors.extend(tls_errors)
            if Path(relative).suffix == ".py":
                try:
                    with tokenize.open(root / relative) as source:
                        ast.parse(source.read())
                except SyntaxError as error:
                    errors.append(
                        {
                            "type": "PythonSyntaxError",
                            "path": relative,
                            "line": error.lineno,
                        }
                    )
                except UnicodeError:
                    errors.append({"type": "PythonEncodingError", "path": relative})
        if not paths["scanned"]:
            errors.append({"type": "NoSupportedFiles"})
        return {
            "schema_version": 1,
            "status": "incomplete" if errors else "completed",
            "scanned_files": len(paths["scanned"]),
            "skipped_files": len(paths.get("skipped", [])),
            "coverage": "Explicit supported Python/Node.js APIs "
            "and literal TLS settings only; "
            "TLS evidence does not establish effective or negotiated configuration; "
            "zero findings does not establish PQC readiness. "
            "Observed PQC identifiers also do not establish system readiness.",
            "findings": sorted(
                findings,
                key=lambda item: (
                    item["path"],
                    item["line"],
                    item["column"],
                    item["rule_id"],
                ),
            ),
            "inventory": sorted(
                [{**entry, "migration_candidate": True} for entry in findings]
                + inventory_only,
                key=lambda entry: (
                    entry["path"],
                    entry["line"],
                    entry["column"],
                    entry["rule_id"],
                ),
            ),
            "errors": errors,
        }
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise ValueError("Semgrep returned an invalid scan response.") from error
