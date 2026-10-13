"""SARIF 2.1.0 export of normalized migration candidates."""

from importlib.metadata import version
from pathlib import Path
from urllib.parse import quote

from ruamel.yaml import YAML


def sarif_report(report: dict) -> dict:
    rules = []
    for path in sorted((Path(__file__).parent / "rules").glob("*.yml")):
        for rule in YAML(typ="safe").load(path.read_text(encoding="utf-8"))["rules"]:
            rules.append(
                {
                    "id": rule["id"],
                    "shortDescription": {"text": rule["message"]},
                    "help": {"text": rule["metadata"]["guidance"]},
                    "defaultConfiguration": {"level": "warning"},
                    "properties": {"tags": ["pqc", "cryptographic-inventory"]},
                }
            )
    indices = {rule["id"]: index for index, rule in enumerate(rules)}
    results = []
    for finding in report["findings"]:
        results.append(
            {
                "ruleId": finding["rule_id"],
                "ruleIndex": indices[finding["rule_id"]],
                "level": "warning",
                "message": {
                    "text": (
                        f"{finding['algorithm']} / {finding['operation']}: "
                        "migration candidate requiring verification. "
                        f"{finding['guidance']}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": quote(finding["path"], safe="/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding["line"],
                                "startColumn": finding["column"],
                            },
                        }
                    }
                ],
                "properties": {
                    key: finding[key]
                    for key in ("algorithm", "operation", "confidence")
                },
            }
        )
    invocation = {"executionSuccessful": report["status"] == "completed"}
    if report["errors"]:
        invocation["toolExecutionNotifications"] = [
            {
                "level": "error",
                "message": {
                    "text": (
                        f"{error['type']}: {error.get('path', 'scan')}"
                        + (f" ({error['reason']})" if "reason" in error else "")
                    )
                },
            }
            for error in report["errors"]
        ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "QRYPT",
                        "version": version("qrypt"),
                        "rules": rules,
                    }
                },
                # A portable base avoids disclosing the host's absolute checkout path.
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
                "invocations": [invocation],
                "results": results,
                "properties": {
                    key: report[key]
                    for key in ("status", "scanned_files", "skipped_files", "coverage")
                },
            }
        ],
    }
