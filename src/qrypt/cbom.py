"""CycloneDX 1.6 cryptographic assets from bounded static observations."""

import hashlib
import json
import re
from importlib.metadata import version


def _reference(kind: str, values: list) -> str:
    digest = hashlib.sha256(json.dumps(values, ensure_ascii=False).encode()).hexdigest()
    return f"qrypt:{kind}:{digest}"


def _algorithm_properties(algorithm: str, operation: str) -> dict:
    match = re.fullmatch(r"ML-(KEM-(512|768|1024)|DSA-(44|65|87))", algorithm)
    if match:
        return {
            "primitive": "kem" if match[2] else "signature",
            "parameterSetIdentifier": match[2] or match[3],
        }
    if algorithm in ("DH", "ECDH"):
        primitive = "key-agree"
    elif algorithm in ("DSA", "ECDSA", "EdDSA") or (
        algorithm == "RSA"
        and ("signature" in operation or "authentication" in operation)
    ):
        primitive = "signature"
    elif algorithm == "RSA" and "key-agreement" in operation:
        primitive = "pke"
    else:
        primitive = "unknown"
    return {"primitive": primitive}


def cbom_report(report: dict) -> dict:
    groups = {}
    for entry in report.get("inventory", report["findings"]):
        groups.setdefault((entry["algorithm"], entry["operation"]), []).append(entry)
    components = []
    for (algorithm, operation), entries in sorted(groups.items()):
        occurrences = {}
        for entry in entries:
            reference = _reference(
                "occurrence",
                [
                    algorithm,
                    operation,
                    entry["path"],
                    entry["line"],
                    entry["column"],
                    entry["rule_id"],
                ],
            )
            occurrences[reference] = {
                "bom-ref": reference,
                "location": entry["path"],
                "line": entry["line"],
            }
        components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": _reference("algorithm", [algorithm, operation]),
                "name": algorithm,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": _algorithm_properties(algorithm, operation),
                },
                "evidence": {
                    "occurrences": [occurrences[key] for key in sorted(occurrences)]
                },
                "properties": [
                    {"name": "qrypt:operation", "value": operation},
                    {
                        "name": "qrypt:migration-candidate",
                        "value": str(
                            any(
                                entry.get("migration_candidate", True)
                                for entry in entries
                            )
                        ).lower(),
                    },
                    {
                        "name": "qrypt:rule-ids",
                        "value": json.dumps(
                            sorted({entry["rule_id"] for entry in entries})
                        ),
                    },
                    {
                        "name": "qrypt:confidence",
                        "value": ",".join(
                            sorted({entry["confidence"] for entry in entries})
                        ),
                    },
                ],
            }
        )
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "QRYPT",
                        "version": version("qrypt"),
                    }
                ]
            },
            "properties": [
                {"name": "qrypt:scan-status", "value": report["status"]},
                {"name": "qrypt:coverage", "value": report["coverage"]},
                {"name": "qrypt:scanned-files", "value": str(report["scanned_files"])},
                {"name": "qrypt:skipped-files", "value": str(report["skipped_files"])},
                {
                    "name": "qrypt:scan-errors",
                    "value": json.dumps(report["errors"], sort_keys=True),
                },
            ],
        },
        "components": components,
        "compositions": [
            {
                "aggregate": "unknown"
                if report["status"] == "completed"
                else "incomplete",
            }
        ],
    }
