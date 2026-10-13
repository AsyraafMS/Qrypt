import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from qrypt.cbom import cbom_report
from qrypt.cli import main

SCHEMAS = Path(__file__).parent / "schemas" / "cyclonedx-1.6"
SCHEMA = json.loads((SCHEMAS / "bom-1.6.schema.json").read_text())
REGISTRY = Registry().with_resources(
    [
        (schema["$id"], Resource.from_contents(schema))
        for schema in (json.loads(path.read_text()) for path in SCHEMAS.glob("*.json"))
    ]
)
VALIDATOR = Draft7Validator(SCHEMA, registry=REGISTRY)
ENTRY = {
    "rule_id": "qrypt.javascript.ml-kem-768-keygen",
    "path": "src/clé #1.js",
    "line": 3,
    "column": 2,
    "algorithm": "ML-KEM-768",
    "operation": "key-generation",
    "confidence": "high",
    "guidance": "Review implementation support.",
    "migration_candidate": False,
}
REPORT = {
    "status": "completed",
    "scanned_files": 1,
    "skipped_files": 0,
    "coverage": "Bounded static evidence; zero findings does not establish readiness.",
    "errors": [],
    "findings": [],
    "inventory": [ENTRY],
}


@pytest.mark.parametrize("status", ["completed", "empty", "incomplete"])
def test_cbom_is_schema_valid_with_honest_completion(status):
    report = copy.deepcopy(REPORT)
    if status == "empty":
        report["inventory"] = []
    if status == "incomplete":
        report["status"] = "incomplete"
        report["errors"] = [
            {"type": "TLSUnresolvedSetting", "path": "nginx.conf", "line": 4}
        ]
    result = cbom_report(report)
    VALIDATOR.validate(result)
    assert result["bomFormat"] == "CycloneDX"
    assert result["specVersion"] == "1.6"
    assert result["compositions"][0]["aggregate"] == (
        "incomplete" if status == "incomplete" else "unknown"
    )
    properties = {p["name"]: p["value"] for p in result["metadata"]["properties"]}
    assert properties["qrypt:scan-status"] == report["status"]
    assert json.loads(properties["qrypt:scan-errors"]) == report["errors"]
    assert properties["qrypt:coverage"] == report["coverage"]
    assert "dependencies" not in result
    assert "vulnerabilities" not in result
    assert len(result["components"]) == len(report["inventory"])


def test_cbom_retains_distinct_occurrences_and_stable_identity():
    report = copy.deepcopy(REPORT)
    report["inventory"] += [
        {**ENTRY, "column": 15},
        {**ENTRY, "path": "other.js", "line": 8},
    ]
    result = cbom_report(report)
    VALIDATOR.validate(result)
    assert len(result["components"]) == 1
    component = result["components"][0]
    assert component["type"] == "cryptographic-asset"
    assert component["cryptoProperties"]["assetType"] == "algorithm"
    algorithm = component["cryptoProperties"]["algorithmProperties"]
    assert algorithm == {"primitive": "kem", "parameterSetIdentifier": "768"}
    occurrences = component["evidence"]["occurrences"]
    assert len(occurrences) == 3
    assert len({o["bom-ref"] for o in occurrences}) == 3
    assert {o["location"] for o in occurrences} == {"src/clé #1.js", "other.js"}
    assert {o["line"] for o in occurrences} == {3, 8}
    report["inventory"].reverse()
    assert cbom_report(report) == result
    assert all("offset" not in o and "additionalContext" not in o for o in occurrences)


@pytest.mark.parametrize(
    "algorithm,operation,primitive",
    [
        ("EC", "key-generation", "unknown"),
        ("RSA", "key-generation", "unknown"),
        ("RSA", "configured-authentication", "signature"),
        ("DH", "parameter-generation", "key-agree"),
        ("ML-DSA-65", "key-generation", "signature"),
    ],
)
def test_cbom_primitive_is_only_inferred_from_supported_evidence(
    algorithm, operation, primitive
):
    report = {
        **REPORT,
        "inventory": [{**ENTRY, "algorithm": algorithm, "operation": operation}],
    }
    component = cbom_report(report)["components"][0]
    props = component["cryptoProperties"]["algorithmProperties"]
    assert props["primitive"] == primitive
    assert "curve" not in props
    assert "classicalSecurityLevel" not in props
    assert "nistQuantumSecurityLevel" not in props


@pytest.mark.parametrize(
    "candidate,incomplete,code", [(False, False, 0), (True, False, 1), (True, True, 2)]
)
def test_cbom_cli_classification_exit_codes_and_private_output(
    tmp_path, monkeypatch, capsys, candidate, incomplete, code
):
    report = copy.deepcopy(REPORT)
    entry = {**ENTRY, "migration_candidate": candidate}
    report["inventory"] = [entry]
    report["findings"] = [entry] if candidate else []
    if incomplete:
        report["status"] = "incomplete"
        report["errors"] = [{"type": "TLSUnresolvedSetting", "path": "nginx.conf"}]
    monkeypatch.setattr("qrypt.cli.scan", lambda path: report)
    output = tmp_path / "inventory.cdx.json"
    assert (
        main(
            [
                "scan",
                str(tmp_path),
                "--format",
                "cbom",
                "--output",
                str(output),
                "--fail-on-findings",
            ]
        )
        == code
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    content = output.read_text()
    result = json.loads(content)
    VALIDATOR.validate(result)
    assert str(tmp_path) not in content
    assert "snippet" not in content
    properties = {p["name"]: p["value"] for p in result["components"][0]["properties"]}
    assert properties["qrypt:migration-candidate"] == str(candidate).lower()


@pytest.mark.parametrize(
    "destination", ["app.js", "report.sarif", "link.json", "missing/report.json"]
)
def test_cbom_output_validation_preserves_source(
    tmp_path, monkeypatch, capsys, destination
):
    source = tmp_path / "app.js"
    source.write_text("preserve this file")
    (tmp_path / "link.json").symlink_to(source)
    monkeypatch.setattr(
        "qrypt.cli.scan", lambda path: pytest.fail("must validate output before scan")
    )
    assert (
        main(
            [
                "scan",
                str(tmp_path),
                "--format",
                "cbom",
                "--output",
                str(tmp_path / destination),
            ]
        )
        == 2
    )
    assert source.read_text() == "preserve this file"
    assert capsys.readouterr().err
