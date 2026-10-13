import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from qrypt.cli import main
from qrypt.sarif import sarif_report

SCHEMA = json.loads((Path(__file__).parent / "schemas/sarif-2.1.0.json").read_text())
REPORT = {
    "status": "completed",
    "scanned_files": 1,
    "skipped_files": 0,
    "coverage": "Zero findings does not establish PQC readiness.",
    "errors": [],
    "findings": [
        {
            "rule_id": "qrypt.python.rsa-keygen",
            "path": "src/clé #1.py",
            "line": 7,
            "column": 3,
            "algorithm": "RSA",
            "operation": "key-generation",
            "confidence": "high",
            "guidance": "Review key purpose and lifetime.",
        }
    ],
}


@pytest.mark.parametrize("status", ["completed", "empty", "incomplete"])
def test_sarif_schema_and_completion(status):
    report = copy.deepcopy(REPORT)
    if status == "empty":
        report["findings"] = []
    if status == "incomplete":
        report["status"] = status
        report["errors"] = [
            {"type": "PythonSyntaxError", "path": "broken.py", "line": 4}
        ]
    result = sarif_report(report)
    Draft7Validator(SCHEMA).validate(result)
    run = result["runs"][0]
    assert result["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "QRYPT"
    assert len(run["tool"]["driver"]["rules"]) == 10
    assert run["invocations"][0]["executionSuccessful"] == (status != "incomplete")
    assert run["properties"]["coverage"] == report["coverage"]
    assert len(run["results"]) == len(report["findings"])
    if status == "incomplete":
        assert "PythonSyntaxError" in json.dumps(run["invocations"])
        assert run["results"]


def test_sarif_rule_links_and_escaped_source_location():
    run = sarif_report(REPORT)["runs"][0]
    result = run["results"][0]
    rule = run["tool"]["driver"]["rules"][result["ruleIndex"]]
    assert result["ruleId"] == rule["id"] == REPORT["findings"][0]["rule_id"]
    assert rule["help"]["text"]
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/cl%C3%A9%20%231.py"
    assert location["region"] == {"startLine": 7}
    assert run["columnKind"] == "unicodeCodePoints"
    base = run["originalUriBaseIds"]["%SRCROOT%"]
    assert "uri" not in base
    assert "scan target" in base["description"]["text"]
    assert result["level"] == "warning"
    assert "requiring verification" in result["message"]["text"]
    assert "security-severity" not in rule["properties"]


@pytest.mark.parametrize(
    "incomplete,enforce,code", [(False, False, 0), (False, True, 1), (True, True, 2)]
)
def test_sarif_cli_preserves_exit_codes_and_privacy(
    tmp_path, monkeypatch, capsys, incomplete, enforce, code
):
    report = copy.deepcopy(REPORT)
    if incomplete:
        report["status"] = "incomplete"
        report["errors"] = [{"type": "PythonSyntaxError", "path": "broken.py"}]
    monkeypatch.setattr("qrypt.cli.scan", lambda target: report)
    output = tmp_path / "report.sarif"
    args = ["scan", str(tmp_path), "--format", "sarif", "--output", str(output)]
    if enforce:
        args.append("--fail-on-findings")
    assert main(args) == code
    captured = capsys.readouterr()
    assert captured.out == ""
    content = output.read_text()
    Draft7Validator(SCHEMA).validate(json.loads(content))
    assert str(tmp_path) not in content
    assert "snippet" not in content


@pytest.mark.parametrize(
    "destination", ["source.py", "report.json", "linked.sarif", "missing/report.sarif"]
)
def test_sarif_rejects_unsafe_output_before_scanning(
    tmp_path, monkeypatch, capsys, destination
):
    source = tmp_path / "source.py"
    source.write_text("preserve = True\n")
    (tmp_path / "linked.sarif").symlink_to(source)

    def unexpected_scan(target):
        pytest.fail("unsafe output must be rejected before scanning")

    monkeypatch.setattr("qrypt.cli.scan", unexpected_scan)
    assert (
        main(
            [
                "scan",
                str(tmp_path),
                "--format",
                "sarif",
                "--output",
                str(tmp_path / destination),
            ]
        )
        == 2
    )
    assert source.read_text() == "preserve = True\n"
    assert capsys.readouterr().err


def test_real_unicode_source_uses_accurate_line_locations(tmp_path, capsys):
    source = tmp_path / "unicode.py"
    source.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "text = 'é😀'; key = rsa.generate_private_key("
        "public_exponent=65537, key_size=2048)\n",
        encoding="utf-8",
    )
    assert main(["scan", str(source), "--format", "sarif"]) == 0
    output = capsys.readouterr()
    run = json.loads(output.out)["runs"][0]
    assert len(run["results"]) == 1
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["region"] == {"startLine": 2}
    assert run["columnKind"] == "unicodeCodePoints"
    assert "uri" not in run["originalUriBaseIds"]["%SRCROOT%"]
    assert str(tmp_path) not in output.out


def test_private_source_base_does_not_invent_filesystem_location():
    base = sarif_report(REPORT)["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]
    assert "uri" not in base
    assert "scan target" in base["description"]["text"]
