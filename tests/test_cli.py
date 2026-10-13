import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (
    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
    "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    "secret = 'DO_NOT_INCLUDE_THIS_SOURCE_IN_REPORTS'\n"
    "open('executed.txt', 'w').write(secret)\n"
)


def run_cli(*arguments, env=None):
    environment = dict(
        os.environ, PATH=f"{Path(sys.executable).parent}:{os.environ['PATH']}"
    )
    if env:
        environment.update(env)
    return subprocess.run(
        [sys.executable, "-m", "qrypt", *map(str, arguments)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.fixture
def project(tmp_path):
    (tmp_path / "app.py").write_text(SOURCE)
    return tmp_path


def test_json_reports_relative_evidence_without_source_or_execution(project):
    result = run_cli("scan", project, "--format", "json")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["schema_version"] == 1
    assert report["status"] == "completed"
    assert report["scanned_files"] == 1
    assert report["errors"] == []
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["rule_id"] == "qrypt.python.rsa-keygen"
    assert finding["path"] == "app.py"
    assert finding["line"] == 2
    assert finding["algorithm"] == "RSA"
    assert finding["operation"] == "key-generation"
    assert finding["confidence"] == "high"
    assert finding["guidance"]
    assert str(project) not in result.stdout
    assert "DO_NOT_INCLUDE_THIS_SOURCE_IN_REPORTS" not in result.stdout + result.stderr
    assert not (project / "executed.txt").exists()
    assert not (ROOT / "executed.txt").exists()


@pytest.mark.parametrize("flag,code", [([], 0), (["--fail-on-findings"], 1)])
def test_findings_are_advisory_unless_enforced(project, flag, code):
    result = run_cli("scan", project, *flag)
    assert result.returncode == code, result.stderr
    assert "app.py:2:" in result.stdout
    assert "migration candidate" in result.stdout.lower()


def test_clean_scan_does_not_claim_readiness(tmp_path):
    (tmp_path / "clean.py").write_text(
        "text = 'RSA ECDH'\n# rsa.generate_private_key()\n"
    )
    result = run_cli("scan", tmp_path, "--fail-on-findings")
    assert result.returncode == 0, result.stderr
    assert "0 migration candidates" in result.stdout
    assert "does not establish PQC readiness" in result.stdout


def test_json_output_file_has_no_stdout(project):
    output = project / "report.json"
    result = run_cli("scan", project, "--format", "json", "--output", output)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert json.loads(output.read_text())["findings"][0]["path"] == "app.py"


def test_single_file_scan_uses_relative_path(project):
    result = run_cli("scan", project / "app.py", "--format", "json")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["findings"][0]["path"] == "app.py"


def test_incomplete_scan_takes_precedence_over_enforcement(project):
    (project / "broken.py").write_text(
        "secret = 'PRIVATE_PARSE_CONTENT'\ndef broken(:\n"
    )
    result = run_cli("scan", project, "--format", "json", "--fail-on-findings")
    assert result.returncode == 2, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "incomplete"
    assert report["errors"]
    assert report["findings"]
    assert "incomplete" in result.stderr.lower()
    assert "PRIVATE_PARSE_CONTENT" not in result.stdout + result.stderr


def test_dependency_directories_are_excluded(project):
    for directory in ["node_modules", ".venv", "vendor"]:
        (project / directory).mkdir()
        (project / directory / "dependency.py").write_text(SOURCE)
    result = run_cli("scan", project, "--format", "json")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["scanned_files"] == 1
    assert report["skipped_files"] >= 3
    assert [item["path"] for item in report["findings"]] == ["app.py"]


@pytest.mark.parametrize("suffix", ["js", "mjs", "cjs"])
def test_supported_javascript_extensions(tmp_path, suffix):
    source = tmp_path / f"app.{suffix}"
    source.write_text(
        'const crypto = require("crypto");\ncrypto.createECDH("prime256v1");\n'
    )
    result = run_cli("scan", source, "--format", "json")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["findings"][0]["algorithm"] == "ECDH"


@pytest.mark.parametrize("case", ["missing", "unsupported", "empty"])
def test_invalid_or_unscannable_inputs_are_errors(tmp_path, case):
    target = tmp_path / "missing"
    if case == "unsupported":
        target = tmp_path / "README.md"
        target.write_text("RSA")
    elif case == "empty":
        target = tmp_path
    result = run_cli("scan", target)
    assert result.returncode == 2
    assert result.stderr


@pytest.mark.parametrize(
    "destination", ["app.py", "README.md", "linked.json", "missing/report.json"]
)
def test_unsafe_output_destinations_preserve_source(project, destination):
    readme = project / "README.md"
    readme.write_text("preserve this document")
    (project / "linked.json").symlink_to(project / "app.py")
    result = run_cli(
        "scan", project, "--format", "json", "--output", project / destination
    )
    assert result.returncode == 2
    assert (project / "app.py").read_text() == SOURCE
    assert readme.read_text() == "preserve this document"


def test_missing_engine_returns_actionable_error(project):
    result = run_cli("scan", project, env={"PATH": str(project)})
    assert result.returncode == 2
    assert "semgrep" in result.stderr.lower()


def test_invalid_engine_response_does_not_look_like_clean_scan(project):
    engine = project / "semgrep"
    engine.write_text(f"#!{sys.executable}\nprint('{{}}')\n")
    engine.chmod(0o755)
    result = run_cli("scan", project, env={"PATH": str(project)})
    assert result.returncode == 2
    assert result.stderr


def test_only_phase_one_output_formats_are_accepted(project):
    result = run_cli("scan", project, "--format", "sarif")
    assert result.returncode == 2
    assert "invalid choice" in result.stderr


def test_analysis_limit_skip_makes_report_incomplete(tmp_path):
    (tmp_path / "small.py").write_text("value = 1\n")
    (tmp_path / "large.py").write_text("# padding\n" * 150000 + SOURCE)
    result = run_cli("scan", tmp_path, "--format", "json")
    assert result.returncode == 2, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "incomplete"
    assert report["scanned_files"] == 1
    assert any(
        error.get("path") == "large.py" and error.get("reason") == "exceeded_size_limit"
        for error in report["errors"]
    )
    assert str(tmp_path) not in result.stdout
