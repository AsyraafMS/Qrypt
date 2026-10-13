import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SEMGREP = Path(sys.executable).with_name("semgrep")


@pytest.mark.parametrize("name,extension", [("python", "py"), ("javascript", "js")])
def test_rule_fixtures_match_only_annotated_crypto_calls(name, extension):
    fixture = ROOT / "tests" / "fixtures" / f"{name}.{extension}"
    expected = set()
    for number, line in enumerate(fixture.read_text().splitlines(), start=1):
        if "ruleid:" in line:
            expected.add((number + 1, line.split("ruleid:", 1)[1].strip()))
    result = subprocess.run(
        [
            str(SEMGREP),
            "scan",
            "--config",
            str(ROOT / "src" / "qrypt" / "rules" / f"{name}.yml"),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            str(fixture),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["errors"] == []
    actual = {(item["start"]["line"], item["check_id"]) for item in payload["results"]}
    assert actual == expected
