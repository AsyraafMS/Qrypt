import json

import pytest

from qrypt.cli import main
from qrypt.scanner import scan

TYPES = [
    "ml-kem-512",
    "ml-kem-768",
    "ml-kem-1024",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
]


@pytest.mark.parametrize(
    "binding",
    [
        'import crypto from "node:crypto";',
        'import * as crypto from "crypto";',
        'const crypto = require("node:crypto");',
    ],
)
def test_namespace_parameters_do_not_create_inventory(tmp_path, binding):
    calls = (
        'crypto.generateKeyPairSync("ml-kem-768", {});'
        'crypto.generateKeyPair("rsa", {}, callback);'
        'crypto.createECDH("prime256v1");'
        "crypto.createDiffieHellman(2048);"
    )
    (tmp_path / "app.js").write_text(
        binding
        + "\n"
        + f"function named(crypto) {{ {calls} }}\n"
        + f"const anonymous = function (crypto) {{ {calls} }};\n"
        + f"const arrow = (crypto) => {{ {calls} }};\n"
        + 'crypto.generateKeyPairSync("ml-kem-768", {});\n'
    )
    report = scan(tmp_path)
    assert report["status"] == "completed"
    assert report["findings"] == []
    assert [(e["algorithm"], e["line"]) for e in report["inventory"]] == [
        ("ML-KEM-768", 5)
    ]


@pytest.mark.parametrize("algorithm", TYPES)
def test_pqc_keygen_is_inventory_without_migration_warnings(tmp_path, algorithm):
    (tmp_path / "app.js").write_text(
        'const crypto = require("node:crypto"); '
        f'crypto.generateKeyPairSync("{algorithm}", {{}});\n'
        'const secret = "PRIVATE_SOURCE";\n'
    )
    report = scan(tmp_path)
    assert report["status"] == "completed"
    assert report["findings"] == []
    assert len(report["inventory"]) == 1
    entry = report["inventory"][0]
    assert entry["algorithm"] == algorithm.upper()
    assert entry["migration_candidate"] is False
    assert entry["operation"] == "key-generation"
    assert entry["path"] == "app.js"
    assert entry["line"] == 1
    assert "PRIVATE_SOURCE" not in json.dumps(report)
    assert str(tmp_path) not in json.dumps(report)


def test_classical_and_pqc_inventory_are_distinct(tmp_path):
    (tmp_path / "app.js").write_text(
        'import { generateKeyPairSync as generate } from "crypto";\n'
        'generate("rsa", {});\n'
        'generate("ml-kem-768", {});\n'
    )
    (tmp_path / "nginx.conf").write_text("ssl_ecdh_curve X25519;\n")
    report = scan(tmp_path)
    assert len(report["inventory"]) == 3
    assert len(report["findings"]) == 2
    assert {
        e["algorithm"] for e in report["inventory"] if not e["migration_candidate"]
    } == {"ML-KEM-768"}
    assert [e["path"] for e in report["inventory"]] == [
        "app.js",
        "app.js",
        "nginx.conf",
    ]


@pytest.mark.parametrize("format", ["text", "json", "sarif"])
def test_pqc_only_enforcement_and_reports(tmp_path, capsys, format):
    (tmp_path / "app.js").write_text(
        'import crypto from "node:crypto";\n'
        'crypto.generateKeyPairSync("ml-dsa-65", {});\n'
    )
    assert main(["scan", str(tmp_path), "--format", format, "--fail-on-findings"]) == 0
    captured = capsys.readouterr()
    if format == "text":
        assert "ML-DSA-65" in captured.out
        assert "0 migration candidates" in captured.out
        assert "1 cryptographic inventory observations" in captured.out
    elif format == "json":
        assert len(json.loads(captured.out)["inventory"]) == 1
    else:
        run = json.loads(captured.out)["runs"][0]
        assert run["results"] == []
        assert not any("ml-" in rule["id"] for rule in run["tool"]["driver"]["rules"])
