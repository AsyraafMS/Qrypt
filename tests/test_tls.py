import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from qrypt.cli import main
from qrypt.scanner import scan
from qrypt.tls import scan_config


@pytest.mark.parametrize(
    "name,content,algorithms",
    [
        (
            "nginx.conf",
            "# ssl_ecdh_curve X448;\nserver {\n ssl_ecdh_curve\n"
            ' "X25519:secp384r1"; # private\n'
            " ssl_conf_command SignatureAlgorithms "
            "rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256;\n"
            " ssl_dhparam /PRIVATE/key.pem;\n}\n",
            {"ECDH", "EC", "RSA", "ECDSA", "DH"},
        ),
        (
            "openssl.cnf",
            "[tls]\nGroups = X25519:\\\n P-256:ffdhe2048 # comment\n"
            "SignatureAlgorithms = "
            '"rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256"\n',
            {"ECDH", "EC", "DH", "RSA", "ECDSA"},
        ),
    ],
)
def test_literal_tls_declarations_are_private_and_located(
    tmp_path, name, content, algorithms
):
    path = tmp_path / name
    path.write_text(content)
    findings, errors = scan_config(path, name)
    assert errors == []
    assert {f["algorithm"] for f in findings} == algorithms
    assert all(
        f["line"] > 1 and f["column"] >= 1 and f["path"] == name for f in findings
    )
    assert all("configured-" in f["operation"] for f in findings)
    assert "PRIVATE" not in json.dumps(findings)
    assert str(tmp_path) not in json.dumps(findings)


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("ECDHE-RSA-AES128-GCM-SHA256", {"ECDH", "RSA"}),
        (
            "ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
            {"ECDH", "ECDSA", "DH", "RSA"},
        ),
        ("!aRSA:!ECDHE:+ECDHE-RSA-AES128-GCM-SHA256", set()),
        ("ECDHE-RSA-AES128-GCM-SHA256:!aRSA", set()),
        (
            "ECDHE-RSA-AES128-GCM-SHA256:-aRSA:ECDHE-RSA-AES128-GCM-SHA256",
            {"ECDH", "RSA"},
        ),
        ("ECDHE-RSA-AES128-GCM-SHA256:!aRSA:ECDHE-RSA-AES128-GCM-SHA256", set()),
    ],
)
def test_cipher_exclusion_and_reordering(tmp_path, expression, expected):
    path = tmp_path / "nginx.conf"
    path.write_text(f'ssl_ciphers "{expression}";\n')
    findings, errors = scan_config(path, path.name)
    assert errors == []
    assert {f["algorithm"] for f in findings} == expected


def test_tls13_symmetric_suite_does_not_infer_key_exchange(tmp_path):
    path = tmp_path / "openssl.cnf"
    path.write_text(
        "[tls]\nCiphersuites = TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256\n"
    )
    assert scan_config(path, path.name) == ([], [])


@pytest.mark.parametrize(
    "name,content,error",
    [
        ("nginx.conf", "ssl_ecdh_curve $PRIVATE;\n", "TLSUnresolvedSetting"),
        ("nginx.conf", "ssl_ciphers DEFAULT:!aRSA;\n", "TLSUnresolvedSetting"),
        ("nginx.conf", "ssl_ecdh_curve auto;\n", "TLSUnresolvedSetting"),
        ("openssl.cnf", "[tls]\nGroups = $ENV::PRIVATE\n", "TLSUnresolvedSetting"),
        ("openssl.cnf", ".include /PRIVATE/outside.cnf\n", "TLSUnresolvedInclude"),
        ("nginx.conf", "include /PRIVATE/outside.conf;\n", "TLSUnresolvedInclude"),
        ("nginx.conf", "server { ssl_ecdh_curve X25519;", "TLSConfigSyntaxError"),
        ("nginx.conf", 'ssl_ecdh_curve "X25519;', "TLSConfigSyntaxError"),
        ("nginx.conf", "ssl_ecdh_curve X25519\n", "TLSConfigSyntaxError"),
    ],
)
def test_unresolved_and_malformed_inputs_are_private_diagnostics(
    tmp_path, name, content, error
):
    path = tmp_path / name
    path.write_text(content)
    _, errors = scan_config(path, name)
    assert any(item["type"] == error for item in errors)
    assert "PRIVATE" not in json.dumps(errors)
    assert str(tmp_path) not in json.dumps(errors)


def test_mixed_source_config_scan_and_sarif(tmp_path, capsys):
    (tmp_path / "nginx.conf").write_text("ssl_ecdh_curve X25519;\n")
    (tmp_path / "openssl.cnf").write_text(
        "[tls]\nSignatureAlgorithms = rsa_pss_rsae_sha256\n"
    )
    (tmp_path / "app.js").write_text(
        'const c = require("crypto"); c.createECDH("prime256v1");\n'
    )
    assert main(["scan", str(tmp_path), "--format", "sarif"]) == 0
    result = json.loads(capsys.readouterr().out)
    schema = json.loads(
        (Path(__file__).parent / "schemas/sarif-2.1.0.json").read_text()
    )
    Draft7Validator(schema).validate(result)
    run = result["runs"][0]
    assert len(run["results"]) == 3
    assert run["properties"]["scanned_files"] == 3
    assert not any("internal" in f["ruleId"] for f in run["results"])
    assert main(["scan", str(tmp_path), "--fail-on-findings"]) == 1
    capsys.readouterr()


def test_config_only_and_ignored_config(tmp_path):
    (tmp_path / "nginx.conf").write_text("ssl_ecdh_curve X25519;\n")
    (tmp_path / ".semgrepignore").write_text("ignored.conf\n")
    (tmp_path / "ignored.conf").write_text("ssl_ecdh_curve $PRIVATE;\n")
    report = scan(tmp_path)
    assert report["status"] == "completed"
    assert report["scanned_files"] == 1
    assert len(report["findings"]) == 1
    assert scan(tmp_path / "nginx.conf")["findings"][0]["algorithm"] == "ECDH"


def test_unresolved_scan_retains_evidence_and_returns_two(tmp_path, capsys):
    (tmp_path / "nginx.conf").write_text(
        "ssl_ecdh_curve X25519;\ninclude /PRIVATE/file;\n"
    )
    assert main(["scan", str(tmp_path), "--format", "json", "--fail-on-findings"]) == 2
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["status"] == "incomplete"
    assert report["findings"]
    assert "PRIVATE" not in captured.out + captured.err


def test_oversize_config_is_incomplete(tmp_path):
    (tmp_path / "nginx.conf").write_text("ssl_ecdh_curve X25519;\n")
    (tmp_path / "large.conf").write_text("# padding\n" * 150000)
    report = scan(tmp_path)
    assert report["status"] == "incomplete"
    assert any(
        e.get("path") == "large.conf" and e.get("reason") == "exceeded_size_limit"
        for e in report["errors"]
    )


@pytest.mark.parametrize(
    "exception,expected",
    [
        (PermissionError("PRIVATE"), "TLSConfigReadError"),
        (
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "PRIVATE"),
            "TLSConfigEncodingError",
        ),
    ],
)
def test_config_read_failures_preserve_privacy(
    tmp_path, monkeypatch, exception, expected
):
    def fail_read(*args, **kwargs):
        raise exception

    monkeypatch.setattr(Path, "read_text", fail_read)
    findings, errors = scan_config(tmp_path / "openssl.cnf", "openssl.cnf")
    assert findings == []
    assert errors == [{"type": expected, "path": "openssl.cnf"}]
