"""Literal TLS configuration evidence; no includes, keys or servers are opened."""

import re
import shlex
from pathlib import Path

TLS_RULES = [
    {
        "id": f"qrypt.tls.{name}",
        "message": f"Explicit TLS {label} is a migration candidate requiring review.",
        "metadata": {
            "guidance": (
                "Review this literal declaration and its deployment context; "
                "verify inheritance, providers, certificate algorithms and "
                "negotiated behavior before choosing compatible PQC migration options."
            )
        },
    }
    for name, label in [
        ("groups", "group selection"),
        ("signatures", "signature selection"),
        ("ciphers", "cipher selection"),
        ("dhparam", "DH parameter reference"),
    ]
]
COMMANDS = {
    "groups": "groups",
    "curves": "groups",
    "signaturealgorithms": "signatures",
    "clientsignaturealgorithms": "signatures",
    "cipherstring": "ciphers",
    "ciphersuites": "suites",
    "dhparameters": "dhparam",
}
NGINX = {"ssl_ecdh_curve": "groups", "ssl_ciphers": "ciphers", "ssl_dhparam": "dhparam"}
GROUPS = {
    **dict.fromkeys(["X25519", "X448"], "ECDH"),
    **dict.fromkeys(
        [
            "P-256",
            "P-384",
            "P-521",
            "prime256v1",
            "secp256r1",
            "secp384r1",
            "secp521r1",
        ],
        "EC",
    ),
    **dict.fromkeys([f"ffdhe{size}" for size in (2048, 3072, 4096, 6144, 8192)], "DH"),
}
TLS13_SUITES = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
}
KEY = "configured-key-agreement"
AUTH = "configured-authentication"
SELECTORS = {
    "kRSA": {("RSA", KEY)},
    "aRSA": {("RSA", AUTH)},
    "RSA": {("RSA", KEY), ("RSA", AUTH)},
    **dict.fromkeys(["DHE", "EDH", "DH", "kDHE", "kEDH"], {("DH", KEY)}),
    **dict.fromkeys(["ECDHE", "EECDH", "ECDH", "kECDHE", "kEECDH"], {("ECDH", KEY)}),
    **dict.fromkeys(["ECDSA", "aECDSA"], {("ECDSA", AUTH)}),
}
TOKENS = re.compile(
    r"""(?P<comment>\#[^\n]*)|(?P<quoted>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
    r"""|(?P<punct>[;{}])|(?P<word>(?:\$\{[^}]*\}|[^\s;{}#'"])+)"""
)


def _tokens(text):
    end, line, column = 0, 1, 1
    for match in TOKENS.finditer(text):
        gap = text[end : match.start()]
        if gap.strip():
            raise ValueError("Invalid configuration syntax")
        line += gap.count("\n")
        column = len(gap.rsplit("\n", 1)[-1]) + 1 if "\n" in gap else column + len(gap)
        raw = match.group()
        if match.lastgroup != "comment":
            value = shlex.split(raw)[0] if match.lastgroup == "quoted" else raw
            yield value, line, column, match.lastgroup
        line += raw.count("\n")
        column = len(raw.rsplit("\n", 1)[-1]) + 1 if "\n" in raw else column + len(raw)
        end = match.end()
    if text[end:].strip():
        raise ValueError("Invalid configuration syntax")


def _nginx(text):
    pending, contexts = [], []
    for value, line, column, kind in _tokens(text):
        if kind != "punct":
            pending.append((value, line, column))
        elif value == ";":
            if pending and (
                pending[0][0] == "include"
                or not any(
                    c in {"map", "geo", "types", "split_clients", "charset_map"}
                    for c in contexts
                )
            ):
                yield (
                    pending[0][0],
                    [v[0] for v in pending[1:]],
                    pending[0][1],
                    pending[0][2],
                )
            pending = []
        elif value == "{":
            if (
                not pending
                or pending[0][0] in NGINX
                or pending[0][0] == "ssl_conf_command"
            ):
                raise ValueError("Invalid directive block")
            contexts.append(pending[0][0])
            pending = []
        else:
            if pending or not contexts:
                raise ValueError("Unbalanced configuration block")
            contexts.pop()
    if pending or contexts:
        raise ValueError("Unterminated configuration")


def _openssl(text):
    logical, start = "", 1
    for number, raw in enumerate(text.splitlines(), 1):
        if not logical:
            start = number
        backslashes = len(raw) - len(raw.rstrip("\\"))
        if backslashes % 2:
            logical += raw[:-1]
            continue
        logical += raw
        column = len(logical) - len(logical.lstrip()) + 1
        words = " ".join(shlex.split(logical, comments=True))
        logical = ""
        if not words:
            continue
        if words.startswith("[") and words.endswith("]"):
            continue
        if words.startswith(".include"):
            yield "include", [], start, column
            continue
        if words.startswith(".pragma"):
            yield "unresolved", [], start, column
            continue
        if "=" not in words:
            raise ValueError("Expected configuration assignment")
        name, value = words.split("=", 1)
        name = name.strip().rsplit("::", 1)[-1]
        if "." in name:
            name = name.partition(".")[2]
        yield name, [value.strip()], start, column
    if logical:
        raise ValueError("Unterminated continuation")


def _cipher(token):
    if token in SELECTORS:
        # RSA key-exchange suites also require RSA authentication.
        return SELECTORS["RSA"] if token == "kRSA" else SELECTORS[token]
    # shortcut: bounded modern suite names; extend this allowlist for new coverage.
    suffixes = {
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
        "AES128-SHA256",
        "CHACHA20-POLY1305",
    }
    for prefix, key in [
        ("ECDHE-RSA-", "ECDH"),
        ("ECDHE-ECDSA-", "ECDH"),
        ("DHE-RSA-", "DH"),
    ]:
        allowed = suffixes | {"AES256-SHA384" if key == "ECDH" else "AES256-SHA256"}
        if token.startswith(prefix) and token[len(prefix) :] in allowed:
            auth = "ECDSA" if "ECDSA" in prefix else "RSA"
            return {(key, KEY), (auth, AUTH)}
    return None


def _cipher_list(tokens):
    selected, banned, unresolved = {}, [], False
    for token in tokens:
        prefix = token[0] if token[0] in "!+-" else ""
        name = token[1:] if prefix else token
        if name in {"@STRENGTH"} or re.fullmatch(r"@SECLEVEL=[0-5]", name):
            continue
        evidence = _cipher(name)
        if evidence is None:
            unresolved = True
            continue

        def matches(entry):
            return entry == name or (
                name in SELECTORS and SELECTORS[name] <= _cipher(entry)
            )

        if prefix in ("!", "-"):
            selected = {n: e for n, e in selected.items() if not matches(n)}
            if prefix == "!":
                banned.append((name, SELECTORS.get(name, evidence)))
        elif prefix != "+":
            if not any(
                name == n or (n in SELECTORS and e <= evidence) for n, e in banned
            ):
                selected[name] = evidence
    return set().union(*selected.values()) if selected else set(), unresolved


def _evidence(kind, value):
    # Keep variable references atomic so names such as $ENV::X25519 are not evidence.
    value = re.sub(r"\$(?:\{[^}]*\}|[\w.]+(?:::[\w.]+)?)", "$unresolved", value)
    tokens = [token for token in re.split(r"[:,\s]+", value) if token]
    if not tokens:
        return set(), True
    if kind == "dhparam":
        return {("DH", "configured-parameter-reference")}, "$" in value or "\\" in value
    if kind == "ciphers":
        return _cipher_list(tokens)
    if kind == "suites":
        return set(), any(token not in TLS13_SUITES for token in tokens)
    evidence, unresolved = set(), False
    for token in tokens:
        if "$" in token or "\\" in token:
            unresolved = True
            continue
        if kind == "groups":
            algorithm = GROUPS.get(token)
            operation = "configured-group"
        else:
            operation = "configured-signature"
            match = re.fullmatch(
                r"(RSA|DSA|ECDSA)\+(SHA1|SHA224|SHA256|SHA384|SHA512)", token
            )
            if match:
                algorithm = match[1]
            elif re.fullmatch(
                r"rsa_(?:pss_(?:rsae|pss)|pkcs1)_(?:sha1|sha256|sha384|sha512)", token
            ):
                algorithm = "RSA"
            elif re.fullmatch(
                r"ecdsa_(?:secp256r1_sha256|secp384r1_sha384|secp521r1_sha512|sha1)",
                token,
            ):
                algorithm = "ECDSA"
            elif token in ("ed25519", "ed448"):
                algorithm = "EdDSA"
            else:
                algorithm = None
        if algorithm:
            evidence.add((algorithm, operation))
        else:
            unresolved = True
    return evidence, unresolved


def scan_config(path: Path, relative: str) -> tuple[list[dict], list[dict]]:
    findings, errors = [], []
    openssl = (
        path.suffix == ".cnf"
        or path.name.startswith("openssl")
        or ".openssl." in path.name
    )
    try:
        text = path.read_text(encoding="utf-8")
        declarations = _openssl(text) if openssl else _nginx(text)
        for name, arguments, line, column in declarations:
            if name in ("include", "unresolved"):
                errors.append(
                    {
                        "type": "TLSUnresolvedInclude"
                        if name == "include"
                        else "TLSUnresolvedSetting",
                        "path": relative,
                        "line": line,
                    }
                )
                continue
            if openssl:
                kind = COMMANDS.get(name.lower())
            elif name == "ssl_conf_command":
                if len(arguments) != 2:
                    errors.append(
                        {"type": "TLSConfigSyntaxError", "path": relative, "line": line}
                    )
                    continue
                if "$" in arguments[0]:
                    errors.append(
                        {"type": "TLSUnresolvedSetting", "path": relative, "line": line}
                    )
                    continue
                kind = COMMANDS.get(arguments[0].lower())
                arguments = arguments[1:]
            else:
                kind = NGINX.get(name)
                if kind and len(arguments) != 1:
                    errors.append(
                        {"type": "TLSConfigSyntaxError", "path": relative, "line": line}
                    )
                    continue
            if kind is None:
                continue
            evidence, unresolved = _evidence(kind, " ".join(arguments))
            if unresolved:
                errors.append(
                    {"type": "TLSUnresolvedSetting", "path": relative, "line": line}
                )
            rule = next(
                r
                for r in TLS_RULES
                if r["id"] == f"qrypt.tls.{'ciphers' if kind == 'suites' else kind}"
            )
            for algorithm, operation in sorted(evidence):
                findings.append(
                    {
                        "rule_id": rule["id"],
                        "path": relative,
                        "line": line,
                        "column": column,
                        "algorithm": algorithm,
                        "operation": operation,
                        "confidence": "high",
                        "guidance": rule["metadata"]["guidance"],
                    }
                )
    except UnicodeError:
        errors.append({"type": "TLSConfigEncodingError", "path": relative})
    except OSError:
        errors.append({"type": "TLSConfigReadError", "path": relative})
    except ValueError:
        errors.append({"type": "TLSConfigSyntaxError", "path": relative})
    return findings, errors
