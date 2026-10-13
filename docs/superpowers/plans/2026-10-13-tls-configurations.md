# Phase 3 Local TLS Configuration Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement task-by-task.

**Goal:** Scan literal Nginx/OpenSSL TLS declarations and add the requested interactive QRYPT banner.
**Architecture:** Reuse Semgrep target discovery and its existing exclusion/limit diagnostics. A small local parser interprets selected `.conf` and `.cnf` files; source detection remains unchanged. All findings use the existing report model and shared SARIF rule descriptors.
**Tech Stack:** Python standard library, existing Semgrep/ruamel.yaml, pytest.
**Spec:** README.md Phase 3 roadmap and the user's banner request.

## Global Constraints

- Detect configured intent, never claim negotiated TLS behavior or effective inherited settings.
- No network probes, target execution, certificate/key inspection, or include expansion.
- `.cnf` and `openssl*.conf` are OpenSSL; other `.conf` files use Nginx directive syntax. Document this scope.
- Analyze Groups/Curves, SignatureAlgorithms/ClientSignatureAlgorithms, CipherString/Ciphersuites and Nginx equivalents plus `ssl_dhparam`.
- Unknown/default/dynamic relevant selections and includes produce private diagnostics and incomplete exit 2. Intentional Git/Semgrep ignores stay intentional.
- Keep JSON schema version 1, advisory exit 0, enforcement exit 1, errors exit 2; AGENTS.md unchanged.
- Banner appears only for interactive text stdout, never JSON/SARIF, redirected text or report files.

## Review Focus

- Comments, quoting, multiline values and unrelated directives must not create matches.
- Cipher removals (`!`, `-`) and reorder-only (`+`) must not be mistaken for enabled cryptography.
- Variables/default aliases/includes and malformed or unreadable files must not look like a complete clean scan.
- Mixed source/config targets and ignored/oversized configs preserve counting, evidence and exit codes.
- The exact banner must not corrupt automation/report output.

## Task 1: TLS analysis and reporting

**Files:** src/qrypt/tls.py, src/qrypt/rules/config-input.yml, src/qrypt/scanner.py, src/qrypt/sarif.py, tests/test_tls.py, tests/test_sarif.py.
**Interfaces:** `scan_config(path: Path, relative: str) -> tuple[list[dict], list[dict]]`; `TLS_RULES` contains four shared report rule descriptors. Internal Semgrep discovery matches never become findings or SARIF rules.

- [ ] Write failing tests for literal groups/signatures, quoted/commented/multiline declarations, exclusions/re-addition/reordering, symmetric TLS 1.3 suites, diagnostics, locations and privacy.
- [ ] Implement bounded syntax parsing and literal algorithm classification; leave unsupported values unresolved.
- [ ] Extend selected extensions and generic discovery; merge TLS results/errors into the source report without bypassing ignores or limits.
- [ ] Test real mixed/config-only scans, schema-valid SARIF, ignored configs, oversized/malformed inputs and exit codes.
- [ ] Run full pytest, Ruff and build; commit the verified TLS feature.

## Task 2: Interactive banner

**Files:** src/qrypt/banner.py, src/qrypt/cli.py, tests/test_banner.py.
**Interface:** `BANNER` is the user's exact block-art text; CLI prepends it only for successful interactive text stdout.

- [ ] Write failing TTY/output-mode tests.
- [ ] Add the banner and gate it using stdout.isatty(), text format and no output destination.
- [ ] Run focused/full tests and Ruff; commit separately.

## Task 3: Examples and verification

**Files:** examples/nginx.conf, examples/openssl.cnf, examples/reports/, README.md, pyproject.toml.

- [ ] Add self-contained TLS scan examples and update supported coverage/commands/limitations; bump development milestone to 0.2.0.
- [ ] Regenerate JSON/SARIF examples and validate their schema, private paths and finding consistency.
- [ ] Build/install wheel and rebuild Docker; verify read-only offline scans and Python 3.12/3.14 tests.
- [ ] Commit, request one independent final review, fix Important findings with RED→GREEN regressions, and record verification. Hosted/public GitHub demonstration stays pending.
