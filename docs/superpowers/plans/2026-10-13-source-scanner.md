# QRYPT Source Scanner Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Execution is authorized by the user's request to start Phase 1.

**Goal:** Deliver the Phase 1 local Python/JavaScript scanner with terminal and JSON migration-candidate reports.

**Architecture:** Bundled original Semgrep rules detect explicit crypto API operations. A Python runner normalizes results; an argparse CLI validates inputs, renders reports, and enforces exit codes.

**Tech Stack:** Python 3.12+, setuptools, Semgrep CE 1.177.0, pytest, Ruff.

**Spec:** [Approved roadmap](../../../README.md).

## Global Constraints

- Source and rules live in `src/qrypt/`; tests and fixtures live in `tests/`.
- Only local Python and Node.js JavaScript are in Phase 1; no SARIF, TLS, CBOM, dashboard, or target-code execution.
- Use bundled rules, disable metrics and version checks, and omit source/key material from reports.
- Findings are advisory unless `--fail-on-findings`; exit 0 for completed scans, 1 for explicit enforcement, 2 for failed/incomplete scans.
- Reports expose scan coverage and parsing errors; zero findings never means proven readiness.

## Review Focus

- Imported aliases and unrelated same-named functions must be distinguished.
- Malformed source or an unavailable engine must not appear as a successful clean scan.
- Report paths must remain relative and report bodies must omit source snippets and secrets.
- An output path must not overwrite a scanned source file.
- Installed wheels must contain the same rules used by development scans.

## Task 1: Package tested detection rules

**Files:** `pyproject.toml`, `.gitignore`, package marker, bundled Python/JavaScript YAML rules, `tests/test_rules.py`, annotated fixtures.

**Produces:** Installed `qrypt` package and tested rule metadata (`algorithm`, `operation`, `confidence`, `guidance`) consumed by Task 2.

- [ ] Write a real-engine test for annotated positive/negative rule fixtures; run it RED without rules.
- [ ] Add original rules for Python RSA/DH/EC key generation, explicit ECDH/ECDSA operations, PyCryptodome RSA/ECC generation, and Node.js RSA/EC/DH key generation and ECDH/DH constructors. Do not infer ECDSA from generic EC key generation.
- [ ] Run the rule suite and Ruff GREEN; commit the independently tested rules/package.

## Task 2: Implement scan/report CLI

**Files:** `src/qrypt/scanner.py`, `src/qrypt/cli.py`, module entry point, `tests/test_cli.py`, scanner-boundary tests.

**Consumes:** Bundled rules and their metadata from Task 1.

**Produces:** `scan(target: Path) -> dict`; `main(argv: list[str] | None = None) -> int`; `qrypt scan PATH --format text|json --output PATH --fail-on-findings`.

- [ ] Write end-to-end tests for finding/clean scans, relative locations, privacy, output files, advisory/enforcing exits, malformed source, unsupported inputs, exclusions, missing engine, and unsafe output destinations; observe RED.
- [ ] Implement the minimal Semgrep subprocess runner and versioned JSON normalization. Use `schema_version: 1`, completion status, scanned-file count, skipped-file count, findings, and errors. Emit diagnostics to stderr.
- [ ] Implement text/JSON rendering and safe atomic output replacement; reject existing source files and other unsafe destinations before scanning.
- [ ] Run the full suite and Ruff GREEN; commit the working CLI.

## Task 3: Document and verify installed use

**Files:** `README.md`, `examples/crypto_usage.py`, `examples/crypto_usage.js`.

- [ ] Add small review examples and actual install, usage, rule-coverage, and test commands. Mark Phase 1 complete while preserving later phases as planned.
- [ ] Build sdist/wheel; install the wheel in a fresh environment; scan examples from outside the repository and compare counts with development scans.
- [ ] Run all tests, Ruff, and whitespace checks; commit documentation/examples.
- [ ] Obtain one independent whole-change review; reproduce and fix any important findings with tests, then rerun the suite.

## Execution Notes

The starting working tree was clean. Work proceeds inline on `feat/source-scanner`; no separate worktree is needed for this single-worker change. No existing test suite or build baseline exists.
