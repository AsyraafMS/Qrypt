# Phase 4 Cryptographic Inventory Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans task-by-task.

**Goal:** Export CycloneDX 1.6 CBOM, recognize supported ML-KEM/ML-DSA calls as inventory, and document a real terminal screenshot.
**Architecture:** Add an inventory array to the existing normalized report while preserving migration findings. Reuse the Node crypto key-generation selectors for six explicit PQC identifiers. A standard-library CBOM exporter groups observed algorithm/operation pairs and retains occurrence locations without constructing a dependency graph.
**Tech Stack:** Python 3.12+, existing Semgrep rules, pytest/JSON Schema, CycloneDX 1.6; GNOME Terminal/Xvfb for an actual terminal screenshot.
**Spec:** README.md Phase 4 roadmap; user's screenshot/README request.

## Global Constraints

- Recognize Node `generateKeyPair`/`generateKeyPairSync` literal `ml-kem-512/768/1024` and `ml-dsa-44/65/87`. Do not match bare strings, unrelated libraries, dynamic selectors or shadowed imports.
- PQC entries are inventory observations, not migration warnings; advisory/enforcement/error exits stay 0/1/2. Preserve existing finding shapes, JSON schema version 1 and SARIF results.
- CBOM assets record observed algorithms and operations, relative occurrence paths/lines, rule IDs and classification. Do not invent dependency edges, deployment state, curves/key sizes or security scores.
- Scan completion is not inventory completeness: composition remains unknown for completed bounded scans, incomplete for errors. Preserve partial evidence and diagnostics privately.
- CLI adds `--format cbom`, with `.json` output and existing atomic-write guards; no banner in machine output or saved files.
- Preserve AGENTS.md, configured author and atomic commits. No external publishing or visibility changes.
- Screenshot captures a dedicated real terminal running QRYPT; exclude personal history/credentials and inspect the PNG before embedding it in README.

## Review Focus

- PQC observations must not disappear from inventory or turn into SARIF/enforcement warnings.
- Aliases/shadowing and unsupported identifiers must retain detection boundaries.
- Repeated same-line occurrences and unknown EC/RSA purpose must not fabricate or lose evidence.
- Empty/incomplete scans must produce schema-valid CBOM with honest completeness and exit codes.
- Screenshot must contain real CLI output, legible block art and a working relative README image link.

## Task 1: Inventory and PQC recognition

**Files:** src/qrypt/scanner.py, src/qrypt/rules/javascript.yml, src/qrypt/cli.py, src/qrypt/sarif.py, tests/test_inventory.py, tests/fixtures/javascript.js.
**Interfaces:** report adds `inventory: list[dict]`; items preserve finding evidence plus `migration_candidate: bool`. Six inventory-only rules reuse existing YAML keygen/module anchors; only classical candidates enter findings/SARIF.

- [ ] Write failing real scans and annotated fixtures for all identifiers, imports/aliases/shadowing, pure/mixed PQC, privacy and exit codes.
- [ ] Normalize all candidate and PQC evidence into inventory; preserve candidate arrays and filter inventory-only SARIF rule descriptors.
- [ ] Show PQC observations in terminal text, retain banner/output gating and readiness caveats.
- [ ] Run pytest, Ruff and build; commit the verified feature.

## Task 2: CycloneDX CBOM

**Files:** src/qrypt/cbom.py, src/qrypt/cli.py, tests/test_cbom.py, tests/schemas/cyclonedx-1.6/, pyproject.toml.
**Interface:** `cbom_report(report: dict) -> dict`; deterministic algorithm/operation asset IDs and occurrence references, private metadata properties, observed primitives only.

- [ ] Vendor official CycloneDX schema/reference files with provenance/license and configure offline validation.
- [ ] Write failing tests for empty/completed/incomplete reports, distinct/repeated locations, stable IDs, unknown primitives, classification and output safety.
- [ ] Implement the minimal exporter and CLI format, preserving errors/enforcement and atomic output behavior.
- [ ] Validate against schema, run suite/Ruff/build and commit.

## Task 3: Documentation, screenshot and verification

**Files:** README.md, examples/pqc_usage.js, examples/reports/, docs/assets/qrypt-terminal.png, pyproject.toml.

- [ ] Add scan-only PQC examples, bump milestone to 0.3.0 and regenerate JSON/SARIF/CBOM examples.
- [ ] Capture a dedicated GNOME terminal running `qrypt scan examples/pqc_usage.js`; inspect the actual screenshot and embed it with a relative README link.
- [ ] Document supported APIs, inventory/CBOM fields, grouping/completeness limits and usage.
- [ ] Build/install wheel and Docker; run Python 3.12/3.14 suites and offline non-root/read-only scans; commit.
- [ ] Request one independent review, fix Important issues with RED→GREEN regressions, record checks, and leave a clean branch. Public GitHub validation remains pending.
