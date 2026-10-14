# Interactive Terminal Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan inline, task-by-task, followed by one independent review.

**Goal:** Make plain `qrypt` open a responsive command prompt with scan results, finding details and safe report export.
**Architecture:** Textual owns terminal interaction; an asynchronous child CLI returns the existing normalized JSON report. Reuse existing serializers and atomic output helpers. Keep process ownership/cleanup in a small separate module so lifecycle tests do not depend on widgets.
**Tech Stack:** Python 3.12+, Textual, asyncio/POSIX process groups, pytest and existing Semgrep rules.
**Spec:** [Approved interactive terminal design](../specs/2026-10-13-interactive-terminal-design.md). User approved implementation on 2026-10-14.

## Global Constraints

- Plain `qrypt` launches only with interactive stdin/stdout; redirected no-argument use returns `2` and usage. Preserve `qrypt scan ...` and `--help`.
- Linux/POSIX first; Windows interactive process cleanup remains outside verified support.
- Commands are `/scan [path]`, `/export <format> <path>`, `/help`, `/quit`; formats are `text`, `json`, `sarif`, `cbom`. Parse with `shlex.split`, never a shell.
- Relative paths use the startup directory. No automatic scan, persistent command history, automatic report writes, AI chat or remediation.
- One scan at a time; reject scan/export while busy. Retain and label previous results on a failure without a valid report. Incomplete reports replace results and remain exportable.
- Async child command is `sys.executable -m qrypt scan <target> --format json`. Own its POSIX process group; quitting terminates, escalates and reaps owned processes, including surviving descendants.
- Preserve normalized evidence and existing output safety. Render untrusted strings literally with terminal control characters removed; keep Unicode and original exported evidence.
- Preserve AGENTS.md and configured author. Commit each verified logical unit; no push/merge without authorization for this branch.

## Review Focus

- A child exits before Semgrep, or descendants ignore TERM: cleanup must still stop the owned group (Task 1 tests).
- Fast repeated submissions or quit during spawning must not create an orphan or replace results after cancellation (Task 1/2 tests).
- A failed second scan must not present the first target's results as new evidence (Task 2 tests).
- Malformed child JSON, invalid report fields and control/markup sequences must not crash or manipulate the interface (Task 1/2 tests).
- Narrow terminals, redirected invocation and installed/container execution must retain usable navigation and scripted output (Task 2/3 checks).

## Task 1: Reusable Reports and Owned Scan Process

**Files:** Modify `src/qrypt/cli.py`; create `src/qrypt/tui_process.py`, `tests/test_tui_process.py`; extend report tests where needed.
**Interfaces:** Produce `render_report(report: dict, output_format: str) -> str` in `cli.py`, with no banner. Preserve `_validate_output(path, output_format)` and `_write_report(path, content)`. Produce `async run_scan(target: Path) -> dict` in `tui_process.py`; invalid/failed output raises `ValueError` with diagnostics, cancellation propagates after cleanup. The child return codes and report status/errors must agree.

- [ ] Write RED regressions for serializer parity, a real source scan, incomplete TLS evidence, failure without JSON, malformed report fields and invalid exit/status combinations. Use `asyncio.run` so no extra async pytest plugin is needed.
- [ ] Write RED owned-process tests: cancellation during startup, a TERM-ignoring descendant, and an exited wrapper with a live descendant. Spawn test-owned processes only; bound waits and reap test children.
- [ ] Extract the existing report-format branches into `render_report`; leave banner gating at CLI stdout. Implement the async subprocess boundary with `start_new_session=True`, captured pipes, report validation, and cleanup in `finally`.
- [ ] On cleanup, signal only the owned process group, wait a bounded grace period, escalate to KILL if still alive, and await wrapper completion. Ensure cancellation cannot interrupt cleanup or lose a successfully spawned process.
- [ ] Run focused tests, then `.venv/bin/pytest -q`, Ruff and `git diff --check`. Expected: all pass and old output/exit tests remain green.
- [ ] Commit: `feat: add cancellable interactive scan execution`.

## Task 2: Command Prompt, Results Panel and Entry Point

**Files:** Create `src/qrypt/tui.py`, `tests/test_tui.py`; modify `cli.py`, `pyproject.toml`; extend `tests/test_cli.py`.
**Interfaces:** Consume Task 1 helpers. Produce `QryptApp` and `launch() -> int` in `tui.py`. CLI imports `launch` lazily for no-argument interactive invocation only. Textual is a runtime dependency, resolved to a stable release compatible with Python 3.12 and the existing environment.

- [ ] Write RED entry-point tests for interactive launch, redirected input/output, existing help and scripted commands. Patch only terminal detection/launch at this boundary; preserve real parser behavior.
- [ ] Write RED headless UI tests using `QryptApp.run_test()` and Textual Pilot: initial prompt focus, `/help`, malformed quoting/arity, quoted paths, all four exports, unsafe destinations, and no-report export.
- [ ] Write RED UI behavior tests for busy scan/export rejection, empty/incomplete results, failed second scan with retained target labels, row details, literal hostile display strings, prompt history and quitting. Use real widgets; replace only the slow subprocess boundary for deterministic state cases. Include a real child scan through the app.
- [ ] Install/depend on Textual; compose banner/compact heading, cwd/status/coverage, inventory table, scrollable details and command input. Match current QRYPT styling without adding a theme system. Use in-memory history only.
- [ ] Implement `/scan`, `/export`, `/help`, `/quit`, input history, focus navigation and Ctrl+C exit. Set busy state before starting the worker; catch expected failures without losing prior results. Cancel/await the worker before terminal teardown.
- [ ] Add no-argument dispatch and a clear unsupported-platform message for the interactive path. Keep noninteractive CLI imports independent of Textual startup.
- [ ] Run focused headless tests at wide and narrow sizes, then full pytest, Ruff/format and package build. Expected: responsive prompt, correct evidence and no regressions.
- [ ] Commit: `feat: launch QRYPT command prompt and results panel`.

## Task 3: Packaging, Real Terminal Demo and Verification

**Files:** Modify `requirements-container.txt`, `README.md`; add `docs/assets/qrypt-tui.png`; update this plan's completion record. Keep the existing CLI screenshot.
**Interfaces:** Installed wheel and Docker image expose the same no-argument TUI; scripted reports remain independent of a terminal. Existing version `0.3.0` remains until the next release milestone is chosen.

- [ ] Resolve the new dependency set in the pinned Python 3.12 container while retaining compatible existing pins. Run `pip check`, Docker build and the full Python 3.12 suite; expected: no dependency conflicts.
- [ ] Build/install the wheel in a separate environment. Verify redirected no-argument usage returns `2`, scripted scan/export still succeeds, and an owned PTY launches the TUI.
- [ ] Verify Docker scripted scanning offline, non-root and read-only. Launch no-argument Docker with `-it` in an owned PTY, submit `/scan examples`, then `/quit`; verify terminal restoration and process cleanup.
- [ ] Capture a real dedicated VTE terminal running installed QRYPT with populated results and finding details; inspect the PNG. Add the screenshot, installation/launch instructions, commands, export-overwrite behavior and Linux-first coverage to README. Document exports to writable destinations and interactive Docker invocation.
- [ ] Run final Python 3.12/3.14 suites, Ruff, format, build and whitespace checks. Commit: `docs: document interactive QRYPT and terminal demo`.
- [ ] Request exactly one independent whole-change review. Fix Important/Critical findings in one author pass with RED→GREEN regressions and a green suite; record remaining limits and decisions. Leave a clean feature branch.

## Plan Review

Self-reviewed against the approved spec: all six acceptance criteria map to the tasks above. Lifecycle cleanup and command/report validation are included before UI integration. Native execution in this session is recommended because all tasks share the same scan/report interface and one final independent review covers the complete interaction.

Awaiting user review of this plan before implementation, per the Superpowers writing-plans handoff.
