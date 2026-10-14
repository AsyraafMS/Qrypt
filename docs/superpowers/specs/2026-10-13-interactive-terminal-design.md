# QRYPT Interactive Terminal Design

## Intent and Scope

Running `qrypt` without arguments opens a terminal application with a command prompt and results panel. The user selected this interaction model over a menu dashboard. The application makes the existing local scanner easier to use; its evidence, migration guidance, privacy boundaries and report formats remain authoritative.

This is a new interface subsystem, implemented with Textual. The first release targets the current Linux environment and POSIX terminals; Windows interactive support requires separate process-lifecycle verification. Existing scripted commands retain their behavior. AI chat, automatic remediation, network scanning, persistent sessions and the planned HTML dashboard are outside this change.

## Entry Point and Layout

- No arguments and interactive stdin/stdout: launch the TUI. No arguments with redirected input/output: print usage and return `2`, without terminal control sequences.
- `qrypt scan ...` continues through argparse with the existing output and exit semantics. `qrypt --help` continues to print CLI help.
- Show the supplied QRYPT banner, startup working directory, scan status and coverage caveat above a results table. On narrow terminals, use a compact QRYPT heading instead of clipping the banner.
- Keep a command input and short command help at the bottom. Tab moves between prompt, table and details. Arrow keys navigate results; selecting a row shows its full location, rule, confidence and guidance.
- Table columns: classification, algorithm, operation, file and line. Include classical migration candidates and PQC inventory observations; distinguish their classification explicitly. Show diagnostics in the details/status area, including incomplete scans and empty results.
- Provide in-memory prompt history through Up/Down. Never save command history or reports automatically.

## Commands

Paths resolve against the startup working directory; scanning does not change it. Parse arguments with `shlex.split`, without a shell. Quoted paths with spaces are supported. Unknown commands, malformed quoting and incorrect argument counts display an actionable error and leave results intact.

| Command | Behavior |
| --- | --- |
| `/scan [path]` | Scan the specified file/directory, defaulting to `.`. |
| `/export <format> <path>` | Save the most recent report as `text`, `json`, `sarif` or `cbom` using existing output validation and atomic writes. |
| `/help` | Show syntax, keyboard navigation and coverage limitations. |
| `/quit` | Exit and stop any active scan. Ctrl+C provides the same safe exit. |

One scan runs at a time. While scanning, retain previous results with their target/status clearly labeled; reject another scan or export until the active scan finishes. A completed or incomplete report replaces previous results and remains exportable. If the new scan fails without a report, retain previous results, identify their target, and show the failed attempt separately. Export before any report exists fails clearly. Existing valid report destinations may be replaced, matching current CLI behavior.

## Execution and Error Handling

Use an asynchronous subprocess invoking `sys.executable -m qrypt scan <target> --format json`. This reuses scanner normalization and exit semantics without blocking the UI or duplicating detection logic. A new POSIX process session allows quitting to stop the scanner and Semgrep process group. Terminate, wait for a bounded grace period, then kill/reap the group if needed; perform cleanup even after the wrapper exits with surviving descendants. Cancellation discards the partial command output and never overwrites prior results.

Exit `0` is advisory success; exit `2` can still contain an incomplete JSON report with partial evidence. Check the return code and validate the expected report shape before populating widgets. Missing engines, malformed output, unsupported targets, subprocess failures and scan timeouts produce readable errors, not a crashed TUI. Keep the existing 120-second engine timeout; avoid claiming measured percentages because the scanner supplies none.

Treat all paths, diagnostics and report strings as untrusted display text: disable Rich markup interpretation and remove terminal control characters while preserving Unicode. Export the original normalized evidence through the existing JSON/SARIF/CBOM serializers. Do not execute commands from source or guidance and do not read private key files.

## Integration and Verification

Add `src/qrypt/tui.py`; keep argument dispatch in `cli.py`. Reuse report serializers, output-path validation and atomic writing instead of adding a second report implementation. Load the UI only when interactive mode is selected. Declare Textual as an installation dependency and update the pinned container dependency set so installed wheels and the Docker image include the interface. Document `docker run -it` separately from existing noninteractive scans.

Use focused pytest tests and Textual's headless testing for no-argument dispatch, command parsing, quoted paths, one-active-scan enforcement, row details, incomplete reports, error recovery and export guards. Test subprocess-group cleanup with a real owned child process, not only mocks. Preserve existing banner, machine-output, privacy and CLI exit tests. Run the full suite, Ruff, package build and installed-wheel/container smoke checks. Capture and inspect a real TUI screenshot and update the README with the new launch command and command examples.

## Acceptance Criteria

1. An installed `qrypt` opens the prompt/results interface in a Linux terminal.
2. `/scan examples` renders the same evidence as the scripted JSON scan without freezing keyboard input.
3. Selecting a row displays evidence and guidance; PQC observations never become migration warnings.
4. All four export formats retain their existing validation, privacy and completeness behavior.
5. Invalid commands and failed/incomplete scans remain recoverable; quitting leaves no owned scan processes running.
6. Existing CLI invocations and redirected outputs pass their regression tests.

## Review Status

Self-reviewed for command syntax, entry-point compatibility, subprocess lifecycle, stale-result labeling and output safety. User approved implementation on 2026-10-14. The [implementation plan](../plans/2026-10-14-interactive-terminal.md) is ready for review before execution.
