# Repository Guidelines

## Project Structure & Module Organization

This repository is at an initial setup stage. `README.md` identifies the project as QuantumLens; it is currently the only tracked project file besides this guide. No source, test, or asset directories exist yet.

When adding implementation files, group them by responsibility and document their locations in `README.md`. Introduce source, test, and asset directories only when needed. Keep generated output and local configuration out of version control.

## Build, Test, and Development Commands

No build system, dependency manifest, development server, or test runner is configured. There are currently no project-specific build or test commands.

Useful repository checks include:

- `git status --short`: inspect pending changes before committing.
- `git diff --check`: catch whitespace errors in tracked changes.
- `git diff`: review the content of tracked changes.

When introducing tooling, document its installation requirements and exact build, test, and local development commands in `README.md`.

## Coding Style & Naming Conventions

No programming language, formatter, or linter has been selected. Match the conventions of the language and tooling introduced with the first implementation; avoid adding competing style tools.

For Markdown, use descriptive headings, concise paragraphs, fenced code blocks for multiline examples, and relative links to repository files. Use descriptive filenames and consistent indentation within each file.

## Testing Guidelines

No testing framework or coverage threshold exists. When adding executable behavior, include focused tests for expected results and meaningful failure cases. Establish a consistent test naming convention with the selected framework and document how contributors run the tests.

## Commit & Pull Request Guidelines

The available history contains only `first commit`, so it establishes no recurring commit convention. Use short, descriptive commit subjects and keep each commit focused on one change.

Pull requests should explain the change, its purpose, and how it was verified. Link relevant issues when available; include screenshots for visual changes. If checks could not be run, state that clearly.

## Security & Configuration

Never commit credentials, tokens, or private configuration. If configuration becomes necessary, provide an example containing placeholders and document the required values.

# Git discipline

- Commit after every logical, self-contained unit of work: small, atomic, single-purpose commits. Never bundle unrelated changes into one commit.
- Do not keep meaningful work uncommitted between steps: finish a step, commit it, then start the next. Steady sequence of small commits, not one giant commit at the end.
- Commit message: short imperative summary line ("fix: 401 handling", "feat: add ..."). No trailing period, no "WIP", no filler.
- Keep the graph linear and readable: avoid creating merge commits unless asked.
- Run build/tests before committing. If something is red, fix it, or commit only the green subset and explicitly say what is still failing. Never commit unverified changes.
- Commit as this repo's configured author. Do not add any Co-authored-by or AI-attribution trailer to commit messages.
- Goal: a healthy graph — frequent, small, reviewable commits, each leaving the tree in a working state.

