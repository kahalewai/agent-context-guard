# Changelog

All notable changes to Agent Context Guard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] — 2026-02-18

### Added

- **`acg` CLI command** — shortened from `agent-context-guard` for faster usage (`acg init`, `acg status`, etc.)
- **`acg recover` command** — new recovery workflow for tampered files. Shows a diff of original vs. changed content and lets the user choose to rollback (restore sealed version) or accept (re-seal with current content).
- **Silent integrity verification in `acg status`** — status now runs a background verify pass so that tampered files show a `TAMPERED` state immediately, without requiring a separate `acg verify` call.
- **Visual interfaces for `acg diff`, `acg approve`, `acg reject`** — these commands now display Rich-formatted tables listing pending proposals with IDs, agents, timestamps, and justifications before requiring user action.
- **Audit log archival failsafe** — the audit log automatically archives to `backups/` when it exceeds a configurable threshold (default 10,000 entries). Prevents unbounded log growth. Threshold configurable via `ACG_AUDIT_MAX_ENTRIES` environment variable.
- **`acg audit --archives`** — new flag to list archived audit log files.
- **`TAMPERED` file state** — new state constant displayed in status when a protected file fails integrity verification.
- **Backups directory** — `.agent-context-guard/backups/` for archived audit logs and file backups.
- **Contextual next steps** — all commands now show context-aware "What to do next" suggestions based on current state (e.g., suggests `acg recover` when tampering is detected).

### Changed

- **CLI base command** renamed from `agent-context-guard` to `acg`.
- **Header branding** updated — now shows `🛡️ Agent Context Guard v1.0.1` with dark green and dark orange color scheme.
- **`acg diff`** no longer requires a file argument — when run without arguments, lists all files with pending proposals so the user can select which to review.
- **`acg approve` / `acg reject`** now display a table of pending proposals before acting, showing what is being approved or rejected.
- **`acg verify`** next steps now suggest `acg recover` when failures are found.
- **Version string** updated to `1.0.1` across all file headers, CLI output, and package metadata.
- **Project name** is "Agent Context Guard" (display) / `agent-context-guard` (PyPI) / `agent_context_guard` (Python import).

### Fixed

- **`acg status` not reflecting file modifications** — previously, status showed `ACTIVE` even after a file was externally modified. Now status runs a silent verify pass and shows `TAMPERED` for any file that fails integrity verification.
- **No recovery path after tampering detected** — previously, after `acg verify` showed a failure, there was no clear workflow to resolve it. The new `acg recover` command provides rollback and accept options.

## [1.0.0] — 2026-02-10

### Added

- Initial release with library-first architecture.
- `Guard` class as single entry point for all operations (`read`, `propose`, `status`, `verify`).
- `GuardSession` for scoped agent identity binding.
- SHA-256 + HMAC-SHA256 cryptographic sealing.
- Deterministic policy engine (read, write, propose, approve).
- Hash-chained append-only audit log (JSON Lines).
- Agent proposal workflow with human-only approval.
- Human edit sessions with diff display and re-sealing.
- Self-protection: HMAC verification of guard metadata files.
- Framework adapters: LangChain, CrewAI, OpenAI, Anthropic, AutoGen, LlamaIndex, MCP, OpenClaw.
- Full CLI: `init`, `protect`, `run`, `edit`, `status`, `diff`, `approve`, `reject`, `audit`, `verify`, `rotate-keys`.
- 51 automated tests covering core modules, Guard API, and adapters.
