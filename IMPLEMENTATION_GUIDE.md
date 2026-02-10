# Implementation Guide for Agent Context Guard v1.0.0

Complete reference for installing, configuring, integrating, and maintaining agent-context-guard.

<br>

## 1. Installation

### From PyPI

```bash
pip install agent-context-guard
```

### From Source

```bash
git clone https://github.com/kahalewai/agent-context-guard.git
cd agent-context-guard
pip install -e ".[dev]"
```

### Requirements

- Python 3.10+
- Dependencies (installed automatically): `click`, `cryptography`, `pyyaml`, `rich`
- No external services, databases, or daemons

### Verify

```bash
agent-context-guard --version
agent-context-guard --help
```

<br>

## 2. Project Structure

```
src/agent_context_guard/
├── __init__.py            # Public API exports
├── api.py                 # Layer 1 Python wrapper (read_md, propose_update, get_status)
├── core/
│   ├── audit.py           # Append-only JSON Lines audit logger
│   ├── constants.py       # Paths, defaults, file extensions
│   ├── edit.py            # Human edit session lifecycle
│   ├── exceptions.py      # Full exception hierarchy
│   ├── inventory.py       # Atomic-write seal record registry
│   ├── policy.py          # Deterministic policy engine
│   ├── proposals.py       # Agent proposal workflow
│   ├── runtime.py         # Runtime guard (ephemeral keys, subprocess, locking)
│   └── seal.py            # SHA-256 hashing + HMAC-SHA256 signing
├── cli/
│   ├── helpers.py         # Rich terminal output helpers
│   └── main.py            # All CLI commands (Click)
├── adapters/
│   └── base.py            # BaseAdapter + LangChainAdapter
└── interceptors/
    └── python_hook.py     # Monkey-patch open()/Path.read_text()
```

### Guard Directory (created by `init`)

```
.agent-context-guard/
├── .gitignore          # Excludes keys/ and locks/ from version control
├── inventory.json      # Sealed file registry
├── audit.log           # Append-only event log
├── policy.yaml         # Access control policy
├── keys/signing.key    # HMAC signing key (32 bytes, mode 0600)
├── proposals/          # Agent change proposals (JSON + diffs)
└── locks/              # Runtime file locks
```

<br>

## 3. Getting Started

```bash
# 1. Initialize
cd your-agent-project
agent-context-guard init

# 2. Protect files
agent-context-guard protect prompts/persona.md prompts/rules.md
agent-context-guard protect 'config/**/*.md'

# 3. Run agent under guard
agent-context-guard run -- python my_agent.py

# 4. Check status
agent-context-guard status

# 5. CI/CD verification
agent-context-guard verify
```

<br>

## 4. CLI Reference

### `init`

```bash
agent-context-guard init [-p PATH]
```

Creates `.agent-context-guard/`, generates signing key, sets up default policy and empty inventory. Idempotent — warns if already initialized.

### `protect`

```bash
agent-context-guard protect FILES... [-a AUTHOR]
```

Accepts file paths or glob patterns. Each markdown file (`.md`, `.markdown`, `.mdown`, `.mkd`, `.mkdn`) is sealed with SHA-256 + HMAC-SHA256 and added to the inventory with state `ACTIVE`. Skips files already protected.

### `run`

```bash
agent-context-guard run -- COMMAND [ARGS...]
```

Workflow:
1. Generate ephemeral Fernet key (exists only in memory)
2. Verify all sealed files against inventory
3. Run command as subprocess (key passed via `ACG_RUNTIME_KEY` env var)
4. On exit: zero out key, release locks, flush audit

Exits with code 2 if seal verification fails (command is never started).

### `edit`

```bash
agent-context-guard edit FILE [-a AUTHOR] [-e EDITOR]
```

Human edit session workflow:
1. Lock the file (agents cannot read while locked)
2. Create temporary working copy
3. Open in `$EDITOR` (or `--editor`)
4. On save: write atomically, re-seal as new version
5. Unlock file

If no changes are made, the file is not re-sealed.

### `status`

```bash
agent-context-guard status [FILES...]
```

Displays a Rich table: file path, state, version, author, seal timestamp, pending proposal count. With no arguments, shows all protected files.

### `diff`

```bash
agent-context-guard diff FILE
```

Shows unified diffs of all pending proposals for a file with agent ID, timestamp, and justification.

### `approve`

```bash
agent-context-guard approve FILE [-p PROPOSAL_ID] [-a AUTHOR] [-y]
```

Applies a pending proposal:
1. Shows the diff and proposal metadata
2. Prompts for confirmation (skip with `-y`)
3. Writes proposed content to disk
4. Re-seals as new version
5. Updates proposal status to `approved`

Without `-p`, approves the latest pending proposal.

### `reject`

```bash
agent-context-guard reject FILE [-p PROPOSAL_ID]
```

Marks a proposal as `rejected`. Does not modify the file.

### `audit`

```bash
agent-context-guard audit [-e EVENT] [-f FILE] [-a ACTOR] [-n LIMIT]
```

Displays audit entries in a formatted table. Filters: event type, file path, actor identity, max entries (default 50).

### `verify`

```bash
agent-context-guard verify
```

Checks every active sealed file:
- Recomputes SHA-256 hash and compares to stored hash
- Verifies HMAC signature against stored key

Exit code 0 = all pass, exit code 1 = any failure. Designed for CI/CD gates.

### `rotate-keys`

```bash
agent-context-guard rotate-keys [-a AUTHOR]
```

Generates a new 32-byte HMAC key, re-signs all active seal records with the new key, and logs the rotation event. The old key is overwritten on disk.

<br>

## 5. Python API Reference

### `read_md(file_path, *, agent_id, root)`

Read a protected file with policy enforcement and audit logging.

```python
from agent_context_guard import read_md

content = read_md("prompts/persona.md", agent_id="my-agent")
```

- If a runtime guard is active, uses full enforcement (policy + integrity + audit)
- Otherwise, performs offline seal verification
- **Raises:** `PolicyDeniedError`, `SealIntegrityError`, `SealNotFoundError`

### `propose_update(file_path, new_content, *, agent_id, justification, root, metadata)`

Submit a change proposal for human review. Returns the proposal ID.

```python
from agent_context_guard import propose_update

pid = propose_update(
    "prompts/persona.md",
    "# New Persona\n\nUpdated content.\n",
    agent_id="my-agent",
    justification="Improved tone"
)
```

- **Raises:** `PolicyDeniedError` if the agent is not allowed to propose

### `get_status(file_path, *, root)`

Get protection status of a file. Returns a dict:

```python
from agent_context_guard import get_status

status = get_status("prompts/persona.md")
# {
#     "protected": True,
#     "state": "ACTIVE",
#     "version": 3,
#     "pending_proposals": 1,
#     "author": "human",
#     "timestamp": 1700000000.0
# }
```

<br>

## 6. Configuration

### Policy File

Located at `.agent-context-guard/policy.yaml`. Default:

```yaml
read:
  allow: all_agents

write:
  allow: none

propose:
  allow: all_agents

approve:
  allow: humans
```

#### Policy Options for `allow`

| Value | Meaning |
|-------|---------|
| `all_agents` | Any agent identity is permitted |
| `humans` | Only human actors (determined by `actor_type`) |
| `none` | No one — operation is universally denied |
| `["agent-1", "agent-2"]` | Allow-list of specific agent IDs |

#### Important Requirements

- `write.allow` should always be `none` — this is the core safety requirement. Direct writes to protected files are blocked regardless of this setting during runtime.
- `approve.allow` only accepts `humans` — agents can never approve proposals.

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `ACG_GUARD_ROOT` | Override guard root directory discovery |
| `ACG_RUNTIME_KEY` | Ephemeral Fernet key (set automatically by `run`) |
| `EDITOR` | Editor for `edit` command (default: `vi`) |

<br>

## 7. Security Model

### Threat Model (In Scope)

- Unauthorized modification of agent markdown files
- Agent self-mutation via tool access
- Prompt injection leading to file tampering
- Confused deputy file writes
- Silent behavioral drift without code changes
- Unauthorized reads during agent execution
- Accidental edits by insiders

### Threat Model (Out of Scope)

- Full host compromise / root access
- Kernel-level adversaries
- Model exfiltration via side channels
- Malicious human operators with full approval authority

### Cryptographic Primitives

| Purpose | Algorithm | Details |
|---------|-----------|---------|
| Content hashing | SHA-256 | 64-char hex digest |
| Seal signatures | HMAC-SHA256 | 32-byte key, constant-time comparison |
| Runtime encryption | Fernet (AES-128-CBC + HMAC) | Ephemeral key, memory-only |

### File Lifecycle States

```
UNSEALED → SEALED → ACTIVE → DEPRECATED → REVOKED
```

| State | Readable | Proposable | Description |
|-------|----------|------------|-------------|
| `UNSEALED` | No | No | Not yet protected |
| `SEALED` | Yes | Yes | Hash + signature registered |
| `ACTIVE` | Yes | Yes | Currently approved version |
| `DEPRECATED` | No | No | Superseded by newer version |
| `REVOKED` | No | No | Blocked from all use |

<br>

## 8. Integration Patterns

### Pattern 1: CLI Wrapper (Zero Code Changes)

The simplest integration — wrap your existing command:

```bash
# Before
python my_agent.py

# After
agent-context-guard run -- python my_agent.py
```

No code changes. The guard verifies files at startup and monitors the process.

### Pattern 2: Python API (Explicit Calls)

Use `read_md` and `propose_update` in your agent code:

```python
from agent_context_guard import read_md, propose_update

# Agent reads its persona
persona = read_md("prompts/persona.md", agent_id="my-agent")

# Agent proposes changes (human must approve)
propose_update(
    "prompts/persona.md",
    updated_persona,
    agent_id="my-agent",
    justification="User requested tone change"
)
```

### Pattern 3: Python Interceptor (Transparent)

Monkey-patch `open()` and `Path.read_text()` so all file reads are intercepted:

```python
from agent_context_guard.interceptors.python_hook import install, uninstall
from agent_context_guard.core.runtime import RuntimeGuard
from pathlib import Path

guard = RuntimeGuard(Path("."))
guard.start()
install()

# All open() and Path.read_text() calls on protected .md files
# are now routed through the guard automatically

# ... run your agent ...

uninstall()
guard.stop()
```

### Pattern 4: Framework Adapter

```python
from agent_context_guard.adapters.base import LangChainAdapter

adapter = LangChainAdapter(agent_id="langchain-agent")

# Returns {"page_content": "...", "metadata": {...}}
doc = adapter.load_document("prompts/system.md")

# Submit a proposal
adapter.propose("prompts/system.md", new_content, justification="Refine instructions")
```

<br>

## 9. Proposal Workflow

Agents can propose changes but **never** approve or activate them.

### Agent Submits a Proposal

```python
from agent_context_guard import propose_update

pid = propose_update(
    "prompts/persona.md",
    "# Updated\n\nNew content.\n",
    agent_id="agent-x",
    justification="Better phrasing"
)
print(f"Proposal submitted: {pid}")
```

### Human Reviews

```bash
# See what changed
agent-context-guard diff prompts/persona.md

# Approve
agent-context-guard approve prompts/persona.md

# Or reject
agent-context-guard reject prompts/persona.md
```

### Proposal Storage

Proposals are stored as JSON in `.agent-context-guard/proposals/<safe-filename>/`:

```json
{
  "proposal_id": "1700000000_a1b2c3d4",
  "file_path": "/abs/path/prompts/persona.md",
  "agent_id": "agent-x",
  "timestamp": 1700000000.0,
  "diff": "--- a/persona.md\n+++ b/persona.md\n...",
  "justification": "Better phrasing",
  "status": "pending",
  "new_content": "# Updated\n\nNew content.\n"
}
```

<br>

## 10. Human Edit Sessions

Humans can edit protected files even while the agent is running.

```bash
agent-context-guard edit prompts/persona.md
```

**Guarantees:**
- The agent cannot read or write the file during editing (file is locked)
- Partial writes are impossible (atomic write via temp file + rename)
- All edits are audited with diff metadata
- The file is automatically re-sealed as a new version

**Editor selection** (in priority order):
1. `--editor` flag
2. `$EDITOR` environment variable
3. `vi` (fallback)

<br>

## 11. CI/CD Integration

### GitHub Actions Example

```yaml
name: Verify Agent Context Integrity
on: [push, pull_request]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install agent-context-guard
      - run: agent-context-guard verify
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
agent-context-guard verify
```

### What `verify` Checks

1. Every active sealed file exists on disk
2. SHA-256 hash matches the stored hash (detects any content change)
3. HMAC signature is valid (detects inventory tampering)

<br>

## 12. Key Management

### Signing Key

- Location: `.agent-context-guard/keys/signing.key`
- Size: 32 bytes (256 bits)
- Permissions: `0600` (owner read/write only)
- **Must be excluded from version control** (handled by `.gitignore`)

### Key Rotation

```bash
agent-context-guard rotate-keys
```

This command:
1. Generates a new 32-byte random key
2. Re-signs every active seal record with the new key
3. Overwrites the old key on disk
4. Logs the rotation in the audit trail

**When to rotate:**
- Team member departure
- Suspected key compromise
- Periodic rotation policy (e.g., quarterly)

### Key Backup

The signing key is the root of trust. If lost, you must re-protect all files:

```bash
# If key is lost, re-initialize
rm -rf .agent-context-guard
agent-context-guard init
agent-context-guard protect 'prompts/*.md'
```

<br>

## 13. Audit Log

### Format

The audit log at `.agent-context-guard/audit.log` is append-only JSON Lines (one JSON object per line):

```json
{"timestamp":1700000000.0,"event":"file_read","actor":"agent-x","file_path":"/path/persona.md","operation":"read","result":"allowed","detail":"","metadata":{}}
{"timestamp":1700000001.0,"event":"write_blocked","actor":"agent-x","file_path":"/path/persona.md","operation":"write","result":"denied","detail":"Direct write blocked by runtime guard","metadata":{}}
```

### Event Types

| Event | Description |
|-------|-------------|
| `file_read` | File read (allowed or denied) |
| `write_blocked` | Write attempt blocked |
| `proposal_submitted` | Agent submitted a proposal |
| `proposal_approved` | Human approved a proposal |
| `proposal_rejected` | Human rejected a proposal |
| `edit_started` | Human edit session began |
| `edit_saved` | Human edit session saved changes |
| `edit_no_changes` | Human edit session closed without changes |
| `file_sealed` | File was sealed (new version) |
| `policy_denied` | Policy engine denied an operation |
| `guard_started` | Runtime guard activated |
| `guard_stopped` | Runtime guard deactivated |
| `subprocess_started` | Guarded subprocess launched |
| `subprocess_exited` | Guarded subprocess exited |
| `key_rotation` | Signing key was rotated |
| `verify` | Seal verification (pass or fail) |
| `initialized` | Guard directory was initialized |

### Querying

```bash
# All entries
agent-context-guard audit

# Filter by event
agent-context-guard audit -e write_blocked

# Filter by file
agent-context-guard audit -f prompts/persona.md

# Filter by actor
agent-context-guard audit -a agent-x

# Limit results
agent-context-guard audit -n 20
```

<br>

## 14. Python Interceptor

The interceptor monkey-patches `builtins.open()` and `pathlib.Path.read_text()` so that any code reading protected markdown files is transparently routed through the guard.

```python
from agent_context_guard.interceptors.python_hook import install, uninstall, is_installed

install()       # Activate interception
is_installed()  # True
uninstall()     # Restore originals
```

**What it does:**
- Read calls on protected `.md` files → routed through `RuntimeGuard.read_file()` (policy + integrity + audit)
- Write/append calls on protected `.md` files → blocked with `PolicyDeniedError`
- All other file operations → passed through to original functions

**Limitations:**
- Only intercepts Python-level file access (not C extensions or subprocess I/O)
- Requires an active `RuntimeGuard` to enforce — without one, passes through silently
- Not a security boundary against determined adversaries in the same process

<br>

## 15. Framework Adapters

### BaseAdapter

All adapters inherit from `BaseAdapter` which provides `load()`, `propose()`, and `status()` methods that delegate to the Layer 1 Python API.

```python
from agent_context_guard.adapters.base import BaseAdapter

adapter = BaseAdapter(root="/path/to/project", agent_id="my-agent")
content = adapter.load("prompts/system.md")
```

### LangChainAdapter

Returns data compatible with LangChain's Document format:

```python
from agent_context_guard.adapters.base import LangChainAdapter

adapter = LangChainAdapter(agent_id="lc-agent")
doc = adapter.load_document("prompts/system.md")
# doc = {
#     "page_content": "...",
#     "metadata": {"source": "...", "protected": True, "version": 2, "state": "ACTIVE"}
# }
```

### Writing Custom Adapters

```python
from agent_context_guard.adapters.base import BaseAdapter

class MyFrameworkAdapter(BaseAdapter):
    def load_prompt(self, path: str) -> MyFrameworkPrompt:
        content = self.load(path)
        return MyFrameworkPrompt(text=content, metadata=self.status(path))
```

<br>

## 16. Troubleshooting

### "No .agent-context-guard directory found"

Run `agent-context-guard init` in your project root, or set `ACG_GUARD_ROOT` to point to the correct directory.

### "Seal verification failed" on `run`

A protected file has been modified outside the guard. Options:
1. Revert the file to its original content
2. Re-protect the file: `agent-context-guard protect <file>` (creates a new sealed version)
3. Check `git diff` for unexpected changes

### "Signing key not found"

The key at `.agent-context-guard/keys/signing.key` is missing. If you've lost it, you must re-initialize:

```bash
rm -rf .agent-context-guard
agent-context-guard init
agent-context-guard protect 'prompts/*.md'
```

### Editor not found during `edit`

Set your editor: `export EDITOR=nano` or pass `--editor nano`.

### "File is locked for human editing"

A previous edit session may not have closed cleanly. Remove stale locks:

```bash
rm .agent-context-guard/locks/*
```

### Permission denied on signing key

The key requires `0600` permissions. Fix with:

```bash
chmod 600 .agent-context-guard/keys/signing.key
```

<br>

## 17. Development

### Setup

```bash
git clone https://github.com/kahalewai/agent-context-guard.git
cd agent-context-guard
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest tests/ -v
```

The test suite includes 40 tests covering:
- Sealing (hashing, signing, verification, tamper detection, key rotation)
- Inventory (CRUD, state transitions, versioning, revocation)
- Policy engine (all operations, all actor types, allow-lists)
- Audit logging (write, filter, count)
- Proposals (create, approve, reject, idempotency, listing)
- Runtime guard (start/stop, read, write blocking, locking, tamper detection, encryption)
- Public API (read_md, propose_update, get_status)

### Lint

```bash
ruff check src/ tests/
```

<br>

## 18. Architecture Deep Dive

### Core Requirement

> The agent never gains authority. The human never loses ownership. The guard never acts implicitly.

This requirement holds across all operations. The policy engine enforces it deterministically without any LLM involvement.

### Layered Architecture

```
Layer 3: Framework Adapters (LangChain, custom)
    ↓ calls
Layer 1: Python API (read_md, propose_update, get_status)
    ↓ calls
Layer 2: Interceptors (optional — monkey-patch open/read_text)
    ↓ calls
Core: Policy Engine + Runtime + Seal + Inventory + Audit + Proposals
```

Adapters call Layer 1 only. They never implement security logic. All enforcement happens in the Core.

### Seal Model

Every protected file has a `SealRecord`:

```python
@dataclass(frozen=True)
class SealRecord:
    file_path: str       # Absolute path
    content_hash: str    # SHA-256 hex digest
    signature: str       # HMAC-SHA256 hex digest
    version: int         # Monotonically increasing
    timestamp: float     # Unix timestamp
    author: str          # Who sealed it
    state: str           # UNSEALED/SEALED/ACTIVE/DEPRECATED/REVOKED
    metadata: dict       # Extensible
```

No semantic interpretation of file contents is performed. The guard treats files as opaque byte sequences.

### Inventory

The inventory is a JSON file with atomic writes (write to temp file, then rename). This prevents corruption from crashes or concurrent access. Schema:

```json
{
  "version": 1,
  "files": {
    "/abs/path/file.md": [
      {"file_path": "...", "content_hash": "...", "signature": "...", ...},
      {"file_path": "...", "content_hash": "...", "signature": "...", ...}
    ]
  }
}
```

Adding a new version automatically deprecates all previous active versions of the same file.

### Runtime Key Lifecycle

1. `run` generates a Fernet key via `Fernet.generate_key()`
2. Key exists only in Python process memory
3. Key is passed to subprocess via `ACG_RUNTIME_KEY` environment variable
4. On exit, key bytes are overwritten with zeros before dereferencing
5. No key material is ever written to disk

### Policy Engine

Decisions are pure functions of: `(actor, actor_type, operation, file_state, policy_rules)`. No network calls, no LLM calls, no randomness. The engine is fully deterministic and testable.

### Error Handling

The exception hierarchy:

```
AgentContextGuardError (base)
├── SealError
│   ├── SealIntegrityError       # File contents changed
│   └── SealNotFoundError        # No seal record for file
├── PolicyDeniedError            # Policy rejected the operation
├── RuntimeNotActiveError        # Operation needs active guard
├── RuntimeAlreadyActiveError    # Guard already running
├── FileLockedError              # File locked for editing
├── ProposalError                # Proposal workflow error
├── InventoryError
│   └── InventoryCorruptedError  # JSON parse failure
├── GuardNotInitializedError     # No .agent-context-guard/
├── EditSessionError             # Edit session failure
└── KeyManagementError           # Key gen/load/rotate failure
```

All exceptions inherit from `AgentContextGuardError` so callers can catch broadly or narrowly.

<br>

## License

Apache License 2.0 — see [LICENSE](LICENSE).
