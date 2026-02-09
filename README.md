<div align="center">
  
![acg](https://github.com/user-attachments/assets/c5073b96-4dcf-47ec-942c-5b25bceb3b9a)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)

Version 1.0.0

</div>

<br>

## Intro

Agent Context Guard is a runtime protection layer for AI agent markdown context files. Modern AI agents encode critical behavioral controls in plaintext markdown, persona definitions, tool instructions, rules, and skills. These files are implicitly trusted, mutable at runtime, and typically unprotected. Agent Context Guard seals these files with cryptographic signatures, detects tampering at runtime, and ensures that only humans can approve changes.

Agent Context Guard is intended to:
* Seal markdown files with cryptographic hashes and HMAC signatures
* Detect tampering; any modification to a protected file is caught immediately
* Block unauthorized writes during agent runtime
* Provide a proposal workflow; agents can propose changes but never approve them
* Preserve human ownership; edit protected files anytime through explicit sessions
* Log everything; append-only audit trail of all access, denials, and changes
* Integrate into CI/CD pipelines for continuous integrity verification
* Work with any agent framework without code changes

<br>

## Core Requirement

Agent Context Guard enforces a single core requirement across all operations:

<br>

> The agent never gains authority. The human never loses ownership. The guard never acts implicitly.

<br>

This means that:

* AI agents can read protected files but cannot modify them
* Humans remain the sole authority for approving changes
* Agents can propose changes with justifications
* All proposals require explicit human review and approval
* Every file operation is cryptographically sealed and logged
* Runtime protection is deterministic, no LLM-based decisions
* Audit records capture every access, denial, and modification

<br>

**Key Characteristics**

| Aspect                | Scope                                             |
| --------------------- | ------------------------------------------------- |
| Protection scope      | Markdown files (.md, .mdx, .markdown)             |
| Signing algorithm     | SHA-256 hash + HMAC-SHA256 signature              |
| Policy enforcement    | Deterministic, non-LLM-based                      |
| Agent integration     | Framework agnostic (LangChain, custom, etc.)      |
| Runtime overhead      | Minimal — file-level monitoring only               |
| Adoption model        | Zero-code-change via CLI wrapper                   |

<br>

## Quick Start

### Installation

```bash
# Install from PyPI
pip install agent-context-guard

# Verify installation
agent-context-guard --version
```

### Basic Usage

```bash
# 1. Initialize in your project directory
agent-context-guard init

# 2. Protect your agent's context files
agent-context-guard protect prompts/*.md

# 3. Run your agent under the guard
agent-context-guard run -- python my_agent.py

# 4. Verify integrity (CI/CD)
agent-context-guard verify
```

### Python API

```python
from agent_context_guard import read_md, propose_update, get_status

# Read a protected file (with policy enforcement + audit)
content = read_md("prompts/persona.md", agent_id="my-agent")

# Propose an update (requires human approval)
propose_update("prompts/persona.md", new_content, agent_id="my-agent",
               justification="Updated greeting style")

# Check protection status
status = get_status("prompts/persona.md")
```

For complete setup instructions, see the [Implementation Guide](./IMPLEMENTATION_GUIDE.md).

<br>

## Package Structure

```
src/agent_context_guard/
├── __init__.py              # Public API exports
├── api.py                   # Python wrapper (read_md, propose_update, get_status)
├── core/
│   ├── audit.py             # Append-only JSON Lines audit logger
│   ├── constants.py         # Paths, defaults, file extensions
│   ├── edit.py              # Human edit session lifecycle
│   ├── exceptions.py        # Full exception hierarchy
│   ├── inventory.py         # Atomic-write seal record registry
│   ├── policy.py            # Deterministic policy engine
│   ├── proposals.py         # Agent proposal workflow
│   ├── runtime.py           # Runtime guard (ephemeral keys, subprocess, locking)
│   ├── seal.py              # SHA-256 hashing + HMAC-SHA256 signing
│   └── selfprotect.py       # Guard metadata self-protection
├── cli/
│   ├── helpers.py           # Rich terminal output helpers
│   └── main.py              # All CLI commands (Click)
├── adapters/
│   └── base.py              # BaseAdapter + LangChain adapter
└── interceptors/
    └── python_hook.py       # Monkey-patch open()/Path.read_text()
```

<br>

## CLI Commands

agent-context-guard provides a complete CLI for managing protected files:

| Command | Description |
|---------|-------------|
| `init` | Initialize guard in a directory |
| `protect` | Register markdown files for protection |
| `run` | Run a command under the runtime guard |
| `edit` | Open a human edit session for a protected file |
| `status` | Show protection status of files |
| `diff` | Show pending proposal diffs |
| `approve` | Approve a pending proposal and apply changes |
| `reject` | Reject a pending proposal |
| `audit` | Display the audit log |
| `verify` | CI/CD verification of sealed files and metadata |
| `rotate-keys` | Rotate the signing key and re-sign all files |

Use `agent-context-guard <command> --help` for detailed options on any command.

<br>

## Works with Your Existing Agent Framework

agent-context-guard was designed to work with any AI agent framework:

* No assumptions about agent framework or prompt format
* Zero-code-change adoption via the CLI wrapper (`agent-context-guard run`)
* Python API available for deeper integration (no CLI wrapper)
* LangChain adapter included, extensible to other frameworks
* Works with single-agent and multi-agent systems
* Protection activates only under `agent-context-guard run`
* No interference with normal development
* All operations are logged to an append-only audit trail
* Policy enforcement is deterministic; no LLM-based decisions

<br>

## Key Design Principles

* **Runtime-only enforcement** - protection activates only under `run`
* **Framework agnostic** - no assumptions about agent framework or prompt format
* **Deterministic control** - all decisions are non-LLM-based
* **Zero-code-change adoption** - use the CLI wrapper, no code changes needed
* **Agent autonomy without authority** - agents propose, humans approve

<br>

## Out of Scope

agent-context-guard does not:
* Provide object-level authorization within files
* Act as a general-purpose file integrity monitor
* Replace authentication or identity management
* Perform prompt injection detection or content filtering
* Support encrypted file storage (sealing is for integrity, not confidentiality)

<br>

## Requirements

* Python 3.10+
* Dependencies (installed automatically): `click`, `cryptography`, `pyyaml`, `rich`
* No external services, databases, or daemons

<br>

## License

Apache License 2.0

<br>

## Documentation

See the [Implementation Guide](./IMPLEMENTATION_GUIDE.md) for detailed installation, configuration, integration patterns, and maintenance procedures.

<br>
<br>
