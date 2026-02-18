<div align="center">
  
<img width="456" height="400" alt="acg" src="https://github.com/user-attachments/assets/22dcee6a-7ae6-45c0-9134-72ac49251d84" />

[![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-orange.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.1-green.svg)](https://github.com/kahalewai/agent-context-guard)

</div>

<br>

## Intro

Agent Context Guard is a runtime protection layer for AI agent markdown context files. Modern AI agents encode critical behavioral controls in plaintext markdown: persona definitions, tool instructions, rules, and skills. These files are implicitly trusted, mutable at runtime, and typically unprotected. Agent Context Guard seals these files with cryptographic signatures, detects tampering at runtime, and ensures that only humans can approve changes.

Agent Context Guard is intended to:
* Seal markdown files with cryptographic hashes and HMAC signatures
* Detect tampering, any modification to a protected file is caught immediately
* Provide a library-based guard API, agents call `guard.read()` for verified access
* Provide a proposal workflow, agents can propose changes but never approve them
* Preserve human ownership, edit protected files anytime through explicit sessions
* Recover from tampering, view diffs and choose to rollback or accept changes
* Log everything, append-only audit trail with automatic archival failsafe
* Integrate into CI/CD pipelines for continuous integrity verification
* Work with any agent framework via adapters or direct API

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
| Protection scope      | Markdown files (.md, .markdown, .mdown, .mkd)     |
| Signing algorithm     | SHA-256 hash + HMAC-SHA256 signature              |
| Policy enforcement    | Deterministic, non-LLM-based                      |
| Agent integration     | Framework agnostic (LangChain, CrewAI, OpenAI, Anthropic, AutoGen, LlamaIndex, MCP, OpenClaw) |
| Runtime overhead      | Minimal, file-level verification only             |
| Adoption model        | Library API with CLI tooling                       |

<br>

## Quick Start

### Installation

```bash
# Install from PyPI
pip install agent-context-guard

# Verify installation
acg --version
```

### Basic Usage

```bash
# 1. Initialize in your project directory
acg init

# 2. Protect your agent's context files
acg protect prompts/*.md

# 3. Run your agent under the guard
acg run -- python my_agent.py

# 4. Verify integrity (CI/CD)
acg verify
```

### Python API

```python
from agent_context_guard import Guard

# Initialize with your project root
guard = Guard("/path/to/project")

# Read a protected file (with policy enforcement + audit)
content = guard.read("prompts/persona.md", agent_id="my-agent")

# Propose an update (requires human approval)
guard.propose(
    "prompts/persona.md",
    new_content="# Updated Persona\n...",
    agent_id="my-agent",
    justification="Updated greeting style",
)

# Check protection status
status = guard.status("prompts/persona.md")

# Scoped sessions for cleaner agent code
with guard.session(agent_id="my-agent") as s:
    persona = s.read("prompts/persona.md")
    rules = s.read("prompts/rules.md")
```

For complete setup instructions, see the [Implementation Guide](./IMPLEMENTATION_GUIDE.md).

<br>

## Package Structure

```
src/agent_context_guard/
├── __init__.py              # Public API exports
├── guard.py                 # Central API (Guard, GuardSession)
├── core/
│   ├── audit.py             # Append-only JSON Lines audit logger with archival
│   ├── constants.py         # Paths, defaults, file extensions
│   ├── exceptions.py        # Full exception hierarchy
│   ├── inventory.py         # Atomic-write seal record registry
│   ├── policy.py            # Deterministic policy engine
│   ├── proposals.py         # Agent proposal workflow
│   ├── seal.py              # SHA-256 hashing + HMAC-SHA256 signing
│   └── selfprotect.py       # Guard metadata self-protection
├── cli/
│   ├── helpers.py           # Rich terminal output helpers
│   └── main.py              # All CLI commands (Click)
└── adapters/
    ├── anthropic_tools.py   # Anthropic Claude tool-use adapter
    ├── autogen.py           # AutoGen / AG2 adapter
    ├── crewai.py            # CrewAI tool adapter
    ├── langchain.py         # LangChain document loader adapter
    ├── llamaindex.py        # LlamaIndex reader adapter
    ├── mcp.py               # Model Context Protocol adapter
    ├── openclaw.py          # OpenClaw skill adapter
    └── openai_tools.py      # OpenAI function-calling adapter
```

<br>

## CLI Commands

Agent Context Guard provides a complete CLI via the `acg` command:

| Command | Description |
|---------|-------------|
| `acg init` | Initialize guard in a directory |
| `acg protect <files>` | Register markdown files for protection |
| `acg run -- <cmd>` | Run a command under the runtime guard |
| `acg edit <file>` | Open a human edit session for a protected file |
| `acg status` | Show protection status (with silent integrity check) |
| `acg diff [file]` | Show pending proposal diffs |
| `acg approve <file>` | Approve a pending proposal and apply changes |
| `acg reject <file>` | Reject a pending proposal |
| `acg recover <file>` | Recover from file tampering (rollback or accept) |
| `acg audit` | Display the audit log |
| `acg verify` | CI/CD verification of sealed files and metadata |
| `acg rotate-keys` | Rotate the signing key and re-sign all files |

Use `acg <command> --help` for detailed options on any command.

<br>

## Works with Your Existing Agent Framework

Agent Context Guard was designed to work with any AI agent framework:

* No assumptions about agent framework or prompt format
* Python API available for direct integration (`guard.read()`)
* Pre-flight verification via `acg run -- <command>`
* Adapters included for LangChain, CrewAI, OpenAI, Anthropic, AutoGen, LlamaIndex, MCP, and OpenClaw
* Works with single-agent and multi-agent systems
* All operations are logged to an append-only audit trail
* Policy enforcement is deterministic, no LLM-based decisions

<br>

## Key Design Principles

* **Library-first architecture** agents call `guard.read()` for verified access
* **Framework agnostic** no assumptions about agent framework or prompt format
* **Deterministic control** all decisions are non-LLM-based
* **Agent autonomy without authority** agents propose, humans approve
* **Tamper recovery** detect changes and recover with `acg recover`
* **Audit failsafe** automatic log archival prevents unbounded growth

<br>

## Out of Scope

Agent Context Guard does not:
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
<br>
