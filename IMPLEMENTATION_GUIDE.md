# Agent Context Guard — Implementation Guide

**Version 1.0.1** · Agent Context Guard contributors

This guide provides detailed, step-by-step instructions for installing, configuring, integrating, and maintaining Agent Context Guard in your AI agent projects.

<br>

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Initialization](#initialization)
4. [Protecting Files](#protecting-files)
5. [Reading Protected Files (Library API)](#reading-protected-files-library-api)
6. [Proposing Changes](#proposing-changes)
7. [Reviewing and Approving Proposals](#reviewing-and-approving-proposals)
8. [Running Agents Under the Guard](#running-agents-under-the-guard)
9. [Human Edit Sessions](#human-edit-sessions)
10. [Monitoring and Status](#monitoring-and-status)
11. [Tamper Detection and Recovery](#tamper-detection-and-recovery)
12. [Audit Log](#audit-log)
13. [Key Rotation](#key-rotation)
14. [CI/CD Integration](#cicd-integration)
15. [Framework Adapters](#framework-adapters)
16. [Policy Configuration](#policy-configuration)
17. [Security Model](#security-model)
18. [Troubleshooting](#troubleshooting)

<br>

## Overview

Agent Context Guard protects markdown files that control AI agent behavior. It works by:

1. **Sealing** files with SHA-256 content hashes and HMAC-SHA256 signatures
2. **Verifying** integrity on every read through the `Guard.read()` API
3. **Enforcing policy** agents can read and propose, only humans can approve
4. **Logging** every operation to a hash-chained, tamper-evident audit trail
5. **Recovering** from unauthorized modifications with the `acg recover` workflow

The primary interface is the `Guard` class in Python. The `acg` CLI provides tooling for initialization, monitoring, and human workflows.

<br>

## Installation

### From PyPI

```bash
pip install agent-context-guard
```

### Verify

```bash
acg --version
# Agent Context Guard, version 1.0.1
```

### With Framework Adapters

```bash
pip install agent-context-guard[langchain]    # LangChain adapter
pip install agent-context-guard[crewai]       # CrewAI adapter
pip install agent-context-guard[llamaindex]   # LlamaIndex adapter
pip install agent-context-guard[autogen]      # AutoGen adapter
pip install agent-context-guard[all]          # All adapters
```

### From Source

```bash
git clone https://github.com/kahalewai/agent-context-guard.git
cd agent-context-guard
pip install -e ".[dev]"
```

<br>

## Initialization

Initialize Agent Context Guard in your project root:

```bash
cd /path/to/your/project
acg init
```

This creates the `.agent-context-guard/` directory containing:

```
.agent-context-guard/
├── keys/
│   └── signing.key          # HMAC signing key (chmod 600)
├── proposals/               # Agent change proposals
├── locks/                   # Edit session locks
├── backups/                 # Archived audit logs and file backups
├── inventory.json           # Registry of all protected files
├── inventory.json.hmac      # HMAC sidecar for integrity
├── policy.yaml              # Access control policy
├── policy.yaml.hmac         # HMAC sidecar for integrity
├── audit.log                # Hash-chained audit trail
└── .gitignore               # Excludes keys/, locks/, backups/
```

**Important:** The `keys/` directory is automatically excluded from version control. Never commit signing keys.

<br>

## Protecting Files

Register markdown files for cryptographic protection:

```bash
# Protect specific files
acg protect prompts/persona.md prompts/rules.md

# Protect with glob patterns
acg protect "prompts/*.md"

# Protect recursively
acg protect "**/*.md"
```

Each protected file gets:

- A SHA-256 content hash stored in the inventory
- An HMAC-SHA256 signature using the project signing key
- A version number (starting at 1)
- A timestamp and author record

<br>

## Reading Protected Files (Library API)

The `Guard.read()` method is the primary way agents access protected files:

```python
from agent_context_guard import Guard

guard = Guard("/path/to/project")

# Basic read — verified, policy-checked, audited
content = guard.read("prompts/persona.md", agent_id="my-agent")
```

Every call to `guard.read()` performs the following, in order:

1. Resolves the file path to an absolute path
2. Looks up the active seal record in the inventory
3. Evaluates policy: can this agent read this file?
4. Reads the file into memory (single disk read)
5. Computes SHA-256 hash of the in-memory buffer
6. Compares hash against the seal record
7. Verifies the HMAC signature with the signing key
8. Appends an entry to the hash-chained audit log
9. Returns the verified content

If any step fails, an exception is raised and the read is denied.

### Using Sessions

For agents that read multiple files, sessions reduce boilerplate:

```python
with guard.session(agent_id="my-agent") as s:
    persona = s.read("prompts/persona.md")
    rules = s.read("prompts/rules.md")
    tools = s.read("prompts/tools.md")
```

Sessions pre-bind the `agent_id` so you don't need to pass it on every call.

<br>

## Proposing Changes

Agents can propose changes but never approve them:

```python
proposal_id = guard.propose(
    "prompts/persona.md",
    new_content="# Updated Persona\n\nYou are a helpful, concise assistant.\n",
    agent_id="my-agent",
    justification="Made the persona more concise per user feedback",
)
print(f"Proposal submitted: {proposal_id}")
```

Proposals are stored as unified diffs in `.agent-context-guard/proposals/` for human review.

<br>

## Reviewing and Approving Proposals

### View Pending Proposals

```bash
# List all files with pending proposals
acg diff

# View diffs for a specific file
acg diff prompts/persona.md
```

### Approve a Proposal

```bash
acg approve prompts/persona.md
```

This displays the proposal details, shows the diff, and asks for confirmation. On approval:

- The file is overwritten with the proposed content
- A new seal record is created (version incremented)
- The proposal is marked as approved
- An audit entry is logged

### Reject a Proposal

```bash
acg reject prompts/persona.md
```

<br>

## Running Agents Under the Guard

The `acg run` command verifies all seals before launching your agent:

```bash
acg run -- python my_agent.py
acg run -- node agent.js --verbose
```

This:

1. Verifies all protected files pass integrity checks
2. Sets `ACG_GUARD_ROOT` in the environment
3. Runs your command
4. Logs the subprocess start and exit to the audit trail

If any file fails verification, the command is not run.

<br>

## Human Edit Sessions

Edit protected files through an audited workflow:

```bash
acg edit prompts/persona.md
acg edit prompts/persona.md --editor code  # Use VS Code
```

The edit session:

1. Opens a temporary copy in your editor
2. Shows a diff when you save
3. Asks for confirmation
4. Atomically writes the new content
5. Re-seals with a new version
6. Logs the edit to the audit trail

**Note:** Edit sessions require an interactive terminal (TTY). This prevents agents from calling `acg edit` to bypass the proposal workflow.

<br>

## Monitoring and Status

### Check Protection Status

```bash
acg status
```

The status command runs a **silent integrity verification** before displaying results. If a file has been modified outside the guard, it will show a `TAMPERED` state:

```
┌─────────────────────┬──────────┬─────────┬────────┬──────────────┬───────────┐
│ File                │  State   │ Version │ Author │    Sealed At │ Proposals │
├─────────────────────┼──────────┼─────────┼────────┼──────────────┼───────────┤
│ prompts/persona.md  │ ACTIVE   │    2    │ human  │ 2026-02-18…  │     0     │
│ prompts/rules.md    │ TAMPERED │    1    │ human  │ 2026-02-17…  │     0     │
└─────────────────────┴──────────┴─────────┴────────┴──────────────┴───────────┘
```

<br>

## Tamper Detection and Recovery

When a protected file is modified outside the guard (by an agent, a script, or manual editing without `acg edit`), the `acg recover` command provides a clear workflow:

```bash
acg recover prompts/rules.md
```

This command:

1. Shows a visual summary of what changed
2. Displays a diff between the sealed version and the current content (when available)
3. Presents three options:
   - **[R] Rollback** — restore the file to its last sealed content
   - **[A] Accept** — re-seal the file with the current (changed) content
   - **[C] Cancel** — take no action

All recovery actions are logged to the audit trail.

<br>

## Audit Log

View the audit trail:

```bash
# Show recent entries (default: 50)
acg audit

# Show more entries
acg audit -n 100

# Filter by event type
acg audit -e file_read

# Filter by file
acg audit -f prompts/persona.md

# Filter by actor
acg audit -a my-agent

# View archived audit logs
acg audit --archives
```

### Audit Failsafe

To prevent unbounded log growth, the audit log automatically archives when it exceeds a configurable entry threshold (default: 10,000 entries). Archives are stored in `.agent-context-guard/backups/` with timestamps.

Configure the threshold via environment variable:

```bash
export ACG_AUDIT_MAX_ENTRIES=5000
```

<br>

## Key Rotation

Rotate the signing key periodically or after a suspected compromise:

```bash
acg rotate-keys
```

This generates a new HMAC signing key and re-signs all protected files and guard metadata. The old key is overwritten.

<br>

## CI/CD Integration

Add integrity verification to your CI/CD pipeline:

```bash
acg verify
```

This exits with code 0 if all files pass, code 1 if any fail. Example GitHub Actions step:

```yaml
- name: Verify agent context integrity
  run: |
    pip install agent-context-guard
    acg verify
```

<br>

## Framework Adapters

### LangChain

```python
from agent_context_guard import Guard
from agent_context_guard.adapters.langchain import ProtectedMarkdownLoader

guard = Guard("/path/to/project")
loader = ProtectedMarkdownLoader("prompts/persona.md", guard=guard, agent_id="my-agent")
docs = loader.load()  # Returns verified LangChain Documents
```

### OpenAI Function Calling

```python
from agent_context_guard.adapters.openai_tools import create_openai_tools

tools, handler = create_openai_tools(guard, agent_id="my-openai-agent")
response = client.chat.completions.create(model="gpt-4", messages=messages, tools=tools)
```

### Anthropic Tool Use

```python
from agent_context_guard.adapters.anthropic_tools import create_anthropic_tools

tools, handler = create_anthropic_tools(guard, agent_id="my-claude-agent")
response = client.messages.create(model="claude-sonnet-4-20250514", messages=messages, tools=tools)
```

### CrewAI

```python
from agent_context_guard.adapters.crewai import create_context_tools

read_tool, propose_tool = create_context_tools(guard, agent_id="my-crew-agent")
agent = Agent(role="Analyst", tools=[read_tool, propose_tool])
```

### LlamaIndex

```python
from agent_context_guard.adapters.llamaindex import ProtectedMarkdownReader

reader = ProtectedMarkdownReader(guard=guard, agent_id="my-llama-agent")
documents = reader.load_data(file_path="prompts/persona.md")
```

### AutoGen

```python
from agent_context_guard.adapters.autogen import create_function_map

function_map = create_function_map(guard, agent_id="my-autogen-agent")
user_proxy = autogen.UserProxyAgent("user_proxy", function_map=function_map)
```

### MCP (Model Context Protocol)

```python
from agent_context_guard.adapters.mcp import create_mcp_tools

tools, handler = create_mcp_tools(guard, agent_id="mcp-agent")
```

### OpenClaw

```python
from agent_context_guard.adapters.openclaw import generate_openclaw_skill

generate_openclaw_skill(
    output_dir="~/.openclaw/skills/context-guard",
    guard_root="/path/to/project",
)
```

Install adapters as needed:

```bash
pip install agent-context-guard[langchain]
pip install agent-context-guard[all]
```

<br>

## Policy Configuration

The policy file at `.agent-context-guard/policy.yaml` controls access:

```yaml
read:
  allow: all_agents          # All agents can read

write:
  allow: none                # Direct writes always blocked

propose:
  allow: all_agents          # All agents can propose changes

approve:
  allow: humans              # Only humans can approve
```

### Allow-list Specific Agents

```yaml
read:
  allow:
    - agent-alpha
    - agent-beta

propose:
  allow:
    - agent-alpha
```

### Policy Options

| Value | Meaning |
|-------|---------|
| `all_agents` | Any agent identity is permitted |
| `humans` | Only human actors (via CLI) |
| `none` | Operation is denied for everyone |
| `[list]` | Only the listed agent IDs are permitted |

<br>

## Security Model

Protection is enforced at the API level. Agents access files through `Guard.read()`, which performs cryptographic verification, enforces policy, and produces an audit trail.

The library does **not** attempt to intercept raw filesystem calls. The trust boundary is the same as any tool-use framework: agents can only use the tools you give them. If you provide `Guard.read()` as the file-reading tool and don't expose raw `open()`, the agent has no way to bypass verification.

For environments requiring OS-level enforcement, combine with file permissions, containers, or namespace isolation.

### What Is Protected

- File **content integrity** SHA-256 hash + HMAC signature
- Guard **metadata integrity** HMAC sidecars for inventory and policy
- **Audit trail integrity** hash-chained log entries

### What Is NOT Protected

- File confidentiality (content is not encrypted)
- Network transport (use TLS for remote access)
- OS-level file permissions (use containers or ACLs)

<br>

## Troubleshooting

### "No .agent-context-guard directory found"

Run `acg init` in your project root.

### "Signing key not found"

The `.agent-context-guard/keys/signing.key` file is missing. Re-initialize with `acg init`.

### Status shows ACTIVE but file was changed

This should no longer happen in v1.0.1. The `acg status` command now runs a silent integrity check. If you still see this, run `acg verify` explicitly.

### "Editor not found"

Set the `$EDITOR` environment variable or pass `--editor`:

```bash
export EDITOR=nano
acg edit prompts/persona.md

# Or directly:
acg edit prompts/persona.md --editor code
```

### Audit log growing too large

The audit log auto-archives at 10,000 entries by default. To change the threshold:

```bash
export ACG_AUDIT_MAX_ENTRIES=5000
```

View archives with:

```bash
acg audit --archives
```

<br>

*For additional support, see the project repository at [github.com/kahalewai/agent-context-guard](https://github.com/kahalewai/agent-context-guard).*
