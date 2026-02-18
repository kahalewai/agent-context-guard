"""
Agent Context Guard — core/constants.py
Version: 1.0.1
Author: Kahalewai

Constants and configuration defaults for Agent Context Guard. All path
helpers, default values, file extensions, and state definitions live
here so that every other module imports from a single source of truth.
"""

from __future__ import annotations

import os
from pathlib import Path

# ── Directory Layout ──────────────────────────────────────────────────────────
GUARD_DIR_NAME = ".agent-context-guard"
INVENTORY_FILE = "inventory.json"
AUDIT_LOG_FILE = "audit.log"
KEYS_DIR = "keys"
PROPOSALS_DIR = "proposals"
POLICY_FILE = "policy.yaml"
LOCK_DIR = "locks"
BACKUPS_DIR = "backups"

# ── Crypto ────────────────────────────────────────────────────────────────────
HASH_ALGORITHM = "sha256"
HMAC_KEY_LENGTH = 32  # bytes

# ── File States ───────────────────────────────────────────────────────────────
STATE_UNSEALED = "UNSEALED"
STATE_SEALED = "SEALED"
STATE_ACTIVE = "ACTIVE"
STATE_DEPRECATED = "DEPRECATED"
STATE_REVOKED = "REVOKED"
STATE_TAMPERED = "TAMPERED"

VALID_STATES = {STATE_UNSEALED, STATE_SEALED, STATE_ACTIVE, STATE_DEPRECATED, STATE_REVOKED, STATE_TAMPERED}
READABLE_STATES = {STATE_SEALED, STATE_ACTIVE}
PROPOSABLE_STATES = {STATE_SEALED, STATE_ACTIVE}

# ── Policy Defaults ───────────────────────────────────────────────────────────
DEFAULT_POLICY = {
    "read": {"allow": "all_agents"},
    "write": {"allow": "none"},
    "propose": {"allow": "all_agents"},
    "approve": {"allow": "humans"},
}

# ── Operations ────────────────────────────────────────────────────────────────
OP_READ = "read"
OP_WRITE = "write"
OP_PROPOSE = "propose"
OP_APPROVE = "approve"
OP_EDIT = "edit"

# ── Environment ───────────────────────────────────────────────────────────────
ENV_GUARD_ROOT = "ACG_GUARD_ROOT"
ENV_EDITOR = "EDITOR"
DEFAULT_EDITOR = os.environ.get(ENV_EDITOR, "vi")

# ── File Patterns ─────────────────────────────────────────────────────────────
# Supported file extensions for protection. Includes markdown, structured data,
# configuration, and template formats commonly used in AI agent workflows.
CONTEXT_FILE_EXTENSIONS = {
    # Markdown
    ".md", ".markdown", ".mdown", ".mkd", ".mkdn",
    # Structured data
    ".yaml", ".yml", ".json", ".jsonl", ".toml",
    # Plain text and config
    ".txt", ".cfg", ".ini", ".env",
    # Web and template
    ".xml", ".html", ".jinja", ".jinja2", ".j2",
    # Prompt files
    ".prompt",
    # CSV / TSV (tabular context)
    ".csv", ".tsv",
}

# Backward-compatible alias — existing code that references MARKDOWN_EXTENSIONS
# will continue to work but now covers all supported context file types.
MARKDOWN_EXTENSIONS = CONTEXT_FILE_EXTENSIONS

# ── Audit Log Limits ─────────────────────────────────────────────────────────
# Default maximum audit log entries before automatic archival is triggered.
# Users can override via policy.yaml or environment variable.
DEFAULT_AUDIT_MAX_ENTRIES = 10000
ENV_AUDIT_MAX_ENTRIES = "ACG_AUDIT_MAX_ENTRIES"


def get_guard_root(start: Path | None = None) -> Path:
    """Walk up from *start* (default: cwd) to find the guard root directory."""
    env_root = os.environ.get(ENV_GUARD_ROOT)
    if env_root:
        return Path(env_root)
    search = start or Path.cwd()
    for parent in [search, *search.parents]:
        candidate = parent / GUARD_DIR_NAME
        if candidate.is_dir():
            return parent
    raise FileNotFoundError(
        f"No {GUARD_DIR_NAME} directory found. Run 'acg init' first."
    )


def guard_dir(root: Path) -> Path:
    return root / GUARD_DIR_NAME


def inventory_path(root: Path) -> Path:
    return guard_dir(root) / INVENTORY_FILE


def audit_log_path(root: Path) -> Path:
    return guard_dir(root) / AUDIT_LOG_FILE


def keys_dir(root: Path) -> Path:
    return guard_dir(root) / KEYS_DIR


def proposals_dir(root: Path) -> Path:
    return guard_dir(root) / PROPOSALS_DIR


def policy_path(root: Path) -> Path:
    return guard_dir(root) / POLICY_FILE


def locks_dir(root: Path) -> Path:
    return guard_dir(root) / LOCK_DIR


def backups_dir(root: Path) -> Path:
    return guard_dir(root) / BACKUPS_DIR
