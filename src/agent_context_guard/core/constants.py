"""Constants and configuration defaults for agent-context-guard."""

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

# ── Crypto ────────────────────────────────────────────────────────────────────
HASH_ALGORITHM = "sha256"
HMAC_KEY_LENGTH = 32  # bytes
FERNET_KEY_ENV = "ACG_RUNTIME_KEY"  # Deprecated — kept for backward compat
FERNET_KEY_FD_ENV = "ACG_RUNTIME_KEY_FD"  # Preferred: FD number of pipe

# ── File States ───────────────────────────────────────────────────────────────
STATE_UNSEALED = "UNSEALED"
STATE_SEALED = "SEALED"
STATE_ACTIVE = "ACTIVE"
STATE_DEPRECATED = "DEPRECATED"
STATE_REVOKED = "REVOKED"

VALID_STATES = {STATE_UNSEALED, STATE_SEALED, STATE_ACTIVE, STATE_DEPRECATED, STATE_REVOKED}
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
MARKDOWN_EXTENSIONS = {".md", ".markdown", ".mdown", ".mkd", ".mkdn"}


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
        f"No {GUARD_DIR_NAME} directory found. Run 'agent-context-guard init' first."
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
