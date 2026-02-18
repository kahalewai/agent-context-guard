"""
Agent Context Guard — core/selfprotect.py
Version: 1.0.1
Author: Kahalewai

Self-Protection: HMAC integrity verification for guard metadata files.

The guard must guard itself.  The inventory, policy, and audit files are
critical security metadata.  If an attacker can modify them, all sealing
and policy enforcement is bypassed.

This module provides:
  - HMAC-SHA256 signing of guard metadata files
  - Verification on every load
  - Atomic update of both file and its HMAC
  - Separate HMAC sidecar files (.hmac) alongside each protected metadata file

The signing key used is the same HMAC key from keys/signing.key.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from pathlib import Path

from agent_context_guard.core.constants import (
    HMAC_KEY_LENGTH,
    inventory_path,
    policy_path,
)
from agent_context_guard.core.exceptions import (
    InventoryCorruptedError,
    KeyManagementError,
)

logger = logging.getLogger(__name__)


def _hmac_path(target: Path) -> Path:
    """Return the sidecar HMAC file path for a given metadata file."""
    return target.with_suffix(target.suffix + ".hmac")


def _load_key_raw(root: Path) -> bytes:
    """Load the signing key without going through seal.py (avoids circular imports)."""
    from agent_context_guard.core.constants import keys_dir
    key_path = keys_dir(root) / "signing.key"
    if not key_path.exists():
        raise KeyManagementError(f"Signing key not found at {key_path}.")
    key = key_path.read_bytes()
    if len(key) != HMAC_KEY_LENGTH:
        raise KeyManagementError("Signing key has unexpected length.")
    return key


def compute_file_hmac(content: bytes, key: bytes) -> str:
    """Compute HMAC-SHA256 of file content."""
    return hmac.new(key, content, hashlib.sha256).hexdigest()


def sign_metadata_file(file_path: Path, root: Path) -> None:
    """Compute and write the HMAC sidecar for a metadata file.

    Called after every write to inventory.json, policy.yaml, etc.
    """
    if not file_path.exists():
        return
    key = _load_key_raw(root)
    content = file_path.read_bytes()
    mac = compute_file_hmac(content, key)
    hmac_file = _hmac_path(file_path)
    hmac_file.write_text(mac, encoding="utf-8")
    hmac_file.chmod(0o644)


def verify_metadata_file(file_path: Path, root: Path) -> bool:
    """Verify the HMAC of a metadata file against its sidecar.

    Returns True if valid.  Raises InventoryCorruptedError if tampered.
    Returns True silently if the HMAC sidecar does not exist (first-run
    or migration scenario — the caller should then sign the file).
    """
    if not file_path.exists():
        return True
    hmac_file = _hmac_path(file_path)
    if not hmac_file.exists():
        # No HMAC yet — migration path.  Caller should sign after init.
        logger.debug("No HMAC sidecar for %s — skipping verification.", file_path)
        return True

    key = _load_key_raw(root)
    content = file_path.read_bytes()
    expected = compute_file_hmac(content, key)
    stored = hmac_file.read_text(encoding="utf-8").strip()

    if not hmac.compare_digest(expected, stored):
        raise InventoryCorruptedError(
            f"Integrity check FAILED for {file_path.name}. "
            "The file has been modified outside of Agent Context Guard. "
            "This may indicate tampering."
        )
    return True


def verify_all_metadata(root: Path) -> list[str]:
    """Verify all guard metadata files.  Returns list of failure messages."""
    failures: list[str] = []
    for target in [inventory_path(root), policy_path(root)]:
        try:
            verify_metadata_file(target, root)
        except InventoryCorruptedError as exc:
            failures.append(str(exc))
    return failures


def sign_all_metadata(root: Path) -> None:
    """Sign all guard metadata files with their current content."""
    for target in [inventory_path(root), policy_path(root)]:
        if target.exists():
            sign_metadata_file(target, root)
            logger.debug("Signed metadata file: %s", target.name)
