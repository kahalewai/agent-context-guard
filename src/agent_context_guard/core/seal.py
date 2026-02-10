"""Sealing: cryptographic hashing and signature management for protected files.

Sealing consists of:
  - SHA-256 hash of file contents
  - HMAC-SHA256 signature using a stored signing key
  - Metadata (timestamp, author, version)

No semantic interpretation of file contents is performed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from agent_context_guard.core.constants import (
    HASH_ALGORITHM,
    HMAC_KEY_LENGTH,
    keys_dir,
)
from agent_context_guard.core.exceptions import (
    KeyManagementError,
    SealError,
    SealIntegrityError,
)


@dataclass(frozen=True)
class SealRecord:
    """Immutable record of a file's sealed state."""

    file_path: str
    content_hash: str
    signature: str
    version: int
    timestamp: float
    author: str
    state: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SealRecord:
        return cls(**data)


# ── Hashing ───────────────────────────────────────────────────────────────────

def compute_hash(content: bytes) -> str:
    """Return hex-encoded SHA-256 hash of *content*."""
    return hashlib.new(HASH_ALGORITHM, content).hexdigest()


def compute_file_hash(path: Path) -> str:
    """Return hex-encoded SHA-256 hash of a file's contents."""
    return compute_hash(path.read_bytes())


# ── Signing ───────────────────────────────────────────────────────────────────

def _signing_key_path(root: Path) -> Path:
    return keys_dir(root) / "signing.key"


def generate_signing_key(root: Path) -> None:
    """Generate and persist a new HMAC signing key."""
    kdir = keys_dir(root)
    kdir.mkdir(parents=True, exist_ok=True)
    key_path = _signing_key_path(root)
    if key_path.exists():
        raise KeyManagementError(
            f"Signing key already exists at {key_path}. "
            "Use 'rotate-keys' to replace it."
        )
    key_path.write_bytes(os.urandom(HMAC_KEY_LENGTH))
    key_path.chmod(0o600)


def load_signing_key(root: Path) -> bytes:
    """Load the HMAC signing key from disk."""
    key_path = _signing_key_path(root)
    if not key_path.exists():
        raise KeyManagementError(
            f"Signing key not found at {key_path}. Run 'init' first."
        )
    key = key_path.read_bytes()
    if len(key) != HMAC_KEY_LENGTH:
        raise KeyManagementError("Signing key has unexpected length — possible corruption.")
    return key


def rotate_signing_key(root: Path) -> tuple[bytes, bytes]:
    """Rotate the signing key. Returns (old_key, new_key)."""
    key_path = _signing_key_path(root)
    old_key = load_signing_key(root)
    new_key = os.urandom(HMAC_KEY_LENGTH)
    key_path.write_bytes(new_key)
    key_path.chmod(0o600)
    return old_key, new_key


def compute_signature(content_hash: str, key: bytes) -> str:
    """Compute HMAC-SHA256 signature of the content hash."""
    return hmac.new(key, content_hash.encode(), hashlib.sha256).hexdigest()


def verify_signature(content_hash: str, signature: str, key: bytes) -> bool:
    """Verify an HMAC-SHA256 signature (constant-time comparison)."""
    expected = compute_signature(content_hash, key)
    return hmac.compare_digest(expected, signature)


# ── Seal Operations ──────────────────────────────────────────────────────────

def seal_file(
    path: Path,
    root: Path,
    *,
    author: str = "human",
    version: int = 1,
    state: str = "SEALED",
    metadata: dict[str, Any] | None = None,
) -> SealRecord:
    """Create a SealRecord for *path*.

    The file must exist. The signing key must already be generated.
    """
    if not path.exists():
        raise SealError(f"Cannot seal non-existent file: {path}")
    content_hash = compute_file_hash(path)
    key = load_signing_key(root)
    signature = compute_signature(content_hash, key)
    return SealRecord(
        file_path=str(path.resolve()),
        content_hash=content_hash,
        signature=signature,
        version=version,
        timestamp=time.time(),
        author=author,
        state=state,
        metadata=metadata or {},
    )


def verify_seal(record: SealRecord, root: Path) -> bool:
    """Verify that a SealRecord's signature is valid and the file is unmodified.

    Raises SealIntegrityError if the file contents have changed.
    Returns False if the signature does not match the stored key.
    """
    path = Path(record.file_path)
    if not path.exists():
        raise SealIntegrityError(f"Sealed file missing: {path}")
    current_hash = compute_file_hash(path)
    if current_hash != record.content_hash:
        raise SealIntegrityError(
            f"File contents changed for {path}. "
            f"Expected hash {record.content_hash[:12]}…, got {current_hash[:12]}…"
        )
    key = load_signing_key(root)
    return verify_signature(record.content_hash, record.signature, key)


def verify_and_read(record: SealRecord, root: Path) -> str:
    """Read a file into memory, verify its seal, and return the content.

    This eliminates the TOCTOU race condition present when verify_seal()
    and read() are called separately.  The file is read exactly ONCE;
    the hash of that in-memory buffer is checked against the seal record.

    Returns the verified file content as a string.

    Raises:
        SealIntegrityError: if the file is missing, tampered, or signature invalid.
    """
    path = Path(record.file_path)
    if not path.exists():
        raise SealIntegrityError(f"Sealed file missing: {path}")

    # Single read — this is the ONLY disk access
    content_bytes = path.read_bytes()
    content_hash = compute_hash(content_bytes)

    if content_hash != record.content_hash:
        raise SealIntegrityError(
            f"File contents changed for {path}. "
            f"Expected hash {record.content_hash[:12]}…, got {content_hash[:12]}…"
        )

    key = load_signing_key(root)
    if not verify_signature(record.content_hash, record.signature, key):
        raise SealIntegrityError(
            f"Signature verification failed for {path}. "
            "The seal record may have been tampered with."
        )

    return content_bytes.decode("utf-8")


def re_seal(
    record: SealRecord,
    new_key: bytes,
) -> SealRecord:
    """Create a new SealRecord with a fresh signature using *new_key*.

    Used during key rotation.  Does NOT re-hash the file; the caller must
    verify integrity beforehand.
    """
    new_signature = compute_signature(record.content_hash, new_key)
    return SealRecord(
        file_path=record.file_path,
        content_hash=record.content_hash,
        signature=new_signature,
        version=record.version,
        timestamp=record.timestamp,
        author=record.author,
        state=record.state,
        metadata=record.metadata,
    )
