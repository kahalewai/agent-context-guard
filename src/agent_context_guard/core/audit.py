"""
Agent Context Guard — core/audit.py
Version: 1.0.1
Author: Kahalewai

Audit Logger: append-only, hash-chained logging of all guard events.

Every access, denial, proposal, approval, and edit is recorded in
`.agent-context-guard/audit.log` as newline-delimited JSON (JSON Lines).

Each entry includes a `prev_hash` field that is the SHA-256 hash of the
previous entry's JSON.  This creates a tamper-evident hash chain: any
deletion, modification, or reordering of entries breaks the chain.

Logs are designed to be both human-readable and machine-parseable.

Failsafe: When the audit log exceeds a configurable entry threshold
(default 10,000), it is automatically archived to a timestamped file
and a fresh log is started. This prevents unbounded growth while
preserving the full history.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from agent_context_guard.core.constants import (
    audit_log_path,
    backups_dir,
    DEFAULT_AUDIT_MAX_ENTRIES,
    ENV_AUDIT_MAX_ENTRIES,
)

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """Single audit log entry."""

    timestamp: float
    event: str
    actor: str
    file_path: str = ""
    operation: str = ""
    result: str = ""  # "allowed", "denied", "error"
    detail: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""  # SHA-256 of previous entry's JSON (hash chain)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, line: str) -> AuditEntry:
        data = json.loads(line)
        # Handle old entries without prev_hash
        if "prev_hash" not in data:
            data["prev_hash"] = ""
        return cls(**data)


class AuditLogger:
    """Append-only, hash-chained audit logger writing JSON Lines.

    Includes automatic archival when the log exceeds max_entries to
    prevent unbounded growth. Archives are stored in the backups/
    subdirectory with timestamps for identification.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self._path = audit_log_path(root)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()
            self._path.chmod(0o644)
        self._last_hash: str = self._compute_tail_hash()

        # Configurable max entries before archive rotation
        try:
            self._max_entries = int(os.environ.get(ENV_AUDIT_MAX_ENTRIES, DEFAULT_AUDIT_MAX_ENTRIES))
        except ValueError:
            self._max_entries = DEFAULT_AUDIT_MAX_ENTRIES

    def _compute_tail_hash(self) -> str:
        """Compute the hash of the last entry in the log (for chaining)."""
        if not self._path.exists() or self._path.stat().st_size == 0:
            return ""
        # Read last non-empty line
        last_line = ""
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
        if not last_line:
            return ""
        return hashlib.sha256(last_line.encode("utf-8")).hexdigest()

    def _append(self, entry: AuditEntry) -> None:
        """Append an entry to the log, archiving if threshold is reached."""
        entry.prev_hash = self._last_hash
        json_line = entry.to_json()
        self._last_hash = hashlib.sha256(json_line.encode("utf-8")).hexdigest()
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json_line + "\n")
            f.flush()
            os.fsync(f.fileno())

        # Check if we need to archive (failsafe for excessive logs)
        self._check_archive()

    def _check_archive(self) -> None:
        """Archive the audit log if it exceeds the configured max entries."""
        current_count = self.entry_count
        if current_count >= self._max_entries:
            self._archive_log()

    def _archive_log(self) -> None:
        """Move the current audit log to the backups directory with a timestamp."""
        bdir = backups_dir(self._root)
        bdir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        archive_name = f"audit_{timestamp}.log"
        archive_path = bdir / archive_name

        # Copy then truncate (preserves the file handle)
        shutil.copy2(self._path, archive_path)
        archive_path.chmod(0o644)

        # Start a fresh log with an archival marker
        with open(self._path, "w", encoding="utf-8") as f:
            f.truncate(0)

        # Reset the chain
        self._last_hash = ""

        # Log the archival event in the new fresh log
        self._append(AuditEntry(
            timestamp=time.time(),
            event="audit_archived",
            actor="system",
            operation="archive",
            result="allowed",
            detail=f"Archived {archive_name} ({self._max_entries} entries). Fresh log started.",
        ))
        logger.info("Audit log archived to %s", archive_path)

    def verify_chain(self) -> tuple[bool, int, str]:
        """Verify the hash chain of the entire audit log.

        Returns (valid, entry_count, error_message).
        """
        if not self._path.exists():
            return True, 0, ""
        prev_hash = ""
        count = 0
        with open(self._path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                count += 1
                try:
                    entry = AuditEntry.from_json(stripped)
                except (json.JSONDecodeError, TypeError) as exc:
                    return False, count, f"Line {line_num}: malformed entry — {exc}"
                if entry.prev_hash != prev_hash:
                    return False, count, (
                        f"Line {line_num}: chain broken. "
                        f"Expected prev_hash {prev_hash[:16]}…, "
                        f"got {entry.prev_hash[:16]}…"
                    )
                prev_hash = hashlib.sha256(stripped.encode("utf-8")).hexdigest()
        return True, count, ""

    def list_archives(self) -> list[Path]:
        """List all archived audit log files, sorted by date."""
        bdir = backups_dir(self._root)
        if not bdir.exists():
            return []
        return sorted(bdir.glob("audit_*.log"))

    # ── Convenience Logging Methods ───────────────────────────────────────

    def log_read(
        self, file_path: str, actor: str, allowed: bool, detail: str = ""
    ) -> None:
        self._append(AuditEntry(
            timestamp=time.time(),
            event="file_read",
            actor=actor,
            file_path=file_path,
            operation="read",
            result="allowed" if allowed else "denied",
            detail=detail,
        ))

    def log_write_blocked(
        self, file_path: str, actor: str, detail: str = ""
    ) -> None:
        self._append(AuditEntry(
            timestamp=time.time(),
            event="write_blocked",
            actor=actor,
            file_path=file_path,
            operation="write",
            result="denied",
            detail=detail,
        ))

    def log_proposal(
        self, file_path: str, actor: str, proposal_id: str, detail: str = ""
    ) -> None:
        self._append(AuditEntry(
            timestamp=time.time(),
            event="proposal_submitted",
            actor=actor,
            file_path=file_path,
            operation="propose",
            result="allowed",
            detail=detail,
            metadata={"proposal_id": proposal_id},
        ))

    def log_approval(
        self, file_path: str, actor: str, proposal_id: str, detail: str = ""
    ) -> None:
        self._append(AuditEntry(
            timestamp=time.time(),
            event="proposal_approved",
            actor=actor,
            file_path=file_path,
            operation="approve",
            result="allowed",
            detail=detail,
            metadata={"proposal_id": proposal_id},
        ))

    def log_rejection(
        self, file_path: str, actor: str, proposal_id: str, detail: str = ""
    ) -> None:
        self._append(AuditEntry(
            timestamp=time.time(),
            event="proposal_rejected",
            actor=actor,
            file_path=file_path,
            operation="approve",
            result="denied",
            detail=detail,
            metadata={"proposal_id": proposal_id},
        ))

    def log_edit_session(
        self, file_path: str, actor: str, action: str, detail: str = ""
    ) -> None:
        """Log human edit session events (start, save, cancel)."""
        self._append(AuditEntry(
            timestamp=time.time(),
            event=f"edit_{action}",
            actor=actor,
            file_path=file_path,
            operation="edit",
            result="allowed",
            detail=detail,
        ))

    def log_seal(
        self, file_path: str, actor: str, version: int, detail: str = ""
    ) -> None:
        self._append(AuditEntry(
            timestamp=time.time(),
            event="file_sealed",
            actor=actor,
            file_path=file_path,
            operation="seal",
            result="allowed",
            detail=detail,
            metadata={"version": version},
        ))

    def log_policy_denial(
        self, file_path: str, actor: str, operation: str, detail: str = ""
    ) -> None:
        self._append(AuditEntry(
            timestamp=time.time(),
            event="policy_denied",
            actor=actor,
            file_path=file_path,
            operation=operation,
            result="denied",
            detail=detail,
        ))

    def log_runtime(self, event: str, detail: str = "") -> None:
        self._append(AuditEntry(
            timestamp=time.time(),
            event=event,
            actor="system",
            operation="runtime",
            result="allowed",
            detail=detail,
        ))

    def log_key_rotation(self, actor: str, detail: str = "") -> None:
        self._append(AuditEntry(
            timestamp=time.time(),
            event="key_rotation",
            actor=actor,
            operation="rotate",
            result="allowed",
            detail=detail,
        ))

    def log_verify(self, file_path: str, success: bool, detail: str = "") -> None:
        self._append(AuditEntry(
            timestamp=time.time(),
            event="verify",
            actor="system",
            file_path=file_path,
            operation="verify",
            result="allowed" if success else "denied",
            detail=detail,
        ))

    def log_recover(self, file_path: str, actor: str, action: str, detail: str = "") -> None:
        """Log recovery workflow events (rollback, accept)."""
        self._append(AuditEntry(
            timestamp=time.time(),
            event=f"recover_{action}",
            actor=actor,
            file_path=file_path,
            operation="recover",
            result="allowed",
            detail=detail,
        ))

    # ── Query ─────────────────────────────────────────────────────────────

    def iter_entries(
        self,
        *,
        event: str | None = None,
        file_path: str | None = None,
        actor: str | None = None,
        since: float | None = None,
        limit: int | None = None,
    ) -> Iterator[AuditEntry]:
        """Iterate over audit entries with optional filters."""
        count = 0
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = AuditEntry.from_json(line)
                except (json.JSONDecodeError, TypeError):
                    logger.warning("Skipping malformed audit entry: %s", line[:80])
                    continue
                if event and entry.event != event:
                    continue
                if file_path and entry.file_path != file_path:
                    continue
                if actor and entry.actor != actor:
                    continue
                if since and entry.timestamp < since:
                    continue
                yield entry
                count += 1
                if limit and count >= limit:
                    return

    @property
    def entry_count(self) -> int:
        if not self._path.exists():
            return 0
        with open(self._path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
