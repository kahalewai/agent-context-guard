"""Inventory: persistent registry of all protected files and their seal records.

The inventory is stored as JSON at `.agent-context-guard/inventory.json`.
All mutations are atomic (write-to-temp then rename) to prevent corruption.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Iterator

from agent_context_guard.core.constants import (
    STATE_ACTIVE,
    STATE_DEPRECATED,
    STATE_REVOKED,
    STATE_SEALED,
    VALID_STATES,
    inventory_path,
)
from agent_context_guard.core.exceptions import (
    InventoryCorruptedError,
    InventoryError,
    SealNotFoundError,
)
from agent_context_guard.core.seal import SealRecord
from agent_context_guard.core.selfprotect import sign_metadata_file, verify_metadata_file

logger = logging.getLogger(__name__)


class Inventory:
    """Thread-safe, atomic-write inventory of seal records.

    Structure on disk::

        {
            "version": 1,
            "files": {
                "/abs/path/to/file.md": [
                    { ...SealRecord... },
                    ...
                ]
            }
        }
    """

    SCHEMA_VERSION = 1

    def __init__(self, root: Path) -> None:
        self._root = root
        self._path = inventory_path(root)
        self._data: dict[str, list[dict[str, Any]]] = {}
        self._load()

    # ── Persistence ───────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._path.exists():
            self._data = {}
            return
        # Verify integrity BEFORE parsing
        verify_metadata_file(self._path, self._root)
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if raw.get("version", 1) != self.SCHEMA_VERSION:
                raise InventoryCorruptedError(
                    f"Unsupported inventory schema version: {raw.get('version')}"
                )
            self._data = raw.get("files", {})
        except (json.JSONDecodeError, KeyError) as exc:
            raise InventoryCorruptedError(f"Cannot parse inventory: {exc}") from exc

    def _save(self) -> None:
        payload = json.dumps(
            {"version": self.SCHEMA_VERSION, "files": self._data},
            indent=2,
            sort_keys=True,
        )
        # Atomic write: temp file in same dir → rename
        fd, tmp = tempfile.mkstemp(
            dir=self._path.parent, suffix=".tmp", prefix="inv_"
        )
        try:
            with open(fd, "w", encoding="utf-8") as f:
                f.write(payload)
            Path(tmp).replace(self._path)
            # Sign the inventory after write
            sign_metadata_file(self._path, self._root)
        except Exception:
            Path(tmp).unlink(missing_ok=True)
            raise

    # ── Queries ───────────────────────────────────────────────────────────

    def has_file(self, file_path: str) -> bool:
        return file_path in self._data

    def get_active_record(self, file_path: str) -> SealRecord:
        """Return the current ACTIVE or SEALED record for a file."""
        records = self._data.get(file_path)
        if not records:
            raise SealNotFoundError(f"No seal records for {file_path}")
        for rec in reversed(records):
            if rec["state"] in (STATE_ACTIVE, STATE_SEALED):
                return SealRecord.from_dict(rec)
        raise SealNotFoundError(f"No active seal record for {file_path}")

    def get_all_records(self, file_path: str) -> list[SealRecord]:
        records = self._data.get(file_path, [])
        return [SealRecord.from_dict(r) for r in records]

    def list_protected_files(self) -> list[str]:
        return list(self._data.keys())

    def iter_active(self) -> Iterator[SealRecord]:
        """Iterate over all currently active seal records."""
        for records in self._data.values():
            for rec in reversed(records):
                if rec["state"] in (STATE_ACTIVE, STATE_SEALED):
                    yield SealRecord.from_dict(rec)
                    break

    @property
    def file_count(self) -> int:
        return len(self._data)

    # ── Mutations ─────────────────────────────────────────────────────────

    def add_record(self, record: SealRecord) -> None:
        """Add a new seal record, deprecating any previous active version."""
        fp = record.file_path
        if fp not in self._data:
            self._data[fp] = []
        # Deprecate previous active records
        for rec in self._data[fp]:
            if rec["state"] in (STATE_ACTIVE, STATE_SEALED):
                rec["state"] = STATE_DEPRECATED
        self._data[fp].append(record.to_dict())
        self._save()
        logger.info("Added seal record for %s (v%d, state=%s)", fp, record.version, record.state)

    def update_state(self, file_path: str, version: int, new_state: str) -> None:
        """Transition a specific version to a new state."""
        if new_state not in VALID_STATES:
            raise InventoryError(f"Invalid state: {new_state}")
        records = self._data.get(file_path)
        if not records:
            raise SealNotFoundError(f"No records for {file_path}")
        for rec in records:
            if rec["version"] == version:
                rec["state"] = new_state
                self._save()
                return
        raise SealNotFoundError(f"Version {version} not found for {file_path}")

    def revoke(self, file_path: str) -> None:
        """Revoke all versions of a file."""
        records = self._data.get(file_path)
        if not records:
            raise SealNotFoundError(f"No records for {file_path}")
        for rec in records:
            rec["state"] = STATE_REVOKED
        self._save()

    def remove_file(self, file_path: str) -> None:
        """Completely remove a file from the inventory."""
        if file_path not in self._data:
            raise SealNotFoundError(f"No records for {file_path}")
        del self._data[file_path]
        self._save()

    def replace_record(self, old_record: SealRecord, new_record: SealRecord) -> None:
        """Replace an existing record in-place (used during key rotation)."""
        fp = old_record.file_path
        records = self._data.get(fp, [])
        for i, rec in enumerate(records):
            if rec["version"] == old_record.version and rec["signature"] == old_record.signature:
                records[i] = new_record.to_dict()
                self._save()
                return
        raise SealNotFoundError(f"Record to replace not found for {fp}")

    def next_version(self, file_path: str) -> int:
        """Return the next version number for a file."""
        records = self._data.get(file_path, [])
        if not records:
            return 1
        return max(r["version"] for r in records) + 1
