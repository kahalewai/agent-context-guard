"""
Agent Context Guard — guard.py
Version: 1.0.1
Author: Kahalewai

Central API for Agent Context Guard. This module is the single entry
point for all library operations. Every adapter, framework integration,
and CLI command ultimately calls through the Guard class defined here.

Security model:
    Protection is enforced at the API level. Agents access files through
    Guard.read(), which verifies cryptographic seals, enforces policy,
    and produces an audit trail.
"""

from __future__ import annotations

import logging
import shutil
import threading
from pathlib import Path
from typing import Any

from agent_context_guard.core.audit import AuditLogger
from agent_context_guard.core.constants import (
    STATE_ACTIVE, guard_dir, inventory_path, backups_dir,
)
from agent_context_guard.core.exceptions import (
    GuardNotInitializedError, PolicyDeniedError,
    SealIntegrityError, SealNotFoundError,
)
from agent_context_guard.core.inventory import Inventory
from agent_context_guard.core.policy import PolicyEngine
from agent_context_guard.core.proposals import ProposalManager
from agent_context_guard.core.seal import seal_file, verify_and_read, verify_seal
from agent_context_guard.core.selfprotect import verify_all_metadata

logger = logging.getLogger(__name__)


class Guard:
    """Entry point for all Agent Context Guard operations.

    A Guard instance is bound to a project root directory that has been
    initialized with ``acg init``. It provides three primary operations:

    - **read()** — Read a protected file with full verification
    - **propose()** — Submit a change for human review
    - **status()** — Query the protection state of a file
    """

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root).resolve()
        self._verify_initialized()
        self._inventory = Inventory(self._root)
        self._policy = PolicyEngine(self._root)
        self._audit = AuditLogger(self._root)
        self._proposals = ProposalManager(self._root)
        self._lock = threading.Lock()
        logger.info("Guard initialized for %s (%d protected file(s))", self._root, self._inventory.file_count)

    @property
    def root(self) -> Path:
        return self._root

    @property
    def inventory(self) -> Inventory:
        return self._inventory

    @property
    def policy(self) -> PolicyEngine:
        return self._policy

    @property
    def audit(self) -> AuditLogger:
        return self._audit

    @property
    def proposals(self) -> ProposalManager:
        return self._proposals

    @property
    def protected_file_count(self) -> int:
        return self._inventory.file_count

    def read(self, file_path: str | Path, *, agent_id: str = "default", actor_type: str = "agent") -> str:
        """Read a protected file with full verification."""
        resolved = str(Path(file_path).resolve())
        record = self._inventory.get_active_record(resolved)
        decision = self._policy.check_read(resolved, agent_id, actor_type=actor_type, file_state=record.state)
        if not decision.allowed:
            self._audit.log_read(resolved, agent_id, allowed=False, detail=decision.reason)
            raise PolicyDeniedError(decision.reason)
        try:
            content = verify_and_read(record, self._root)
        except SealIntegrityError as exc:
            self._audit.log_read(resolved, agent_id, allowed=False, detail=str(exc))
            raise
        self._audit.log_read(resolved, agent_id, allowed=True)
        return content

    def propose(self, file_path: str | Path, new_content: str, *, agent_id: str = "default", justification: str = "", metadata: dict[str, Any] | None = None) -> str:
        """Propose a change to a protected file for human review."""
        resolved = str(Path(file_path).resolve())
        record = self._inventory.get_active_record(resolved)
        decision = self._policy.check_propose(resolved, agent_id, file_state=record.state)
        if not decision.allowed:
            self._audit.log_policy_denial(resolved, agent_id, "propose", decision.reason)
            raise PolicyDeniedError(decision.reason)
        original = Path(resolved).read_text(encoding="utf-8")
        with self._lock:
            proposal = self._proposals.create_proposal(
                file_path=resolved, original_content=original, proposed_content=new_content,
                agent_id=agent_id, justification=justification, metadata=metadata,
            )
        self._audit.log_proposal(resolved, agent_id, proposal.proposal_id, justification)
        return proposal.proposal_id

    def status(self, file_path: str | Path) -> dict[str, Any]:
        """Get the protection status of a file."""
        resolved = str(Path(file_path).resolve())
        if not self._inventory.has_file(resolved):
            return {"protected": False}
        record = self._inventory.get_active_record(resolved)
        pending = self._proposals.list_proposals(file_path=resolved, status="pending")
        return {
            "protected": True, "state": record.state, "version": record.version,
            "author": record.author, "timestamp": record.timestamp,
            "content_hash": record.content_hash, "pending_proposals": len(pending),
        }

    def verify_all(self) -> list[str]:
        """Verify the integrity of all protected files and guard metadata."""
        failures = verify_all_metadata(self._root)
        for record in self._inventory.iter_active():
            try:
                verify_and_read(record, self._root)
            except SealIntegrityError as exc:
                failures.append(str(exc))
                self._audit.log_verify(record.file_path, success=False, detail=str(exc))
            else:
                self._audit.log_verify(record.file_path, success=True)
        if failures:
            logger.warning("Verification found %d failure(s)", len(failures))
        return failures

    def verify_file(self, file_path: str | Path) -> bool:
        """Verify a single file's integrity."""
        resolved = str(Path(file_path).resolve())
        record = self._inventory.get_active_record(resolved)
        try:
            verify_and_read(record, self._root)
        except SealIntegrityError as exc:
            self._audit.log_verify(resolved, success=False, detail=str(exc))
            raise
        self._audit.log_verify(resolved, success=True)
        return True

    def backup_file(self, file_path: str | Path) -> Path | None:
        """Create a backup of a protected file in the backups directory."""
        resolved = Path(file_path).resolve()
        if not resolved.exists():
            return None
        bdir = backups_dir(self._root)
        bdir.mkdir(parents=True, exist_ok=True)
        import time
        ts = int(time.time())
        backup_path = bdir / f"{resolved.name}.{ts}"
        shutil.copy2(resolved, backup_path)
        return backup_path

    def session(self, agent_id: str = "default") -> GuardSession:
        """Create a scoped session bound to a specific agent identity."""
        return GuardSession(self, agent_id)

    def _verify_initialized(self) -> None:
        gd = guard_dir(self._root)
        if not gd.is_dir():
            raise GuardNotInitializedError(f"No .agent-context-guard directory found at {self._root}. Run 'acg init' first.")
        inv_path = inventory_path(self._root)
        if not inv_path.exists():
            raise GuardNotInitializedError(f"Inventory file missing at {inv_path}. Run 'acg init' to reinitialize.")

    def __repr__(self) -> str:
        return f"Guard(root={self._root!r}, files={self._inventory.file_count})"


class GuardSession:
    """A scoped session that binds an agent identity to a Guard instance."""

    def __init__(self, guard: Guard, agent_id: str) -> None:
        self._guard = guard
        self._agent_id = agent_id

    def __enter__(self) -> GuardSession:
        return self

    def __exit__(self, *exc: Any) -> None:
        pass

    def read(self, file_path: str | Path) -> str:
        return self._guard.read(file_path, agent_id=self._agent_id)

    def propose(self, file_path: str | Path, new_content: str, justification: str = "", metadata: dict[str, Any] | None = None) -> str:
        return self._guard.propose(file_path, new_content, agent_id=self._agent_id, justification=justification, metadata=metadata)

    def status(self, file_path: str | Path) -> dict[str, Any]:
        return self._guard.status(file_path)

    def verify(self, file_path: str | Path) -> bool:
        return self._guard.verify_file(file_path)

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def guard(self) -> Guard:
        return self._guard

    def __repr__(self) -> str:
        return f"GuardSession(agent_id={self._agent_id!r}, guard={self._guard!r})"
