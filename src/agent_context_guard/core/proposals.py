"""Proposal Manager: agent-submitted update workflow.

Agents may *propose* updates to protected files but never approve or activate
them. Proposals are stored as unified diffs alongside metadata.
"""

from __future__ import annotations

import difflib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

from agent_context_guard.core.constants import proposals_dir
from agent_context_guard.core.exceptions import ProposalError

logger = logging.getLogger(__name__)


@dataclass
class Proposal:
    """A proposed change to a protected file."""

    proposal_id: str
    file_path: str
    agent_id: str
    timestamp: float
    diff: str
    justification: str = ""
    status: str = "pending"  # pending | approved | rejected
    new_content: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Proposal:
        return cls(**data)


class ProposalManager:
    """Manages the lifecycle of agent-submitted file change proposals."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._base = proposals_dir(root)
        self._base.mkdir(parents=True, exist_ok=True)

    def _file_dir(self, file_path: str) -> Path:
        """Directory for proposals targeting a specific file."""
        safe_name = file_path.replace("/", "_").replace("\\", "_").strip("_")
        d = self._base / safe_name
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ── Create ────────────────────────────────────────────────────────────

    def create_proposal(
        self,
        file_path: str,
        original_content: str,
        proposed_content: str,
        agent_id: str,
        justification: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> Proposal:
        """Create and persist a new proposal."""
        diff = "\n".join(difflib.unified_diff(
            original_content.splitlines(keepends=True),
            proposed_content.splitlines(keepends=True),
            fromfile=f"a/{Path(file_path).name}",
            tofile=f"b/{Path(file_path).name}",
        ))
        proposal_id = f"{int(time.time())}_{uuid.uuid4().hex[:8]}"
        proposal = Proposal(
            proposal_id=proposal_id,
            file_path=file_path,
            agent_id=agent_id,
            timestamp=time.time(),
            diff=diff,
            justification=justification,
            status="pending",
            new_content=proposed_content,
            metadata=metadata or {},
        )
        out_path = self._file_dir(file_path) / f"{proposal_id}.json"
        out_path.write_text(
            json.dumps(proposal.to_dict(), indent=2), encoding="utf-8"
        )
        logger.info("Proposal %s created for %s by %s", proposal_id, file_path, agent_id)
        return proposal

    # ── Query ─────────────────────────────────────────────────────────────

    def list_proposals(
        self, file_path: str | None = None, status: str | None = None
    ) -> list[Proposal]:
        """List proposals, optionally filtered by file and/or status."""
        results: list[Proposal] = []
        search_dirs = (
            [self._file_dir(file_path)] if file_path else list(self._base.iterdir())
        )
        for d in search_dirs:
            if not d.is_dir():
                continue
            for f in sorted(d.glob("*.json")):
                try:
                    p = Proposal.from_dict(json.loads(f.read_text(encoding="utf-8")))
                    if status and p.status != status:
                        continue
                    results.append(p)
                except Exception as exc:
                    logger.warning("Skipping malformed proposal %s: %s", f, exc)
        return results

    def get_proposal(self, file_path: str, proposal_id: str) -> Proposal:
        d = self._file_dir(file_path)
        p_path = d / f"{proposal_id}.json"
        if not p_path.exists():
            raise ProposalError(f"Proposal {proposal_id} not found for {file_path}")
        return Proposal.from_dict(json.loads(p_path.read_text(encoding="utf-8")))

    def get_latest_pending(self, file_path: str) -> Proposal | None:
        """Return the most recent pending proposal for a file, or None."""
        pending = self.list_proposals(file_path=file_path, status="pending")
        return pending[-1] if pending else None

    # ── Status Changes ────────────────────────────────────────────────────

    def _update_status(self, file_path: str, proposal_id: str, new_status: str) -> Proposal:
        d = self._file_dir(file_path)
        p_path = d / f"{proposal_id}.json"
        if not p_path.exists():
            raise ProposalError(f"Proposal {proposal_id} not found for {file_path}")
        proposal = Proposal.from_dict(json.loads(p_path.read_text(encoding="utf-8")))
        if proposal.status != "pending":
            raise ProposalError(
                f"Proposal {proposal_id} is already {proposal.status}, cannot change to {new_status}."
            )
        proposal.status = new_status
        p_path.write_text(
            json.dumps(proposal.to_dict(), indent=2), encoding="utf-8"
        )
        return proposal

    def approve(self, file_path: str, proposal_id: str) -> Proposal:
        return self._update_status(file_path, proposal_id, "approved")

    def reject(self, file_path: str, proposal_id: str) -> Proposal:
        return self._update_status(file_path, proposal_id, "rejected")
