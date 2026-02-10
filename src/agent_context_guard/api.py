"""Public Python API for agent-context-guard (Layer 1 Language Wrapper).

Usage::

    from agent_context_guard import read_md, propose_update, get_status

    content = read_md("prompts/persona.md", agent_id="my-agent")
    propose_update("prompts/persona.md", new_content, agent_id="my-agent")
    status = get_status("prompts/persona.md")
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from agent_context_guard.core.audit import AuditLogger
from agent_context_guard.core.constants import STATE_ACTIVE, STATE_SEALED, get_guard_root
from agent_context_guard.core.exceptions import (
    GuardNotInitializedError,
    PolicyDeniedError,
    RuntimeNotActiveError,
)
from agent_context_guard.core.inventory import Inventory
from agent_context_guard.core.policy import PolicyContext, PolicyEngine
from agent_context_guard.core.proposals import ProposalManager
from agent_context_guard.core.runtime import get_active_guard
from agent_context_guard.core.seal import verify_seal, verify_and_read

logger = logging.getLogger(__name__)


def _resolve_root(root: Path | str | None = None) -> Path:
    if root:
        return Path(root)
    try:
        return get_guard_root()
    except FileNotFoundError as exc:
        raise GuardNotInitializedError(str(exc)) from exc


def read_md(
    file_path: str | Path,
    *,
    agent_id: str = "default-agent",
    root: Path | str | None = None,
) -> str:
    """Read a protected markdown file.

    If a runtime guard is active, uses it (with policy enforcement and audit).
    Otherwise, performs a basic seal verification and returns the content.

    Args:
        file_path: Path to the markdown file.
        agent_id: Identity of the calling agent.
        root: Guard root directory (auto-detected if None).

    Returns:
        The file content as a string.

    Raises:
        PolicyDeniedError: If the policy denies the read.
        SealIntegrityError: If the file has been tampered with.
    """
    resolved = str(Path(file_path).resolve())

    # Try runtime guard first
    try:
        guard = get_active_guard()
        return guard.read_file(resolved, actor=agent_id, actor_type="agent")
    except RuntimeNotActiveError:
        pass

    # Fallback: offline verification
    root_path = _resolve_root(root)
    inv = Inventory(root_path)
    policy = PolicyEngine(root_path)
    audit = AuditLogger(root_path)

    record = inv.get_active_record(resolved)
    decision = policy.check_read(resolved, agent_id, file_state=record.state)
    if not decision.allowed:
        audit.log_read(resolved, agent_id, allowed=False, detail=decision.reason)
        raise PolicyDeniedError(decision.reason)

    verify_seal(record, root_path)
    content = verify_and_read(record, root_path)
    audit.log_read(resolved, agent_id, allowed=True)
    return content


def propose_update(
    file_path: str | Path,
    new_content: str,
    *,
    agent_id: str = "default-agent",
    justification: str = "",
    root: Path | str | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Propose an update to a protected file.

    The proposal is stored for human review. Agents can never approve
    their own proposals.

    Args:
        file_path: Path to the target file.
        new_content: The proposed new file content.
        agent_id: Identity of the calling agent.
        justification: Reason for the change.
        root: Guard root directory.
        metadata: Optional extra metadata.

    Returns:
        The proposal ID.
    """
    resolved = str(Path(file_path).resolve())
    root_path = _resolve_root(root)
    inv = Inventory(root_path)
    policy = PolicyEngine(root_path)
    audit = AuditLogger(root_path)
    pm = ProposalManager(root_path)

    record = inv.get_active_record(resolved)
    decision = policy.check_propose(resolved, agent_id, file_state=record.state)
    if not decision.allowed:
        audit.log_policy_denial(resolved, agent_id, "propose", decision.reason)
        raise PolicyDeniedError(decision.reason)

    original = Path(resolved).read_text(encoding="utf-8")
    proposal = pm.create_proposal(
        file_path=resolved,
        original_content=original,
        proposed_content=new_content,
        agent_id=agent_id,
        justification=justification,
        metadata=metadata,
    )
    audit.log_proposal(resolved, agent_id, proposal.proposal_id, justification)
    return proposal.proposal_id


def get_status(
    file_path: str | Path,
    *,
    root: Path | str | None = None,
) -> dict[str, Any]:
    """Get the protection status of a file.

    Returns a dict with keys: protected, state, version, pending_proposals.
    """
    resolved = str(Path(file_path).resolve())
    root_path = _resolve_root(root)
    inv = Inventory(root_path)
    pm = ProposalManager(root_path)

    if not inv.has_file(resolved):
        return {
            "protected": False,
            "state": None,
            "version": None,
            "pending_proposals": 0,
        }

    record = inv.get_active_record(resolved)
    pending = pm.list_proposals(file_path=resolved, status="pending")
    return {
        "protected": True,
        "state": record.state,
        "version": record.version,
        "pending_proposals": len(pending),
        "author": record.author,
        "timestamp": record.timestamp,
    }
