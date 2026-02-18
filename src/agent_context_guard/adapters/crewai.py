"""
agent_context_guard/adapters/crewai.py — CrewAI tool integration.

Provides factory functions that create CrewAI-compatible Tool instances
for reading protected files and proposing changes. Each tool delegates
to Guard.read() or Guard.propose() for full verification and auditing.

Usage:
    from agent_context_guard import Guard
    from agent_context_guard.adapters.crewai import create_context_tools

    guard = Guard("/path/to/project")
    read_tool, propose_tool = create_context_tools(guard, agent_id="my-crew-agent")

    # Use in a CrewAI agent
    from crewai import Agent
    agent = Agent(
        role="Analyst",
        tools=[read_tool, propose_tool],
        ...
    )

Requirements:
    pip install agent-context-guard[crewai]
    (installs crewai >= 0.1)
"""

from __future__ import annotations

import logging
from typing import Any

from agent_context_guard.guard import Guard

logger = logging.getLogger(__name__)

# Defer the crewai import to runtime so the module can be imported
# without crewai installed.
try:
    from crewai.tools import tool as crewai_tool

    _CREWAI_AVAILABLE = True
except ImportError:
    _CREWAI_AVAILABLE = False


def _require_crewai() -> None:
    """Raise a clear error if crewai is not installed."""
    if not _CREWAI_AVAILABLE:
        raise ImportError(
            "The CrewAI adapter requires 'crewai'. "
            "Install it with: pip install agent-context-guard[crewai]"
        )


def create_context_tools(
    guard: Guard,
    agent_id: str = "crewai-agent",
) -> tuple[Any, Any]:
    """Create a pair of CrewAI tools for reading and proposing changes.

    Returns two tools:
        1. ``read_protected_file`` — Read a verified protected file
        2. ``propose_file_update`` — Propose a change for human review

    Both tools perform full cryptographic verification, policy checking,
    and audit logging through the Guard instance.

    Args:
        guard: An initialized Guard instance.
        agent_id: Identity for policy evaluation and audit logging.

    Returns:
        A tuple of (read_tool, propose_tool).

    Raises:
        ImportError: If crewai is not installed.
    """
    _require_crewai()

    @crewai_tool("Read Protected File")
    def read_protected_file(file_path: str) -> str:
        """Read a cryptographically verified protected markdown file.

        The file content is verified against its sealed hash and HMAC
        signature before being returned. The access is policy-checked
        and logged to the tamper-evident audit trail.

        Args:
            file_path: Path to the protected markdown file.

        Returns:
            The verified file content as a string.
        """
        logger.debug("CrewAI read_protected_file called for: %s", file_path)
        return guard.read(file_path, agent_id=agent_id)

    @crewai_tool("Propose File Update")
    def propose_file_update(
        file_path: str,
        new_content: str,
        justification: str = "",
    ) -> str:
        """Propose a change to a protected markdown file for human review.

        The proposal is stored with a unified diff for human review.
        Agents cannot approve their own proposals — only humans can.

        Args:
            file_path: Path to the target protected file.
            new_content: The proposed new file content.
            justification: Reason for the change.

        Returns:
            The proposal ID for tracking.
        """
        logger.debug("CrewAI propose_file_update called for: %s", file_path)
        proposal_id = guard.propose(
            file_path,
            new_content,
            agent_id=agent_id,
            justification=justification,
        )
        return f"Proposal {proposal_id} submitted for human review."

    return read_protected_file, propose_file_update
