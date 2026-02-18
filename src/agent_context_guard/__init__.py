"""
Agent Context Guard — __init__.py
Version: 1.0.1
Author: Agent Context Guard contributors

Integrity verification and access control for AI agent context files.

Primary entry point is the Guard class:

    from agent_context_guard import Guard
    guard = Guard("/path/to/project")
    content = guard.read("prompts/persona.md", agent_id="my-agent")
"""

__version__ = "1.0.1"
__author__ = "Agent Context Guard contributors"
__license__ = "Apache-2.0"

from agent_context_guard.guard import Guard, GuardSession
from agent_context_guard.core.seal import seal_file, verify_seal, verify_and_read
from agent_context_guard.core.inventory import Inventory
from agent_context_guard.core.policy import PolicyEngine
from agent_context_guard.core.audit import AuditLogger
from agent_context_guard.core.proposals import ProposalManager
from agent_context_guard.core.exceptions import (
    AgentContextGuardError, GuardNotInitializedError, PolicyDeniedError,
    SealError, SealIntegrityError, SealNotFoundError, FileLockedError,
    ProposalError, InventoryError, InventoryCorruptedError, KeyManagementError,
)

__all__ = [
    "Guard", "GuardSession", "seal_file", "verify_seal", "verify_and_read",
    "Inventory", "PolicyEngine", "AuditLogger", "ProposalManager",
    "AgentContextGuardError", "GuardNotInitializedError", "PolicyDeniedError",
    "SealError", "SealIntegrityError", "SealNotFoundError", "FileLockedError",
    "ProposalError", "InventoryError", "InventoryCorruptedError", "KeyManagementError",
]
