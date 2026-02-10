"""
agent-context-guard: Runtime protection for AI agent markdown context files.

Prevents unauthorized viewing, modification, and silent drift of markdown files
that influence AI agent behavior, while preserving human ownership and editability.
"""

__version__ = "1.0.0"
__author__ = "agent-context-guard contributors"
__license__ = "Apache-2.0"

from agent_context_guard.core.seal import seal_file, verify_seal, verify_and_read
from agent_context_guard.core.inventory import Inventory
from agent_context_guard.core.policy import PolicyEngine
from agent_context_guard.core.runtime import RuntimeGuard
from agent_context_guard.core.proposals import ProposalManager
from agent_context_guard.core.audit import AuditLogger
from agent_context_guard.api import read_md, propose_update, get_status

__all__ = [
    "seal_file",
    "verify_seal",
    "Inventory",
    "PolicyEngine",
    "RuntimeGuard",
    "ProposalManager",
    "AuditLogger",
    "read_md",
    "propose_update",
    "get_status",
]
