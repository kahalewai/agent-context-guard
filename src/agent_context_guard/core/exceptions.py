"""Custom exceptions for agent-context-guard."""

from __future__ import annotations


class AgentContextGuardError(Exception):
    """Base exception for all agent-context-guard errors."""


class SealError(AgentContextGuardError):
    """Raised when sealing or seal verification fails."""


class SealIntegrityError(SealError):
    """Raised when a sealed file's content does not match its recorded hash."""


class SealNotFoundError(SealError):
    """Raised when a seal record is missing for a protected file."""


class PolicyDeniedError(AgentContextGuardError):
    """Raised when the policy engine denies an operation."""


class RuntimeNotActiveError(AgentContextGuardError):
    """Raised when an operation requires an active runtime guard but none is running."""


class RuntimeAlreadyActiveError(AgentContextGuardError):
    """Raised when attempting to start a guard that is already active."""


class FileLockedError(AgentContextGuardError):
    """Raised when a file is locked for human editing and cannot be accessed."""


class ProposalError(AgentContextGuardError):
    """Raised for errors in the proposal workflow."""


class InventoryError(AgentContextGuardError):
    """Raised for errors in the inventory system."""


class InventoryCorruptedError(InventoryError):
    """Raised when the inventory file is corrupted or unreadable."""


class GuardNotInitializedError(AgentContextGuardError):
    """Raised when the guard directory has not been initialized."""


class EditSessionError(AgentContextGuardError):
    """Raised for errors during human edit sessions."""


class KeyManagementError(AgentContextGuardError):
    """Raised for errors in key generation, rotation, or management."""
