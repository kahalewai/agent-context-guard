"""Policy Engine: deterministic, non-LLM access control.

All authorization decisions are made without LLM input.
Policy dimensions:
  - agent identity
  - operation (read / propose / edit / approve / write)
  - environment
  - time
  - file state
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agent_context_guard.core.constants import (
    DEFAULT_POLICY,
    OP_APPROVE,
    OP_EDIT,
    OP_PROPOSE,
    OP_READ,
    OP_WRITE,
    READABLE_STATES,
    PROPOSABLE_STATES,
    policy_path,
)
from agent_context_guard.core.exceptions import PolicyDeniedError
from agent_context_guard.core.selfprotect import verify_metadata_file

logger = logging.getLogger(__name__)


@dataclass
class PolicyContext:
    """Contextual information used for policy evaluation."""

    actor: str = "unknown"
    actor_type: str = "agent"  # "agent" | "human" | "system"
    operation: str = ""
    file_path: str = ""
    file_state: str = ""
    environment: str = "default"
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecision:
    """Result of a policy evaluation."""

    allowed: bool
    reason: str
    context: PolicyContext


class PolicyEngine:
    """Deterministic policy evaluator.

    Loads policy from ``policy.yaml`` in the guard directory, falling back
    to sensible defaults if the file is absent or incomplete.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self._policy = self._load_policy()

    def _load_policy(self) -> dict[str, Any]:
        ppath = policy_path(self._root)
        if ppath.exists():
            # Verify integrity before trusting
            try:
                verify_metadata_file(ppath, self._root)
            except Exception as exc:
                logger.warning("Policy file integrity check failed: %s", exc)
                raise
            try:
                with open(ppath, encoding="utf-8") as f:
                    custom = yaml.safe_load(f) or {}
                merged = {**DEFAULT_POLICY, **custom}
                logger.debug("Loaded custom policy from %s", ppath)
                return merged
            except Exception as exc:
                logger.warning("Failed to load policy file, using defaults: %s", exc)
        return dict(DEFAULT_POLICY)

    def reload(self) -> None:
        """Re-read the policy file from disk."""
        self._policy = self._load_policy()

    @property
    def policy(self) -> dict[str, Any]:
        return dict(self._policy)

    # ── Evaluation ────────────────────────────────────────────────────────

    def evaluate(self, ctx: PolicyContext) -> PolicyDecision:
        """Evaluate whether an operation should be permitted.

        This is the single decision point for all access control.
        """
        # Write is ALWAYS denied during runtime — core invariant
        if ctx.operation == OP_WRITE:
            return PolicyDecision(
                allowed=False,
                reason="Direct writes to protected files are never allowed during runtime.",
                context=ctx,
            )

        # Approve is human-only — core invariant
        if ctx.operation == OP_APPROVE:
            if ctx.actor_type != "human":
                return PolicyDecision(
                    allowed=False,
                    reason="Only humans may approve proposals.",
                    context=ctx,
                )
            return PolicyDecision(
                allowed=True,
                reason="Human approval permitted.",
                context=ctx,
            )

        # Edit is human-only
        if ctx.operation == OP_EDIT:
            if ctx.actor_type != "human":
                return PolicyDecision(
                    allowed=False,
                    reason="Only humans may edit protected files.",
                    context=ctx,
                )
            return PolicyDecision(
                allowed=True,
                reason="Human edit permitted.",
                context=ctx,
            )

        # Read: check file state and policy
        if ctx.operation == OP_READ:
            if ctx.file_state and ctx.file_state not in READABLE_STATES:
                return PolicyDecision(
                    allowed=False,
                    reason=f"File state '{ctx.file_state}' is not readable.",
                    context=ctx,
                )
            rule = self._policy.get("read", {})
            return self._evaluate_rule(rule, ctx, "read")

        # Propose: check file state and policy
        if ctx.operation == OP_PROPOSE:
            if ctx.file_state and ctx.file_state not in PROPOSABLE_STATES:
                return PolicyDecision(
                    allowed=False,
                    reason=f"File state '{ctx.file_state}' does not accept proposals.",
                    context=ctx,
                )
            rule = self._policy.get("propose", {})
            return self._evaluate_rule(rule, ctx, "propose")

        return PolicyDecision(
            allowed=False,
            reason=f"Unknown operation: {ctx.operation}",
            context=ctx,
        )

    def _evaluate_rule(
        self, rule: dict[str, Any], ctx: PolicyContext, op_name: str
    ) -> PolicyDecision:
        allow = rule.get("allow", "none")

        # Simple wildcard rules
        if allow == "none":
            return PolicyDecision(
                allowed=False,
                reason=f"Policy denies all {op_name} operations.",
                context=ctx,
            )
        if allow == "all_agents":
            return PolicyDecision(
                allowed=True,
                reason=f"Policy allows all agents to {op_name}.",
                context=ctx,
            )
        if allow == "humans":
            if ctx.actor_type == "human":
                return PolicyDecision(
                    allowed=True,
                    reason=f"Policy allows humans to {op_name}.",
                    context=ctx,
                )
            return PolicyDecision(
                allowed=False,
                reason=f"Policy restricts {op_name} to humans.",
                context=ctx,
            )

        # Allow-list of specific agent IDs
        if isinstance(allow, list):
            if ctx.actor in allow:
                return PolicyDecision(
                    allowed=True,
                    reason=f"Actor '{ctx.actor}' is in the {op_name} allow list.",
                    context=ctx,
                )
            return PolicyDecision(
                allowed=False,
                reason=f"Actor '{ctx.actor}' is not in the {op_name} allow list.",
                context=ctx,
            )

        return PolicyDecision(
            allowed=False,
            reason=f"Unrecognized policy rule for {op_name}: {allow!r}",
            context=ctx,
        )

    # ── Convenience ───────────────────────────────────────────────────────

    def require(self, ctx: PolicyContext) -> PolicyDecision:
        """Evaluate and raise PolicyDeniedError if denied."""
        decision = self.evaluate(ctx)
        if not decision.allowed:
            raise PolicyDeniedError(
                f"[{ctx.operation}] denied for {ctx.actor}: {decision.reason}"
            )
        return decision

    def check_read(
        self, file_path: str, actor: str, actor_type: str = "agent", file_state: str = ""
    ) -> PolicyDecision:
        return self.evaluate(PolicyContext(
            actor=actor, actor_type=actor_type, operation=OP_READ,
            file_path=file_path, file_state=file_state,
        ))

    def check_propose(
        self, file_path: str, actor: str, actor_type: str = "agent", file_state: str = ""
    ) -> PolicyDecision:
        return self.evaluate(PolicyContext(
            actor=actor, actor_type=actor_type, operation=OP_PROPOSE,
            file_path=file_path, file_state=file_state,
        ))
