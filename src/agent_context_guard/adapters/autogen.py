"""
agent_context_guard/adapters/autogen.py — AutoGen (AG2) integration.

Provides factory functions that create AutoGen-compatible function map
entries and tool registrations for reading protected files and proposing
changes.

Supports both AutoGen 0.2.x (ConversableAgent with function_map) and
AG2 / AutoGen 0.4+ (register_for_llm / register_for_execution patterns).

Usage (AutoGen 0.2.x):
    from agent_context_guard import Guard
    from agent_context_guard.adapters.autogen import create_function_map

    guard = Guard("/path/to/project")
    function_map = create_function_map(guard, agent_id="my-autogen-agent")

    # Register with an AutoGen agent
    assistant = autogen.AssistantAgent("assistant", llm_config=llm_config)
    user_proxy = autogen.UserProxyAgent(
        "user_proxy",
        function_map=function_map,
    )

Usage (AG2 / AutoGen 0.4+):
    from agent_context_guard import Guard
    from agent_context_guard.adapters.autogen import register_guard_tools

    guard = Guard("/path/to/project")
    register_guard_tools(guard, assistant, user_proxy, agent_id="my-agent")

Requirements:
    pip install agent-context-guard[autogen]
    (installs pyautogen >= 0.2 or ag2)
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from agent_context_guard.guard import Guard

logger = logging.getLogger(__name__)


# ── Function Map (AutoGen 0.2.x) ─────────────────────────────────────────────

def create_function_map(
    guard: Guard,
    agent_id: str = "autogen-agent",
) -> dict[str, Callable[..., str]]:
    """Create an AutoGen function_map dict for guard operations.

    The returned dict maps function names to callable handlers, suitable
    for passing to ``UserProxyAgent(function_map=...)``.

    Args:
        guard: An initialized Guard instance.
        agent_id: Identity for policy evaluation and audit logging.

    Returns:
        A dict mapping function names to handler callables.
    """

    def read_protected_file(file_path: str) -> str:
        """Read a cryptographically verified protected markdown file."""
        logger.debug("AutoGen read_protected_file: %s", file_path)
        try:
            return guard.read(file_path, agent_id=agent_id)
        except Exception as exc:
            logger.warning("AutoGen read failed for %s: %s", file_path, exc)
            return json.dumps({"error": type(exc).__name__, "message": str(exc)})

    def propose_file_update(
        file_path: str,
        new_content: str,
        justification: str = "",
    ) -> str:
        """Propose a change to a protected file for human review."""
        logger.debug("AutoGen propose_file_update: %s", file_path)
        try:
            proposal_id = guard.propose(
                file_path,
                new_content,
                agent_id=agent_id,
                justification=justification,
            )
            return json.dumps({
                "proposal_id": proposal_id,
                "message": "Proposal submitted for human review.",
            })
        except Exception as exc:
            logger.warning("AutoGen propose failed for %s: %s", file_path, exc)
            return json.dumps({"error": type(exc).__name__, "message": str(exc)})

    def get_file_status(file_path: str) -> str:
        """Get the protection status of a file."""
        logger.debug("AutoGen get_file_status: %s", file_path)
        try:
            status = guard.status(file_path)
            return json.dumps(status)
        except Exception as exc:
            logger.warning("AutoGen status failed for %s: %s", file_path, exc)
            return json.dumps({"error": type(exc).__name__, "message": str(exc)})

    return {
        "read_protected_file": read_protected_file,
        "propose_file_update": propose_file_update,
        "get_file_status": get_file_status,
    }


# ── Tool Descriptions (for LLM function calling) ─────────────────────────────

TOOL_DESCRIPTIONS: list[dict[str, Any]] = [
    {
        "name": "read_protected_file",
        "description": (
            "Read a cryptographically verified protected markdown file. "
            "Content is verified against its sealed hash and HMAC signature."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the protected markdown file.",
                },
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "propose_file_update",
        "description": (
            "Propose a change to a protected markdown file for human review. "
            "Only humans can approve proposals."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file."},
                "new_content": {"type": "string", "description": "Proposed new content."},
                "justification": {"type": "string", "description": "Reason for the change."},
            },
            "required": ["file_path", "new_content"],
        },
    },
    {
        "name": "get_file_status",
        "description": "Get the protection status of a file.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file."},
            },
            "required": ["file_path"],
        },
    },
]


# ── AG2 / AutoGen 0.4+ Registration ──────────────────────────────────────────

def register_guard_tools(
    guard: Guard,
    assistant: Any,
    executor: Any,
    agent_id: str = "autogen-agent",
) -> None:
    """Register guard tools with AG2 / AutoGen 0.4+ agents.

    Uses the ``register_for_llm`` and ``register_for_execution`` pattern
    introduced in newer AutoGen versions.

    Args:
        guard: An initialized Guard instance.
        assistant: The AssistantAgent (or similar) that calls tools.
        executor: The UserProxyAgent (or similar) that executes tools.
        agent_id: Identity for policy evaluation and audit logging.

    Raises:
        ImportError: If AutoGen is not installed.
        AttributeError: If the agents don't support tool registration.
    """
    function_map = create_function_map(guard, agent_id=agent_id)

    # Register each tool with the assistant (LLM-facing) and executor
    for tool_desc in TOOL_DESCRIPTIONS:
        name = tool_desc["name"]
        func = function_map[name]

        # AG2 pattern: register_for_llm on assistant, register_for_execution on executor
        try:
            assistant.register_for_llm(
                name=name,
                description=tool_desc["description"],
            )(func)

            executor.register_for_execution(name=name)(func)

            logger.debug("Registered AG2 tool: %s", name)

        except AttributeError:
            # Fall back to older AutoGen pattern if register_for_llm doesn't exist
            logger.warning(
                "Agent does not support register_for_llm. "
                "Use create_function_map() for AutoGen 0.2.x instead."
            )
            raise

    logger.info(
        "Registered %d guard tools with AutoGen agents", len(TOOL_DESCRIPTIONS)
    )
