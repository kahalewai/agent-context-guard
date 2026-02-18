"""
agent_context_guard/adapters/anthropic_tools.py — Anthropic tool-use integration.

Provides tool definitions and handler functions compatible with Anthropic's
tool-use API (Claude function calling). These can be passed directly to the
Anthropic client's ``tools`` parameter.

Usage:
    from agent_context_guard import Guard
    from agent_context_guard.adapters.anthropic_tools import (
        create_anthropic_tools,
        handle_tool_use,
    )

    guard = Guard("/path/to/project")
    tools, handler = create_anthropic_tools(guard, agent_id="my-claude-agent")

    # Pass tool definitions to Anthropic
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        messages=messages,
        tools=tools,
    )

    # Handle tool use blocks from the response
    for block in response.content:
        if block.type == "tool_use":
            result = handler(block.name, block.input)

Requirements:
    No additional dependencies — this adapter produces plain dicts and
    functions compatible with the Anthropic API format.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from agent_context_guard.guard import Guard

logger = logging.getLogger(__name__)

# ── Tool Schema Definitions ───────────────────────────────────────────────────
# These follow the Anthropic tool-use JSON schema format exactly.
# Key difference from OpenAI: Anthropic uses a flat structure with
# "name", "description", and "input_schema" at the top level.

_READ_TOOL_SCHEMA: dict[str, Any] = {
    "name": "read_protected_file",
    "description": (
        "Read a cryptographically verified protected markdown file. "
        "The file content is verified against its sealed hash and HMAC "
        "signature before being returned. The access is policy-checked "
        "and logged to a tamper-evident audit trail."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Path to the protected markdown file to read.",
            },
        },
        "required": ["file_path"],
    },
}

_PROPOSE_TOOL_SCHEMA: dict[str, Any] = {
    "name": "propose_file_update",
    "description": (
        "Propose a change to a protected markdown file for human review. "
        "The proposal is stored as a unified diff. Only humans can approve "
        "proposals — agents cannot approve their own changes."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Path to the protected file to update.",
            },
            "new_content": {
                "type": "string",
                "description": "The complete proposed new content for the file.",
            },
            "justification": {
                "type": "string",
                "description": "Reason for the proposed change.",
            },
        },
        "required": ["file_path", "new_content"],
    },
}

_STATUS_TOOL_SCHEMA: dict[str, Any] = {
    "name": "get_file_status",
    "description": (
        "Get the protection status of a file, including its current "
        "state, version, and number of pending proposals."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Path to the file to check.",
            },
        },
        "required": ["file_path"],
    },
}


# ── Factory Function ──────────────────────────────────────────────────────────

def create_anthropic_tools(
    guard: Guard,
    agent_id: str = "anthropic-agent",
) -> tuple[list[dict[str, Any]], Callable[[str, dict[str, Any]], str]]:
    """Create Anthropic-compatible tool definitions and a dispatch handler.

    Returns a tuple of:
        1. A list of tool schema dicts to pass to ``tools=`` in the API call
        2. A handler function that dispatches tool-use blocks by name

    The handler accepts (tool_name, input_dict) and returns a string
    result suitable for passing back as a tool_result content block.

    Args:
        guard: An initialized Guard instance.
        agent_id: Identity for policy evaluation and audit logging.

    Returns:
        (tool_schemas, handler_function)

    Example::

        tools, handler = create_anthropic_tools(guard)

        # In your tool-use dispatch loop:
        for block in response.content:
            if block.type == "tool_use":
                result = handler(block.name, block.input)
    """
    # Return copies of the schemas to prevent external mutation
    tool_schemas = [
        _READ_TOOL_SCHEMA.copy(),
        _PROPOSE_TOOL_SCHEMA.copy(),
        _STATUS_TOOL_SCHEMA.copy(),
    ]

    def handler(tool_name: str, tool_input: dict[str, Any]) -> str:
        """Dispatch a tool-use block to the appropriate guard operation.

        Args:
            tool_name: The name of the tool being called.
            tool_input: The input dictionary from the tool-use block.

        Returns:
            A string result to return in the tool_result block.
        """
        logger.debug("Anthropic tool call: %s(%s)", tool_name, tool_input)

        try:
            if tool_name == "read_protected_file":
                content = guard.read(
                    tool_input["file_path"], agent_id=agent_id
                )
                return content

            elif tool_name == "propose_file_update":
                proposal_id = guard.propose(
                    tool_input["file_path"],
                    tool_input["new_content"],
                    agent_id=agent_id,
                    justification=tool_input.get("justification", ""),
                )
                return json.dumps({
                    "proposal_id": proposal_id,
                    "message": "Proposal submitted for human review.",
                })

            elif tool_name == "get_file_status":
                status = guard.status(tool_input["file_path"])
                return json.dumps(status)

            else:
                raise ValueError(f"Unknown tool: {tool_name}")

        except Exception as exc:
            # Return structured error so Claude can understand and recover
            logger.warning("Tool call %s failed: %s", tool_name, exc)
            return json.dumps({
                "error": type(exc).__name__,
                "message": str(exc),
            })

    return tool_schemas, handler
