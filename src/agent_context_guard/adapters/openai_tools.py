"""
agent_context_guard/adapters/openai_tools.py — OpenAI function-calling integration.

Provides tool definitions and handler functions compatible with OpenAI's
function-calling / tool-use API. These can be passed directly to the
OpenAI client's ``tools`` parameter and dispatched through a standard
tool-call handler.

Usage:
    from agent_context_guard import Guard
    from agent_context_guard.adapters.openai_tools import (
        create_openai_tools,
        handle_tool_call,
    )

    guard = Guard("/path/to/project")
    tools, handler = create_openai_tools(guard, agent_id="my-openai-agent")

    # Pass tool definitions to OpenAI
    response = client.chat.completions.create(
        model="gpt-4",
        messages=messages,
        tools=tools,
    )

    # Handle tool calls from the response
    for tool_call in response.choices[0].message.tool_calls:
        result = handler(tool_call.function.name, tool_call.function.arguments)

Requirements:
    No additional dependencies — this adapter produces plain dicts and
    functions compatible with the OpenAI API format.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from agent_context_guard.guard import Guard

logger = logging.getLogger(__name__)

# ── Tool Schema Definitions ───────────────────────────────────────────────────
# These follow the OpenAI function-calling JSON schema format exactly.

_READ_TOOL_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "read_protected_file",
        "description": (
            "Read a cryptographically verified protected markdown file. "
            "The file content is verified against its sealed hash and HMAC "
            "signature before being returned. The access is policy-checked "
            "and logged to a tamper-evident audit trail."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the protected markdown file to read.",
                },
            },
            "required": ["file_path"],
            "additionalProperties": False,
        },
    },
}

_PROPOSE_TOOL_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "propose_file_update",
        "description": (
            "Propose a change to a protected markdown file for human review. "
            "The proposal is stored as a unified diff. Only humans can approve "
            "proposals — agents cannot approve their own changes."
        ),
        "parameters": {
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
            "additionalProperties": False,
        },
    },
}

_STATUS_TOOL_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "get_file_status",
        "description": (
            "Get the protection status of a file, including its current "
            "state, version, and number of pending proposals."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file to check.",
                },
            },
            "required": ["file_path"],
            "additionalProperties": False,
        },
    },
}


# ── Factory Function ──────────────────────────────────────────────────────────

def create_openai_tools(
    guard: Guard,
    agent_id: str = "openai-agent",
) -> tuple[list[dict[str, Any]], Callable[[str, str], str]]:
    """Create OpenAI-compatible tool definitions and a dispatch handler.

    Returns a tuple of:
        1. A list of tool schema dicts to pass to ``tools=`` in the API call
        2. A handler function that dispatches tool calls by name

    The handler accepts (function_name, arguments_json) and returns a
    string result suitable for passing back as a tool response.

    Args:
        guard: An initialized Guard instance.
        agent_id: Identity for policy evaluation and audit logging.

    Returns:
        (tool_schemas, handler_function)

    Example::

        tools, handler = create_openai_tools(guard)

        # In your tool-call dispatch loop:
        result = handler(
            tool_call.function.name,
            tool_call.function.arguments,
        )
    """
    # The tool schemas are static — return copies to prevent mutation
    tool_schemas = [
        _READ_TOOL_SCHEMA.copy(),
        _PROPOSE_TOOL_SCHEMA.copy(),
        _STATUS_TOOL_SCHEMA.copy(),
    ]

    def handler(function_name: str, arguments_json: str) -> str:
        """Dispatch a tool call to the appropriate guard operation.

        Args:
            function_name: The name of the function to call.
            arguments_json: JSON string of function arguments.

        Returns:
            A string result to return as the tool response.

        Raises:
            ValueError: If the function name is not recognized.
        """
        try:
            args = json.loads(arguments_json)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse tool arguments: %s", exc)
            return json.dumps({"error": f"Invalid JSON arguments: {exc}"})

        logger.debug("OpenAI tool call: %s(%s)", function_name, args)

        try:
            if function_name == "read_protected_file":
                content = guard.read(args["file_path"], agent_id=agent_id)
                return content

            elif function_name == "propose_file_update":
                proposal_id = guard.propose(
                    args["file_path"],
                    args["new_content"],
                    agent_id=agent_id,
                    justification=args.get("justification", ""),
                )
                return json.dumps({
                    "proposal_id": proposal_id,
                    "message": "Proposal submitted for human review.",
                })

            elif function_name == "get_file_status":
                status = guard.status(args["file_path"])
                return json.dumps(status)

            else:
                raise ValueError(f"Unknown function: {function_name}")

        except Exception as exc:
            # Return errors as structured JSON so the LLM can understand
            # what went wrong and potentially recover.
            logger.warning(
                "Tool call %s failed: %s", function_name, exc
            )
            return json.dumps({
                "error": type(exc).__name__,
                "message": str(exc),
            })

    return tool_schemas, handler
