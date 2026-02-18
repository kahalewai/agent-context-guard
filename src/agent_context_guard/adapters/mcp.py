"""
agent_context_guard/adapters/mcp.py — Model Context Protocol integration.

Provides MCP-compatible tool definitions and handlers for agent-context-guard.
The Model Context Protocol (MCP) is an open standard for connecting AI models
to external data sources and tools.

This adapter can be used in two ways:

1. **Tool definitions only** — Get MCP tool schemas and a handler function
   to integrate into your own MCP server implementation.

2. **Standalone MCP server** — Run a complete MCP server that exposes
   guard operations as tools (requires the ``mcp`` package).

Usage (tool definitions):
    from agent_context_guard import Guard
    from agent_context_guard.adapters.mcp import create_mcp_tools

    guard = Guard("/path/to/project")
    tools, handler = create_mcp_tools(guard, agent_id="mcp-agent")

    # tools is a list of MCP tool definition dicts
    # handler dispatches tool calls: handler("read_protected_file", {"file_path": "..."})

Usage (standalone server — requires 'mcp' package):
    from agent_context_guard import Guard
    from agent_context_guard.adapters.mcp import create_mcp_server

    guard = Guard("/path/to/project")
    server = create_mcp_server(guard)
    server.run()

Requirements:
    Tool definitions: No additional dependencies.
    Standalone server: pip install agent-context-guard[mcp]
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from agent_context_guard.guard import Guard

logger = logging.getLogger(__name__)

# ── MCP Tool Definitions ─────────────────────────────────────────────────────
# These follow the MCP tool schema format. Each tool has a name,
# description, and inputSchema (JSON Schema for parameters).

_READ_TOOL: dict[str, Any] = {
    "name": "read_protected_file",
    "description": (
        "Read a cryptographically verified protected markdown file. "
        "The file content is verified against its sealed hash and HMAC "
        "signature before being returned. The access is policy-checked "
        "and logged to a tamper-evident audit trail."
    ),
    "inputSchema": {
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

_PROPOSE_TOOL: dict[str, Any] = {
    "name": "propose_file_update",
    "description": (
        "Propose a change to a protected markdown file for human review. "
        "The proposal is stored as a unified diff. Only humans can approve "
        "proposals — agents cannot approve their own changes."
    ),
    "inputSchema": {
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

_STATUS_TOOL: dict[str, Any] = {
    "name": "get_file_status",
    "description": (
        "Get the protection status of a file, including whether it is "
        "protected, its current state, version, and pending proposals."
    ),
    "inputSchema": {
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

_VERIFY_TOOL: dict[str, Any] = {
    "name": "verify_file_integrity",
    "description": (
        "Verify the cryptographic integrity of a protected file. "
        "Returns whether the file passes hash and signature verification."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Path to the protected file to verify.",
            },
        },
        "required": ["file_path"],
    },
}


# ── Factory Function ──────────────────────────────────────────────────────────

def create_mcp_tools(
    guard: Guard,
    agent_id: str = "mcp-agent",
) -> tuple[list[dict[str, Any]], Callable[[str, dict[str, Any]], str]]:
    """Create MCP tool definitions and a dispatch handler.

    Returns a tuple of:
        1. A list of MCP tool definition dicts
        2. A handler function: (tool_name, arguments_dict) -> result_string

    Args:
        guard: An initialized Guard instance.
        agent_id: Identity for policy evaluation and audit logging.

    Returns:
        (tool_definitions, handler_function)
    """
    tool_definitions = [
        _READ_TOOL.copy(),
        _PROPOSE_TOOL.copy(),
        _STATUS_TOOL.copy(),
        _VERIFY_TOOL.copy(),
    ]

    def handler(tool_name: str, arguments: dict[str, Any]) -> str:
        """Dispatch an MCP tool call to the appropriate guard operation.

        Args:
            tool_name: The name of the tool being called.
            arguments: The input arguments dict.

        Returns:
            A string result for the tool response.
        """
        logger.debug("MCP tool call: %s(%s)", tool_name, arguments)

        try:
            if tool_name == "read_protected_file":
                return guard.read(arguments["file_path"], agent_id=agent_id)

            elif tool_name == "propose_file_update":
                proposal_id = guard.propose(
                    arguments["file_path"],
                    arguments["new_content"],
                    agent_id=agent_id,
                    justification=arguments.get("justification", ""),
                )
                return json.dumps({
                    "proposal_id": proposal_id,
                    "message": "Proposal submitted for human review.",
                })

            elif tool_name == "get_file_status":
                return json.dumps(guard.status(arguments["file_path"]))

            elif tool_name == "verify_file_integrity":
                try:
                    guard.verify_file(arguments["file_path"])
                    return json.dumps({"verified": True, "message": "File integrity verified."})
                except Exception as exc:
                    return json.dumps({"verified": False, "message": str(exc)})

            else:
                raise ValueError(f"Unknown MCP tool: {tool_name}")

        except Exception as exc:
            logger.warning("MCP tool %s failed: %s", tool_name, exc)
            return json.dumps({
                "error": type(exc).__name__,
                "message": str(exc),
            })

    return tool_definitions, handler
