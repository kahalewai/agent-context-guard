"""Framework adapters for agent-context-guard.

Adapters are thin, optional integrations that call Layer 1 APIs only.
They do NOT implement security logic — all enforcement happens in the core.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_context_guard.api import get_status, propose_update, read_md


class BaseAdapter:
    """Base class for framework adapters.

    Subclasses override ``load_document`` and optionally ``on_propose``
    to integrate with specific agent frameworks.
    """

    def __init__(self, root: Path | str | None = None, agent_id: str = "adapter") -> None:
        self._root = Path(root) if root else None
        self._agent_id = agent_id

    def load(self, file_path: str | Path) -> str:
        """Load a protected markdown file, returning its content."""
        return read_md(file_path, agent_id=self._agent_id, root=self._root)

    def propose(
        self,
        file_path: str | Path,
        new_content: str,
        justification: str = "",
    ) -> str:
        """Submit a proposal to update a protected file."""
        return propose_update(
            file_path,
            new_content,
            agent_id=self._agent_id,
            justification=justification,
            root=self._root,
        )

    def status(self, file_path: str | Path) -> dict[str, Any]:
        """Get the protection status of a file."""
        return get_status(file_path, root=self._root)


class LangChainAdapter(BaseAdapter):
    """Adapter for LangChain document loaders.

    Usage::

        from agent_context_guard.adapters.base import LangChainAdapter

        adapter = LangChainAdapter(agent_id="my-langchain-agent")
        content = adapter.load("prompts/system.md")

    For a full LangChain DocumentLoader integration, wrap this in a
    custom loader class that returns LangChain Document objects.
    """

    def __init__(self, agent_id: str = "langchain-agent", **kwargs: Any) -> None:
        super().__init__(agent_id=agent_id, **kwargs)

    def load_document(self, file_path: str | Path) -> dict[str, Any]:
        """Load a file and return a dict compatible with LangChain Document."""
        content = self.load(file_path)
        status_info = self.status(file_path)
        return {
            "page_content": content,
            "metadata": {
                "source": str(file_path),
                "protected": status_info.get("protected", False),
                "version": status_info.get("version"),
                "state": status_info.get("state"),
            },
        }
