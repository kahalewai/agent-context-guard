"""
agent_context_guard/adapters/llamaindex.py — LlamaIndex reader integration.

Provides a LlamaIndex-compatible BaseReader that loads protected markdown
files through agent-context-guard's verification pipeline.

Usage:
    from agent_context_guard import Guard
    from agent_context_guard.adapters.llamaindex import ProtectedMarkdownReader

    guard = Guard("/path/to/project")
    reader = ProtectedMarkdownReader(guard=guard, agent_id="my-llama-agent")

    # Load a single file
    documents = reader.load_data(file_path="prompts/persona.md")

    # Load all protected files
    documents = reader.load_data()

Requirements:
    pip install agent-context-guard[llamaindex]
    (installs llama-index-core >= 0.10)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from agent_context_guard.guard import Guard

logger = logging.getLogger(__name__)

# Defer the llama_index import to runtime so the module can be imported
# without llama-index installed.
try:
    from llama_index.core import Document
    from llama_index.core.readers.base import BaseReader

    _LLAMAINDEX_AVAILABLE = True
except ImportError:
    _LLAMAINDEX_AVAILABLE = False

    # Stub types for import-time class definition
    class BaseReader:  # type: ignore[no-redef]
        pass

    class Document:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            pass


def _require_llamaindex() -> None:
    """Raise a clear error if llama-index-core is not installed."""
    if not _LLAMAINDEX_AVAILABLE:
        raise ImportError(
            "The LlamaIndex adapter requires 'llama-index-core'. "
            "Install it with: pip install agent-context-guard[llamaindex]"
        )


class ProtectedMarkdownReader(BaseReader):
    """LlamaIndex reader for protected markdown files.

    Reads files through Guard.read(), which performs cryptographic
    verification, policy checking, and audit logging before returning
    the content.

    Can load a single specified file or all files registered in the
    guard's inventory.

    Args:
        guard: An initialized Guard instance.
        agent_id: Identity of the calling agent (for policy and audit).
    """

    def __init__(
        self,
        guard: Guard,
        agent_id: str = "llamaindex-agent",
    ) -> None:
        _require_llamaindex()
        self.guard = guard
        self.agent_id = agent_id

    def load_data(
        self,
        file_path: str | Path | None = None,
        **kwargs: Any,
    ) -> list[Document]:
        """Load protected documents.

        If ``file_path`` is provided, loads that single file. Otherwise,
        loads all protected files in the guard's inventory.

        Args:
            file_path: Optional path to a specific file. If None, loads all.

        Returns:
            A list of LlamaIndex Document objects with verified content.

        Raises:
            SealIntegrityError: If any file has been tampered with (single file mode).
            PolicyDeniedError: If the policy denies the read (single file mode).
        """
        if file_path is not None:
            return self._load_single(str(file_path))
        return self._load_all()

    def _load_single(self, file_path: str) -> list[Document]:
        """Load a single protected file with full verification."""
        content = self.guard.read(file_path, agent_id=self.agent_id)
        status = self.guard.status(file_path)

        metadata = {
            "file_path": file_path,
            "loader": "agent-context-guard",
            **status,
        }

        logger.debug(
            "Loaded protected document: %s (v%s)",
            file_path,
            status.get("version"),
        )

        return [Document(text=content, metadata=metadata)]

    def _load_all(self) -> list[Document]:
        """Load all protected files, skipping any that fail verification."""
        documents: list[Document] = []

        for file_path in self.guard.inventory.list_protected_files():
            try:
                docs = self._load_single(file_path)
                documents.extend(docs)
            except Exception as exc:
                # Log and skip — allow partial results for bulk loading
                logger.warning(
                    "Failed to load protected file %s: %s", file_path, exc
                )

        logger.info(
            "Loaded %d protected document(s) from inventory", len(documents)
        )
        return documents
