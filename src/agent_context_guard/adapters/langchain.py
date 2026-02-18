"""
agent_context_guard/adapters/langchain.py — LangChain document loader integration.

Provides a LangChain-compatible document loader that reads protected markdown
files through agent-context-guard's verification pipeline. Every document
returned has been cryptographically verified and policy-checked.

Usage:
    from agent_context_guard import Guard
    from agent_context_guard.adapters.langchain import ProtectedMarkdownLoader

    guard = Guard("/path/to/project")

    # Load a single file
    loader = ProtectedMarkdownLoader(
        file_path="prompts/persona.md",
        guard=guard,
        agent_id="my-langchain-agent",
    )
    docs = loader.load()

    # Load multiple files
    loader = ProtectedDirectoryLoader(
        guard=guard,
        agent_id="my-langchain-agent",
    )
    docs = loader.load()

Requirements:
    pip install agent-context-guard[langchain]
    (installs langchain-core >= 0.1)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterator

from agent_context_guard.guard import Guard

logger = logging.getLogger(__name__)

# Defer the langchain import to runtime so the adapter module can be
# imported without langchain installed (for inspection, help text, etc.).
# The actual classes are created only when instantiated.

try:
    from langchain_core.documents import Document
    from langchain_core.document_loaders import BaseLoader

    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False

    # Provide stub types so the class definition doesn't fail at import
    # time. Instantiation will raise a clear error instead.
    class BaseLoader:  # type: ignore[no-redef]
        pass

    class Document:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            pass


def _require_langchain() -> None:
    """Raise a clear error if langchain-core is not installed."""
    if not _LANGCHAIN_AVAILABLE:
        raise ImportError(
            "The LangChain adapter requires 'langchain-core'. "
            "Install it with: pip install agent-context-guard[langchain]"
        )


class ProtectedMarkdownLoader(BaseLoader):
    """LangChain document loader for a single protected markdown file.

    Reads the file through Guard.read(), which performs cryptographic
    verification, policy checking, and audit logging before returning
    the content.

    The returned Document includes guard metadata (protection state,
    version, content hash) in its metadata dict.

    Args:
        file_path: Path to the protected markdown file.
        guard: An initialized Guard instance.
        agent_id: Identity of the calling agent (for policy and audit).
    """

    def __init__(
        self,
        file_path: str | Path,
        guard: Guard,
        agent_id: str = "langchain-agent",
    ) -> None:
        _require_langchain()
        self.file_path = str(file_path)
        self.guard = guard
        self.agent_id = agent_id

    def load(self) -> list[Document]:
        """Load and return the protected document.

        Returns:
            A single-element list containing a LangChain Document with
            verified content and guard metadata.

        Raises:
            SealIntegrityError: If the file has been tampered with.
            PolicyDeniedError: If the policy denies the read.
            SealNotFoundError: If the file is not protected.
        """
        # Read through the guard — this verifies integrity and enforces policy
        content = self.guard.read(self.file_path, agent_id=self.agent_id)

        # Attach guard metadata to the document
        status = self.guard.status(self.file_path)
        metadata = {
            "source": self.file_path,
            "loader": "agent-context-guard",
            **status,
        }

        logger.debug(
            "Loaded protected document: %s (v%s)",
            self.file_path,
            status.get("version"),
        )

        return [Document(page_content=content, metadata=metadata)]

    def lazy_load(self) -> Iterator[Document]:
        """Lazy load — yields a single document (same as load for single files)."""
        yield from self.load()


class ProtectedDirectoryLoader(BaseLoader):
    """LangChain document loader for all protected files in a project.

    Iterates over every file registered in the guard's inventory and
    loads each one through the verification pipeline.

    Args:
        guard: An initialized Guard instance.
        agent_id: Identity of the calling agent (for policy and audit).
    """

    def __init__(
        self,
        guard: Guard,
        agent_id: str = "langchain-agent",
    ) -> None:
        _require_langchain()
        self.guard = guard
        self.agent_id = agent_id

    def load(self) -> list[Document]:
        """Load all protected documents.

        Files that fail verification are logged and skipped rather than
        raising an exception, allowing partial results.

        Returns:
            A list of LangChain Documents for all successfully loaded files.
        """
        documents: list[Document] = []
        for file_path in self.guard.inventory.list_protected_files():
            try:
                loader = ProtectedMarkdownLoader(
                    file_path=file_path,
                    guard=self.guard,
                    agent_id=self.agent_id,
                )
                documents.extend(loader.load())
            except Exception as exc:
                # Log the failure but continue loading other files
                logger.warning(
                    "Failed to load protected file %s: %s", file_path, exc
                )
        return documents

    def lazy_load(self) -> Iterator[Document]:
        """Lazy load — yields documents one at a time."""
        for file_path in self.guard.inventory.list_protected_files():
            try:
                content = self.guard.read(file_path, agent_id=self.agent_id)
                status = self.guard.status(file_path)
                yield Document(
                    page_content=content,
                    metadata={"source": file_path, "loader": "agent-context-guard", **status},
                )
            except Exception as exc:
                logger.warning(
                    "Failed to load protected file %s: %s", file_path, exc
                )
