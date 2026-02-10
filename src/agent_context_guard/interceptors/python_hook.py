"""Python-level filesystem interception via monkey-patching.

This module provides a zero-code-change interception layer that wraps
Python's built-in ``open()`` and ``pathlib.Path.read_text`` to enforce
guard policies on protected markdown files.

This is the Python-native equivalent of FUSE or LD_PRELOAD interception.
It is lighter-weight and does not require root or kernel modules.

Usage::

    from agent_context_guard.interceptors.python_hook import install, uninstall

    install(root=Path("."))
    # ... agent code runs with intercepted file access ...
    uninstall()
"""

from __future__ import annotations

import builtins
import logging
from pathlib import Path
from typing import Any

from agent_context_guard.core.constants import MARKDOWN_EXTENSIONS
from agent_context_guard.core.runtime import get_active_guard
from agent_context_guard.core.exceptions import RuntimeNotActiveError

logger = logging.getLogger(__name__)

_original_open = builtins.open
_original_read_text = Path.read_text
_installed = False


def _is_protected_markdown(filepath: str | Path) -> bool:
    """Check if a path looks like a protected markdown file."""
    p = Path(filepath)
    return p.suffix.lower() in MARKDOWN_EXTENSIONS


def _guarded_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
    """Replacement for built-in open() that intercepts protected file access."""
    filepath = str(file) if not isinstance(file, (str, Path)) else file
    str_path = str(Path(filepath).resolve()) if isinstance(filepath, (str, Path)) else None

    if str_path and _is_protected_markdown(str_path):
        try:
            guard = get_active_guard()
        except RuntimeNotActiveError:
            return _original_open(file, mode, *args, **kwargs)

        # Block writes to protected files
        if any(c in mode for c in ("w", "a", "x", "+")):
            if guard.inventory.has_file(str_path):
                guard.block_write(str_path, actor="intercepted-process")
                # block_write always raises, so this line is unreachable

        # For reads, verify through guard
        if "r" in mode or mode == "":
            if guard.inventory.has_file(str_path):
                content = guard.read_file(str_path, actor="intercepted-process")
                import io
                if "b" in mode:
                    return io.BytesIO(content.encode("utf-8"))
                return io.StringIO(content)

    return _original_open(file, mode, *args, **kwargs)


def _guarded_read_text(self: Path, encoding: str = "utf-8", errors: str | None = None) -> str:
    """Replacement for Path.read_text() that intercepts protected file access."""
    str_path = str(self.resolve())

    if _is_protected_markdown(str_path):
        try:
            guard = get_active_guard()
            if guard.inventory.has_file(str_path):
                return guard.read_file(str_path, actor="intercepted-process")
        except RuntimeNotActiveError:
            pass

    return _original_read_text(self, encoding=encoding, errors=errors)


def install(root: Path | None = None) -> None:
    """Install the Python file-access interceptor.

    After calling this, all ``open()`` and ``Path.read_text()`` calls
    for protected markdown files will be routed through the guard.
    """
    global _installed
    if _installed:
        logger.debug("Interceptor already installed.")
        return

    builtins.open = _guarded_open  # type: ignore[assignment]
    Path.read_text = _guarded_read_text  # type: ignore[assignment]
    _installed = True
    logger.info("Python file interceptor installed.")


def uninstall() -> None:
    """Remove the Python file-access interceptor, restoring originals."""
    global _installed
    if not _installed:
        return

    builtins.open = _original_open  # type: ignore[assignment]
    Path.read_text = _original_read_text  # type: ignore[method-assign]
    _installed = False
    logger.info("Python file interceptor uninstalled.")


def is_installed() -> bool:
    return _installed
