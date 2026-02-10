"""Edit Sessions: human edit workflow for protected files.

Humans must be able to edit protected files even while an agent is running,
but only through explicit, privileged actions.

Flow:
  1. Verify interactive TTY
  2. Lock file (agent access paused)
  3. Create temp working copy
  4. Launch $EDITOR
  5. On exit: compute diff, prompt for confirmation
  6. Seal new version
  7. Unlock file
"""

from __future__ import annotations

import difflib
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from agent_context_guard.core.audit import AuditLogger
from agent_context_guard.core.constants import DEFAULT_EDITOR, STATE_ACTIVE
from agent_context_guard.core.exceptions import EditSessionError
from agent_context_guard.core.inventory import Inventory
from agent_context_guard.core.runtime import RuntimeGuard, get_active_guard
from agent_context_guard.core.seal import seal_file

logger = logging.getLogger(__name__)


def is_interactive_tty() -> bool:
    """Check if stdin is an interactive terminal."""
    return hasattr(sys.stdin, "isatty") and sys.stdin.isatty()


class EditSession:
    """Manages a human edit session for a single protected file."""

    def __init__(
        self,
        file_path: str,
        root: Path,
        *,
        author: str = "human",
        editor: str | None = None,
    ) -> None:
        self._file_path = file_path
        self._root = root
        self._author = author
        self._editor = editor or os.environ.get("EDITOR", DEFAULT_EDITOR)
        self._inventory = Inventory(root)
        self._audit = AuditLogger(root)
        self._guard: RuntimeGuard | None = None
        self._original_content: str = ""

    def execute(self) -> bool:
        """Run the full edit session. Returns True if changes were saved.

        Raises EditSessionError on failures.
        """
        # M4: Enforce interactive TTY — prevents programmatic edit by agents
        if not is_interactive_tty():
            raise EditSessionError(
                "Edit sessions require an interactive terminal (TTY). "
                "Non-interactive processes cannot edit protected files. "
                "This prevents agents from bypassing the proposal workflow."
            )

        path = Path(self._file_path)
        if not path.exists():
            raise EditSessionError(f"File does not exist: {self._file_path}")

        # Try to get active guard for locking
        try:
            self._guard = get_active_guard()
        except Exception:
            self._guard = None

        # Lock file if guard is active
        if self._guard:
            self._guard.lock_file(self._file_path)
            logger.info("Locked file for editing: %s", self._file_path)

        try:
            return self._do_edit(path)
        finally:
            if self._guard:
                self._guard.unlock_file(self._file_path)
                logger.info("Unlocked file: %s", self._file_path)

    def _do_edit(self, path: Path) -> bool:
        self._original_content = path.read_text(encoding="utf-8")
        self._audit.log_edit_session(self._file_path, self._author, "started")

        # Create temp copy
        suffix = path.suffix or ".md"
        fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix="acg_edit_")
        os.close(fd)
        tmp = Path(tmp_path)
        try:
            tmp.write_text(self._original_content, encoding="utf-8")

            # Launch editor
            try:
                result = subprocess.run([self._editor, str(tmp)])
                if result.returncode != 0:
                    raise EditSessionError(f"Editor exited with code {result.returncode}")
            except FileNotFoundError:
                raise EditSessionError(
                    f"Editor '{self._editor}' not found. Set $EDITOR or pass --editor."
                )

            new_content = tmp.read_text(encoding="utf-8")

            # Compute diff
            if new_content == self._original_content:
                self._audit.log_edit_session(self._file_path, self._author, "no_changes")
                return False

            return self._finalize(path, new_content)
        finally:
            tmp.unlink(missing_ok=True)

    def _finalize(self, path: Path, new_content: str) -> bool:
        """Show diff, confirm, write atomically, and re-seal."""
        diff_lines = list(difflib.unified_diff(
            self._original_content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=f"a/{path.name}",
            tofile=f"b/{path.name}",
        ))

        # Atomic write: temp file in same dir → rename
        fd, tmp_write = tempfile.mkstemp(
            dir=path.parent, suffix=".tmp", prefix="acg_save_"
        )
        try:
            with open(fd, "w", encoding="utf-8") as f:
                f.write(new_content)
            Path(tmp_write).replace(path)
        except Exception:
            Path(tmp_write).unlink(missing_ok=True)
            raise

        # Re-seal
        next_ver = self._inventory.next_version(self._file_path)
        record = seal_file(
            path,
            self._root,
            author=self._author,
            version=next_ver,
            state=STATE_ACTIVE,
        )
        self._inventory.add_record(record)
        self._audit.log_edit_session(
            self._file_path, self._author, "saved",
            detail=f"Version {next_ver}, {len(diff_lines)} diff lines",
        )
        self._audit.log_seal(self._file_path, self._author, next_ver)
        logger.info("Edit saved: %s → v%d", self._file_path, next_ver)
        return True

    @property
    def diff_text(self) -> str:
        """Return the diff for the last edit (after execute)."""
        path = Path(self._file_path)
        if not path.exists():
            return ""
        current = path.read_text(encoding="utf-8")
        lines = list(difflib.unified_diff(
            self._original_content.splitlines(keepends=True),
            current.splitlines(keepends=True),
            fromfile=f"a/{path.name}",
            tofile=f"b/{path.name}",
        ))
        return "".join(lines)
