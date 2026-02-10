"""Runtime Guard: the core runtime protection engine.

Manages ephemeral keys, runtime policy enforcement, file access interception,
and the guarded subprocess lifecycle.
"""

from __future__ import annotations

import hashlib
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from agent_context_guard.core.audit import AuditLogger
from agent_context_guard.core.constants import (
    FERNET_KEY_ENV,
    FERNET_KEY_FD_ENV,
    STATE_ACTIVE,
    STATE_SEALED,
    locks_dir,
)
from agent_context_guard.core.exceptions import (
    FileLockedError,
    PolicyDeniedError,
    RuntimeAlreadyActiveError,
    RuntimeNotActiveError,
    SealIntegrityError,
)
from agent_context_guard.core.inventory import Inventory
from agent_context_guard.core.policy import PolicyContext, PolicyEngine
from agent_context_guard.core.seal import SealRecord, verify_seal, verify_and_read
from agent_context_guard.core.selfprotect import verify_all_metadata

logger = logging.getLogger(__name__)

# Module-level singleton — only one runtime per process
_active_guard: RuntimeGuard | None = None
_lock = threading.Lock()


def get_active_guard() -> RuntimeGuard:
    """Return the currently active RuntimeGuard, or raise."""
    if _active_guard is None:
        raise RuntimeNotActiveError("No active runtime guard.")
    return _active_guard


class RuntimeGuard:
    """Manages the guarded runtime lifecycle.

    On start:
      1. Generate ephemeral Fernet key (memory-only)
      2. Verify all sealed files
      3. Activate filesystem / API interception
      4. Run the agent subprocess

    On stop:
      1. Zero-out ephemeral key
      2. Release locks
      3. Flush audit log
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self._inventory = Inventory(root)
        self._policy = PolicyEngine(root)
        self._audit = AuditLogger(root)
        self._fernet_key: bytes | None = None
        self._fernet: Fernet | None = None
        self._active = False
        self._locked_files: set[str] = set()
        self._locks_dir = locks_dir(root)
        self._locks_dir.mkdir(parents=True, exist_ok=True)

    # ── Properties ────────────────────────────────────────────────────────

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def inventory(self) -> Inventory:
        return self._inventory

    @property
    def policy(self) -> PolicyEngine:
        return self._policy

    @property
    def audit(self) -> AuditLogger:
        return self._audit

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Activate the runtime guard."""
        global _active_guard
        with _lock:
            if self._active:
                raise RuntimeAlreadyActiveError("Guard is already active.")
            if _active_guard is not None:
                raise RuntimeAlreadyActiveError("Another guard is already active in this process.")

            # 1. Verify guard metadata integrity (inventory, policy)
            meta_failures = verify_all_metadata(self._root)
            if meta_failures:
                raise SealIntegrityError(
                    f"Guard metadata integrity check failed:\n"
                    + "\n".join(f"  • {f}" for f in meta_failures)
                )

            # 2. Generate ephemeral key
            self._fernet_key = Fernet.generate_key()
            self._fernet = Fernet(self._fernet_key)

            # 3. Verify all sealed files
            failures: list[str] = []
            for record in self._inventory.iter_active():
                try:
                    if not verify_seal(record, self._root):
                        failures.append(f"{record.file_path}: signature mismatch")
                except SealIntegrityError as exc:
                    failures.append(str(exc))
            if failures:
                self._fernet_key = None
                self._fernet = None
                raise SealIntegrityError(
                    f"Seal verification failed for {len(failures)} file(s):\n"
                    + "\n".join(f"  • {f}" for f in failures)
                )

            self._active = True
            _active_guard = self
            self._audit.log_runtime("guard_started", f"Protecting {self._inventory.file_count} file(s)")
            logger.info("Runtime guard started — %d file(s) protected", self._inventory.file_count)

    def stop(self) -> None:
        """Deactivate the runtime guard and zero out keys."""
        global _active_guard
        with _lock:
            if not self._active:
                return
            # Release file locks
            for fp in list(self._locked_files):
                self._unlock_file(fp)
            # Zero out key material
            if self._fernet_key:
                self._fernet_key = b"\x00" * len(self._fernet_key)
            self._fernet_key = None
            self._fernet = None
            self._active = False
            _active_guard = None
            self._audit.log_runtime("guard_stopped")
            logger.info("Runtime guard stopped.")

    def __enter__(self) -> RuntimeGuard:
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # ── File Access ───────────────────────────────────────────────────────

    def read_file(self, file_path: str, actor: str = "agent", actor_type: str = "agent") -> str:
        """Read a protected file through the guard.

        Enforces policy, checks seal integrity, and logs the access.
        """
        if not self._active:
            raise RuntimeNotActiveError("Cannot read files — guard is not active.")

        # Check lock
        if file_path in self._locked_files:
            self._audit.log_read(file_path, actor, allowed=False, detail="File is locked for editing")
            raise FileLockedError(f"File {file_path} is locked for human editing.")

        # Policy check
        try:
            record = self._inventory.get_active_record(file_path)
        except Exception:
            self._audit.log_read(file_path, actor, allowed=False, detail="Not a protected file")
            raise

        decision = self._policy.check_read(
            file_path, actor, actor_type=actor_type, file_state=record.state
        )
        if not decision.allowed:
            self._audit.log_read(file_path, actor, allowed=False, detail=decision.reason)
            self._audit.log_policy_denial(file_path, actor, "read", decision.reason)
            raise PolicyDeniedError(decision.reason)

        # Integrity check + read (single disk access — no TOCTOU)
        try:
            content = verify_and_read(record, self._root)
        except SealIntegrityError as exc:
            self._audit.log_read(file_path, actor, allowed=False, detail=str(exc))
            raise

        self._audit.log_read(file_path, actor, allowed=True)
        return content

    def block_write(self, file_path: str, actor: str = "agent") -> None:
        """Called when a write attempt is intercepted. Always denies."""
        self._audit.log_write_blocked(file_path, actor, "Direct write blocked by runtime guard")
        raise PolicyDeniedError(
            f"Direct writes to protected file '{file_path}' are blocked. "
            "Use the proposal mechanism instead."
        )

    # ── File Locking (for edit sessions) ──────────────────────────────────

    def lock_file(self, file_path: str) -> None:
        """Lock a file for human editing — blocks agent access."""
        lock_name = hashlib.sha256(file_path.encode()).hexdigest()[:16] + ".lock"
        lock_path = self._locks_dir / lock_name
        lock_path.touch()
        self._locked_files.add(file_path)
        logger.debug("Locked file for editing: %s", file_path)

    def _unlock_file(self, file_path: str) -> None:
        lock_name = hashlib.sha256(file_path.encode()).hexdigest()[:16] + ".lock"
        lock_path = self._locks_dir / lock_name
        lock_path.unlink(missing_ok=True)
        self._locked_files.discard(file_path)
        logger.debug("Unlocked file: %s", file_path)

    def unlock_file(self, file_path: str) -> None:
        self._unlock_file(file_path)

    def is_locked(self, file_path: str) -> bool:
        return file_path in self._locked_files

    # ── Subprocess Execution ──────────────────────────────────────────────

    def run_command(self, command: list[str], env: dict[str, str] | None = None) -> int:
        """Run a command under the guard, passing the ephemeral key via a pipe.

        The key is written to a pipe file descriptor and the FD number is
        passed in the environment as ACG_RUNTIME_KEY_FD.  This avoids
        exposing the key in /proc/<pid>/environ.

        Returns the exit code of the subprocess.
        """
        if not self._active:
            raise RuntimeNotActiveError("Guard must be started before running commands.")

        run_env = {**os.environ, **(env or {})}
        # Remove any stale key from environment
        run_env.pop(FERNET_KEY_ENV, None)

        pass_fds: tuple[int, ...] = ()
        r_fd = -1

        if self._fernet_key:
            # Create a pipe and write the key to the write-end
            r_fd, w_fd = os.pipe()
            try:
                os.write(w_fd, self._fernet_key)
            finally:
                os.close(w_fd)  # Close write-end; child reads then gets EOF
            run_env[FERNET_KEY_FD_ENV] = str(r_fd)
            pass_fds = (r_fd,)

        self._audit.log_runtime(
            "subprocess_started", f"Command: {' '.join(command)}"
        )

        try:
            result = subprocess.run(
                command,
                env=run_env,
                cwd=self._root,
                pass_fds=pass_fds,
            )
            exit_code = result.returncode
        except FileNotFoundError:
            logger.error("Command not found: %s", command[0])
            exit_code = 127
        except KeyboardInterrupt:
            logger.info("Interrupted by user.")
            exit_code = 130
        except Exception as exc:
            logger.error("Subprocess failed: %s", exc)
            exit_code = 1
        finally:
            if r_fd >= 0:
                try:
                    os.close(r_fd)
                except OSError:
                    pass  # already closed by child

        self._audit.log_runtime("subprocess_exited", f"Exit code: {exit_code}")
        return exit_code

    # ── Encryption Helpers ────────────────────────────────────────────────

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data with the ephemeral runtime key."""
        if not self._fernet:
            raise RuntimeNotActiveError("No ephemeral key available.")
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        """Decrypt data with the ephemeral runtime key."""
        if not self._fernet:
            raise RuntimeNotActiveError("No ephemeral key available.")
        return self._fernet.decrypt(token)
