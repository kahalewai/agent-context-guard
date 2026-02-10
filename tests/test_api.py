"""Tests for the public Python API."""

from __future__ import annotations

import os
import pytest
from pathlib import Path

from agent_context_guard.api import read_md, propose_update, get_status
from agent_context_guard.core.seal import seal_file
from agent_context_guard.core.inventory import Inventory
from agent_context_guard.core.constants import STATE_ACTIVE
from agent_context_guard.core.exceptions import PolicyDeniedError


class TestPublicAPI:
    def test_read_md(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)

        content = read_md(sample_md, agent_id="test", root=guard_root)
        assert "Agent Persona" in content

    def test_propose_update(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)

        pid = propose_update(
            sample_md,
            "# Updated Persona\n\nNew content.\n",
            agent_id="test-agent",
            justification="Improved persona",
            root=guard_root,
        )
        assert pid  # non-empty proposal ID

    def test_get_status_protected(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)

        status = get_status(sample_md, root=guard_root)
        assert status["protected"] is True
        assert status["state"] == STATE_ACTIVE
        assert status["version"] == 1

    def test_get_status_unprotected(self, guard_root: Path) -> None:
        unprotected = guard_root / "notes.md"
        unprotected.write_text("Just notes", encoding="utf-8")
        status = get_status(unprotected, root=guard_root)
        assert status["protected"] is False
