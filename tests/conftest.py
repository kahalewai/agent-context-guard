"""Shared test fixtures for agent-context-guard."""

from __future__ import annotations

import pytest
from pathlib import Path

from agent_context_guard.core.seal import generate_signing_key
from agent_context_guard.core.constants import (
    guard_dir, keys_dir, proposals_dir, locks_dir,
    inventory_path, policy_path,
)
from agent_context_guard.core.selfprotect import sign_all_metadata


@pytest.fixture
def guard_root(tmp_path: Path) -> Path:
    """Create a fully initialized guard directory structure."""
    root = tmp_path / "project"
    root.mkdir()
    guard_dir(root).mkdir()
    keys_dir(root).mkdir(parents=True, exist_ok=True)
    proposals_dir(root).mkdir(parents=True, exist_ok=True)
    locks_dir(root).mkdir(parents=True, exist_ok=True)
    generate_signing_key(root)
    inventory_path(root).write_text('{"version": 1, "files": {}}', encoding="utf-8")
    policy_path(root).write_text(
        "read:\n  allow: all_agents\nwrite:\n  allow: none\n"
        "propose:\n  allow: all_agents\napprove:\n  allow: humans\n",
        encoding="utf-8",
    )
    sign_all_metadata(root)
    return root


@pytest.fixture
def sample_md(guard_root: Path) -> Path:
    """Create a sample markdown file in the guard root."""
    md = guard_root / "prompts" / "persona.md"
    md.parent.mkdir(parents=True, exist_ok=True)
    md.write_text("# Agent Persona\n\nYou are a helpful assistant.\n", encoding="utf-8")
    return md
