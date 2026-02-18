"""Tests for agent-context-guard core modules and Guard API."""

from __future__ import annotations

import pytest
from pathlib import Path

from agent_context_guard.core.seal import (
    compute_hash, compute_file_hash, seal_file, verify_seal,
    verify_and_read, rotate_signing_key, re_seal,
)
from agent_context_guard.core.inventory import Inventory
from agent_context_guard.core.policy import PolicyEngine, PolicyContext
from agent_context_guard.core.audit import AuditLogger
from agent_context_guard.core.proposals import ProposalManager
from agent_context_guard.core.constants import (
    STATE_ACTIVE, STATE_SEALED, OP_READ, OP_WRITE, OP_PROPOSE,
    OP_APPROVE, OP_EDIT, audit_log_path, inventory_path, policy_path,
)
from agent_context_guard.core.exceptions import (
    SealIntegrityError, PolicyDeniedError, SealNotFoundError,
    ProposalError, InventoryCorruptedError, KeyManagementError,
)
from agent_context_guard.core.selfprotect import (
    sign_metadata_file, verify_metadata_file, verify_all_metadata, sign_all_metadata,
)
from agent_context_guard.guard import Guard, GuardSession


# ── Seal Tests ────────────────────────────────────────────────────────────────

class TestSeal:
    def test_compute_hash_deterministic(self) -> None:
        assert compute_hash(b"hello world") == compute_hash(b"hello world")

    def test_compute_hash_different(self) -> None:
        assert compute_hash(b"hello") != compute_hash(b"world")

    def test_compute_file_hash(self, sample_md: Path) -> None:
        h = compute_file_hash(sample_md)
        assert isinstance(h, str) and len(h) == 64

    def test_seal_file(self, guard_root: Path, sample_md: Path) -> None:
        record = seal_file(sample_md, guard_root)
        assert record.content_hash and record.signature
        assert record.version == 1 and record.author == "human"

    def test_verify_seal_success(self, guard_root: Path, sample_md: Path) -> None:
        record = seal_file(sample_md, guard_root)
        assert verify_seal(record, guard_root) is True

    def test_verify_seal_tampered(self, guard_root: Path, sample_md: Path) -> None:
        record = seal_file(sample_md, guard_root)
        sample_md.write_text("TAMPERED", encoding="utf-8")
        with pytest.raises(SealIntegrityError):
            verify_seal(record, guard_root)

    def test_seal_nonexistent_file(self, guard_root: Path) -> None:
        from agent_context_guard.core.exceptions import SealError
        with pytest.raises(SealError):
            seal_file(guard_root / "nonexistent.md", guard_root)

    def test_key_rotation(self, guard_root: Path, sample_md: Path) -> None:
        record = seal_file(sample_md, guard_root)
        old_key, new_key = rotate_signing_key(guard_root)
        new_record = re_seal(record, new_key)
        assert new_record.signature != record.signature
        assert new_record.content_hash == record.content_hash

    def test_verify_and_read(self, guard_root: Path, sample_md: Path) -> None:
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        content = verify_and_read(record, guard_root)
        assert "Agent Persona" in content

    def test_verify_and_read_tampered(self, guard_root: Path, sample_md: Path) -> None:
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        sample_md.write_text("TAMPERED", encoding="utf-8")
        with pytest.raises(SealIntegrityError):
            verify_and_read(record, guard_root)


# ── Inventory Tests ───────────────────────────────────────────────────────────

class TestInventory:
    def test_add_and_get(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)
        retrieved = inv.get_active_record(str(sample_md.resolve()))
        assert retrieved.content_hash == record.content_hash

    def test_list_protected_files(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)
        assert str(sample_md.resolve()) in inv.list_protected_files()

    def test_deprecation_on_new_version(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        r1 = seal_file(sample_md, guard_root, version=1, state=STATE_ACTIVE)
        inv.add_record(r1)
        sample_md.write_text("Updated content", encoding="utf-8")
        r2 = seal_file(sample_md, guard_root, version=2, state=STATE_ACTIVE)
        inv.add_record(r2)
        assert inv.get_active_record(str(sample_md.resolve())).version == 2

    def test_revoke(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)
        inv.revoke(str(sample_md.resolve()))
        with pytest.raises(SealNotFoundError):
            inv.get_active_record(str(sample_md.resolve()))

    def test_next_version(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        assert inv.next_version(str(sample_md.resolve())) == 1
        record = seal_file(sample_md, guard_root, version=1, state=STATE_ACTIVE)
        inv.add_record(record)
        assert inv.next_version(str(sample_md.resolve())) == 2


# ── Policy Tests ──────────────────────────────────────────────────────────────

class TestPolicy:
    def test_read_allowed_for_agents(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="agent-1", actor_type="agent", operation=OP_READ, file_state=STATE_ACTIVE)
        assert pe.evaluate(ctx).allowed is True

    def test_write_always_denied(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="agent-1", actor_type="agent", operation=OP_WRITE)
        assert pe.evaluate(ctx).allowed is False

    def test_propose_allowed(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="agent-1", actor_type="agent", operation=OP_PROPOSE, file_state=STATE_ACTIVE)
        assert pe.evaluate(ctx).allowed is True

    def test_approve_denied_for_agents(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="agent-1", actor_type="agent", operation=OP_APPROVE)
        assert pe.evaluate(ctx).allowed is False

    def test_approve_allowed_for_humans(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="admin", actor_type="human", operation=OP_APPROVE)
        assert pe.evaluate(ctx).allowed is True

    def test_edit_denied_for_agents(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="agent-1", actor_type="agent", operation=OP_EDIT)
        assert pe.evaluate(ctx).allowed is False

    def test_require_raises_on_denial(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="agent-1", actor_type="agent", operation=OP_WRITE)
        with pytest.raises(PolicyDeniedError):
            pe.require(ctx)


# ── Audit Tests ───────────────────────────────────────────────────────────────

class TestAudit:
    def test_log_and_read(self, guard_root: Path) -> None:
        al = AuditLogger(guard_root)
        al.log_read("/test.md", "agent-1", True)
        al.log_write_blocked("/test.md", "agent-1")
        entries = list(al.iter_entries())
        assert len(entries) == 2

    def test_filter_by_event(self, guard_root: Path) -> None:
        al = AuditLogger(guard_root)
        al.log_read("/test.md", "agent-1", True)
        al.log_write_blocked("/test.md", "agent-1")
        assert len(list(al.iter_entries(event="write_blocked"))) == 1

    def test_chain_integrity(self, guard_root: Path) -> None:
        al = AuditLogger(guard_root)
        al.log_read("/a.md", "agent-1", True)
        al.log_read("/b.md", "agent-2", True)
        al.log_read("/c.md", "agent-3", True)
        valid, count, msg = al.verify_chain()
        assert valid is True and count == 3

    def test_chain_detects_deletion(self, guard_root: Path) -> None:
        al = AuditLogger(guard_root)
        al.log_read("/a.md", "agent-1", True)
        al.log_write_blocked("/b.md", "agent-1")
        al.log_read("/c.md", "agent-2", True)
        log_path = audit_log_path(guard_root)
        lines = log_path.read_text(encoding="utf-8").splitlines(keepends=True)
        log_path.write_text(lines[0] + lines[2], encoding="utf-8")
        al2 = AuditLogger(guard_root)
        valid, count, msg = al2.verify_chain()
        assert valid is False and "chain broken" in msg


# ── Proposal Tests ────────────────────────────────────────────────────────────

class TestProposals:
    def test_create_and_list(self, guard_root: Path) -> None:
        pm = ProposalManager(guard_root)
        p = pm.create_proposal("/test.md", "Hello", "Hello World", "agent-1", "Add greeting")
        assert p.status == "pending"
        assert len(pm.list_proposals(file_path="/test.md")) == 1

    def test_approve_proposal(self, guard_root: Path) -> None:
        pm = ProposalManager(guard_root)
        p = pm.create_proposal("/test.md", "old", "new", "agent-1")
        assert pm.approve("/test.md", p.proposal_id).status == "approved"

    def test_reject_proposal(self, guard_root: Path) -> None:
        pm = ProposalManager(guard_root)
        p = pm.create_proposal("/test.md", "old", "new", "agent-1")
        assert pm.reject("/test.md", p.proposal_id).status == "rejected"

    def test_cannot_approve_twice(self, guard_root: Path) -> None:
        pm = ProposalManager(guard_root)
        p = pm.create_proposal("/test.md", "old", "new", "agent-1")
        pm.approve("/test.md", p.proposal_id)
        with pytest.raises(ProposalError):
            pm.approve("/test.md", p.proposal_id)


# ── Self-Protection Tests ─────────────────────────────────────────────────────

class TestSelfProtection:
    def test_sign_and_verify_inventory(self, guard_root: Path) -> None:
        inv_path = inventory_path(guard_root)
        sign_metadata_file(inv_path, guard_root)
        assert verify_metadata_file(inv_path, guard_root) is True

    def test_tampered_inventory_detected(self, guard_root: Path) -> None:
        inv_path = inventory_path(guard_root)
        sign_metadata_file(inv_path, guard_root)
        inv_path.write_text('{"version": 1, "files": {"INJECTED": []}}', encoding="utf-8")
        with pytest.raises(InventoryCorruptedError):
            verify_metadata_file(inv_path, guard_root)

    def test_tampered_policy_detected(self, guard_root: Path) -> None:
        pol_path = policy_path(guard_root)
        sign_metadata_file(pol_path, guard_root)
        pol_path.write_text("read:\n  allow: all_agents\nwrite:\n  allow: all_agents\n", encoding="utf-8")
        with pytest.raises(InventoryCorruptedError):
            verify_metadata_file(pol_path, guard_root)

    def test_verify_all_metadata(self, guard_root: Path) -> None:
        assert verify_all_metadata(guard_root) == []


# ── Guard API Tests ───────────────────────────────────────────────────────────

class TestGuard:
    def _protect(self, guard_root: Path, sample_md: Path) -> Guard:
        """Helper: create a Guard with the sample file protected."""
        guard = Guard(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        guard.inventory.add_record(record)
        return guard

    def test_read(self, guard_root: Path, sample_md: Path) -> None:
        guard = self._protect(guard_root, sample_md)
        content = guard.read(sample_md, agent_id="test-agent")
        assert "Agent Persona" in content

    def test_read_tampered(self, guard_root: Path, sample_md: Path) -> None:
        guard = self._protect(guard_root, sample_md)
        sample_md.write_text("TAMPERED", encoding="utf-8")
        with pytest.raises(SealIntegrityError):
            guard.read(sample_md, agent_id="test-agent")

    def test_read_unprotected(self, guard_root: Path) -> None:
        guard = Guard(guard_root)
        with pytest.raises(SealNotFoundError):
            guard.read(guard_root / "nonexistent.md", agent_id="test-agent")

    def test_propose(self, guard_root: Path, sample_md: Path) -> None:
        guard = self._protect(guard_root, sample_md)
        pid = guard.propose(sample_md, "# New Content\n", agent_id="test-agent", justification="Update")
        assert pid  # non-empty ID

    def test_status_protected(self, guard_root: Path, sample_md: Path) -> None:
        guard = self._protect(guard_root, sample_md)
        s = guard.status(sample_md)
        assert s["protected"] is True
        assert s["state"] == STATE_ACTIVE
        assert s["version"] == 1

    def test_status_unprotected(self, guard_root: Path) -> None:
        guard = Guard(guard_root)
        s = guard.status(guard_root / "random.md")
        assert s["protected"] is False

    def test_verify_all(self, guard_root: Path, sample_md: Path) -> None:
        guard = self._protect(guard_root, sample_md)
        assert guard.verify_all() == []

    def test_verify_all_catches_tampering(self, guard_root: Path, sample_md: Path) -> None:
        guard = self._protect(guard_root, sample_md)
        sample_md.write_text("TAMPERED", encoding="utf-8")
        failures = guard.verify_all()
        assert len(failures) > 0

    def test_verify_file(self, guard_root: Path, sample_md: Path) -> None:
        guard = self._protect(guard_root, sample_md)
        assert guard.verify_file(sample_md) is True

    def test_session(self, guard_root: Path, sample_md: Path) -> None:
        guard = self._protect(guard_root, sample_md)
        with guard.session(agent_id="session-agent") as s:
            content = s.read(sample_md)
            assert "Agent Persona" in content
            s_info = s.status(sample_md)
            assert s_info["protected"] is True

    def test_session_propose(self, guard_root: Path, sample_md: Path) -> None:
        guard = self._protect(guard_root, sample_md)
        with guard.session(agent_id="session-agent") as s:
            pid = s.propose(sample_md, "# Updated\n", justification="Test")
            assert pid

    def test_repr(self, guard_root: Path) -> None:
        guard = Guard(guard_root)
        r = repr(guard)
        assert "Guard(" in r and "files=" in r


# ── Adapter Tests (no framework deps required) ───────────────────────────────

class TestAdapters:
    def _protect(self, guard_root: Path, sample_md: Path) -> Guard:
        guard = Guard(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        guard.inventory.add_record(record)
        return guard

    def test_openai_tools(self, guard_root: Path, sample_md: Path) -> None:
        """Test OpenAI adapter creates valid schemas and handler."""
        from agent_context_guard.adapters.openai_tools import create_openai_tools
        import json
        guard = self._protect(guard_root, sample_md)
        tools, handler = create_openai_tools(guard, agent_id="test")
        assert len(tools) == 3
        assert tools[0]["function"]["name"] == "read_protected_file"
        # Test the handler
        result = handler("read_protected_file", json.dumps({"file_path": str(sample_md)}))
        assert "Agent Persona" in result

    def test_anthropic_tools(self, guard_root: Path, sample_md: Path) -> None:
        """Test Anthropic adapter creates valid schemas and handler."""
        from agent_context_guard.adapters.anthropic_tools import create_anthropic_tools
        guard = self._protect(guard_root, sample_md)
        tools, handler = create_anthropic_tools(guard, agent_id="test")
        assert len(tools) == 3
        assert tools[0]["name"] == "read_protected_file"
        result = handler("read_protected_file", {"file_path": str(sample_md)})
        assert "Agent Persona" in result

    def test_mcp_tools(self, guard_root: Path, sample_md: Path) -> None:
        """Test MCP adapter creates valid definitions and handler."""
        from agent_context_guard.adapters.mcp import create_mcp_tools
        guard = self._protect(guard_root, sample_md)
        tools, handler = create_mcp_tools(guard, agent_id="test")
        assert len(tools) == 4  # read, propose, status, verify
        result = handler("read_protected_file", {"file_path": str(sample_md)})
        assert "Agent Persona" in result

    def test_autogen_function_map(self, guard_root: Path, sample_md: Path) -> None:
        """Test AutoGen adapter creates valid function map."""
        from agent_context_guard.adapters.autogen import create_function_map
        guard = self._protect(guard_root, sample_md)
        fmap = create_function_map(guard, agent_id="test")
        assert "read_protected_file" in fmap
        result = fmap["read_protected_file"](str(sample_md))
        assert "Agent Persona" in result

    def test_openclaw_handlers(self, guard_root: Path, sample_md: Path) -> None:
        """Test OpenClaw adapter creates working handlers."""
        from agent_context_guard.adapters.openclaw import create_openclaw_handlers
        guard = self._protect(guard_root, sample_md)
        handlers = create_openclaw_handlers(guard, agent_id="test")
        result = handlers["read"](str(sample_md))
        assert "Agent Persona" in result
