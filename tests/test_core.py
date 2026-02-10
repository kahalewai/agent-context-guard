"""Tests for core modules."""

from __future__ import annotations

import pytest
from pathlib import Path

from agent_context_guard.core.seal import (
    compute_hash,
    compute_file_hash,
    seal_file,
    verify_seal,
    load_signing_key,
    rotate_signing_key,
    re_seal,
)
from agent_context_guard.core.inventory import Inventory
from agent_context_guard.core.policy import PolicyEngine, PolicyContext
from agent_context_guard.core.audit import AuditLogger
from agent_context_guard.core.proposals import ProposalManager
from agent_context_guard.core.runtime import RuntimeGuard
from agent_context_guard.core.constants import (
    STATE_ACTIVE,
    STATE_SEALED,
    STATE_DEPRECATED,
    STATE_REVOKED,
    OP_READ,
    OP_WRITE,
    OP_PROPOSE,
    OP_APPROVE,
    OP_EDIT,
)
from agent_context_guard.core.exceptions import (
    InventoryCorruptedError,
    SealIntegrityError,
    PolicyDeniedError,
    SealNotFoundError,
    FileLockedError,
    KeyManagementError,
    ProposalError,
)


# ── Seal Tests ────────────────────────────────────────────────────────────────

class TestSeal:
    def test_compute_hash_deterministic(self) -> None:
        h1 = compute_hash(b"hello world")
        h2 = compute_hash(b"hello world")
        assert h1 == h2

    def test_compute_hash_different(self) -> None:
        h1 = compute_hash(b"hello")
        h2 = compute_hash(b"world")
        assert h1 != h2

    def test_compute_file_hash(self, sample_md: Path) -> None:
        h = compute_file_hash(sample_md)
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex

    def test_seal_file(self, guard_root: Path, sample_md: Path) -> None:
        record = seal_file(sample_md, guard_root)
        assert record.content_hash
        assert record.signature
        assert record.version == 1
        assert record.author == "human"
        assert record.state == STATE_SEALED

    def test_verify_seal_success(self, guard_root: Path, sample_md: Path) -> None:
        record = seal_file(sample_md, guard_root)
        assert verify_seal(record, guard_root) is True

    def test_verify_seal_tampered(self, guard_root: Path, sample_md: Path) -> None:
        record = seal_file(sample_md, guard_root)
        sample_md.write_text("TAMPERED CONTENT", encoding="utf-8")
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
        files = inv.list_protected_files()
        assert str(sample_md.resolve()) in files

    def test_deprecation_on_new_version(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        r1 = seal_file(sample_md, guard_root, version=1, state=STATE_ACTIVE)
        inv.add_record(r1)
        sample_md.write_text("Updated content", encoding="utf-8")
        r2 = seal_file(sample_md, guard_root, version=2, state=STATE_ACTIVE)
        inv.add_record(r2)
        active = inv.get_active_record(str(sample_md.resolve()))
        assert active.version == 2

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
        decision = pe.evaluate(ctx)
        assert decision.allowed is True

    def test_write_always_denied(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="agent-1", actor_type="agent", operation=OP_WRITE)
        decision = pe.evaluate(ctx)
        assert decision.allowed is False

    def test_propose_allowed_for_agents(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="agent-1", actor_type="agent", operation=OP_PROPOSE, file_state=STATE_ACTIVE)
        decision = pe.evaluate(ctx)
        assert decision.allowed is True

    def test_approve_denied_for_agents(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="agent-1", actor_type="agent", operation=OP_APPROVE)
        decision = pe.evaluate(ctx)
        assert decision.allowed is False

    def test_approve_allowed_for_humans(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="admin", actor_type="human", operation=OP_APPROVE)
        decision = pe.evaluate(ctx)
        assert decision.allowed is True

    def test_edit_denied_for_agents(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="agent-1", actor_type="agent", operation=OP_EDIT)
        decision = pe.evaluate(ctx)
        assert decision.allowed is False

    def test_edit_allowed_for_humans(self, guard_root: Path) -> None:
        pe = PolicyEngine(guard_root)
        ctx = PolicyContext(actor="admin", actor_type="human", operation=OP_EDIT)
        decision = pe.evaluate(ctx)
        assert decision.allowed is True

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
        assert entries[0].event == "file_read"
        assert entries[1].event == "write_blocked"

    def test_filter_by_event(self, guard_root: Path) -> None:
        al = AuditLogger(guard_root)
        al.log_read("/test.md", "agent-1", True)
        al.log_write_blocked("/test.md", "agent-1")
        entries = list(al.iter_entries(event="write_blocked"))
        assert len(entries) == 1

    def test_entry_count(self, guard_root: Path) -> None:
        al = AuditLogger(guard_root)
        al.log_read("/test.md", "agent-1", True)
        al.log_read("/test2.md", "agent-2", True)
        assert al.entry_count == 2


# ── Proposal Tests ────────────────────────────────────────────────────────────

class TestProposals:
    def test_create_and_list(self, guard_root: Path) -> None:
        pm = ProposalManager(guard_root)
        p = pm.create_proposal(
            file_path="/test.md",
            original_content="Hello",
            proposed_content="Hello World",
            agent_id="agent-1",
            justification="Add greeting",
        )
        assert p.status == "pending"
        proposals = pm.list_proposals(file_path="/test.md")
        assert len(proposals) == 1
        assert proposals[0].proposal_id == p.proposal_id

    def test_approve_proposal(self, guard_root: Path) -> None:
        pm = ProposalManager(guard_root)
        p = pm.create_proposal("/test.md", "old", "new", "agent-1")
        result = pm.approve("/test.md", p.proposal_id)
        assert result.status == "approved"

    def test_reject_proposal(self, guard_root: Path) -> None:
        pm = ProposalManager(guard_root)
        p = pm.create_proposal("/test.md", "old", "new", "agent-1")
        result = pm.reject("/test.md", p.proposal_id)
        assert result.status == "rejected"

    def test_cannot_approve_twice(self, guard_root: Path) -> None:
        pm = ProposalManager(guard_root)
        p = pm.create_proposal("/test.md", "old", "new", "agent-1")
        pm.approve("/test.md", p.proposal_id)
        with pytest.raises(ProposalError):
            pm.approve("/test.md", p.proposal_id)

    def test_get_latest_pending(self, guard_root: Path) -> None:
        pm = ProposalManager(guard_root)
        pm.create_proposal("/test.md", "v1", "v2", "agent-1")
        pm.create_proposal("/test.md", "v1", "v3", "agent-1")
        latest = pm.get_latest_pending("/test.md")
        assert latest is not None
        assert latest.status == "pending"
        # Should have two pending proposals total
        all_pending = pm.list_proposals(file_path="/test.md", status="pending")
        assert len(all_pending) == 2


# ── Runtime Guard Tests ───────────────────────────────────────────────────────

class TestRuntime:
    def test_start_and_stop(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)

        guard = RuntimeGuard(guard_root)
        guard.start()
        assert guard.is_active
        guard.stop()
        assert not guard.is_active

    def test_read_protected_file(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)

        guard = RuntimeGuard(guard_root)
        guard.start()
        try:
            content = guard.read_file(str(sample_md.resolve()), actor="test-agent")
            assert "Agent Persona" in content
        finally:
            guard.stop()

    def test_write_blocked(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)

        guard = RuntimeGuard(guard_root)
        guard.start()
        try:
            with pytest.raises(PolicyDeniedError):
                guard.block_write(str(sample_md.resolve()))
        finally:
            guard.stop()

    def test_locked_file_blocked(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)

        guard = RuntimeGuard(guard_root)
        guard.start()
        try:
            resolved = str(sample_md.resolve())
            guard.lock_file(resolved)
            with pytest.raises(FileLockedError):
                guard.read_file(resolved, actor="test-agent")
            guard.unlock_file(resolved)
            content = guard.read_file(resolved, actor="test-agent")
            assert content
        finally:
            guard.stop()

    def test_tampered_file_detected_at_start(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)
        sample_md.write_text("TAMPERED", encoding="utf-8")

        guard = RuntimeGuard(guard_root)
        with pytest.raises(SealIntegrityError):
            guard.start()

    def test_context_manager(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)

        with RuntimeGuard(guard_root) as guard:
            assert guard.is_active
        assert not guard.is_active

    def test_encrypt_decrypt(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)

        with RuntimeGuard(guard_root) as guard:
            data = b"secret data"
            encrypted = guard.encrypt(data)
            assert encrypted != data
            decrypted = guard.decrypt(encrypted)
            assert decrypted == data


# ── Self-Protection Tests ─────────────────────────────────────────────────────

from agent_context_guard.core.selfprotect import (
    sign_metadata_file,
    verify_metadata_file,
    verify_all_metadata,
    sign_all_metadata,
)
from agent_context_guard.core.constants import inventory_path, policy_path


class TestSelfProtection:
    def test_sign_and_verify_inventory(self, guard_root: Path) -> None:
        inv_path = inventory_path(guard_root)
        sign_metadata_file(inv_path, guard_root)
        assert verify_metadata_file(inv_path, guard_root) is True

    def test_tampered_inventory_detected(self, guard_root: Path) -> None:
        inv_path = inventory_path(guard_root)
        sign_metadata_file(inv_path, guard_root)
        # Tamper with the inventory
        inv_path.write_text('{"version": 1, "files": {"INJECTED": []}}', encoding="utf-8")
        with pytest.raises(InventoryCorruptedError):
            verify_metadata_file(inv_path, guard_root)

    def test_sign_and_verify_policy(self, guard_root: Path) -> None:
        pol_path = policy_path(guard_root)
        sign_metadata_file(pol_path, guard_root)
        assert verify_metadata_file(pol_path, guard_root) is True

    def test_tampered_policy_detected(self, guard_root: Path) -> None:
        pol_path = policy_path(guard_root)
        sign_metadata_file(pol_path, guard_root)
        pol_path.write_text("read:\n  allow: all_agents\nwrite:\n  allow: all_agents\n", encoding="utf-8")
        with pytest.raises(InventoryCorruptedError):
            verify_metadata_file(pol_path, guard_root)

    def test_verify_all_metadata(self, guard_root: Path) -> None:
        sign_all_metadata(guard_root)
        failures = verify_all_metadata(guard_root)
        assert failures == []

    def test_verify_all_detects_tampering(self, guard_root: Path) -> None:
        sign_all_metadata(guard_root)
        inv_path = inventory_path(guard_root)
        inv_path.write_text("TAMPERED", encoding="utf-8")
        failures = verify_all_metadata(guard_root)
        assert len(failures) > 0

    def test_runtime_rejects_tampered_metadata(self, guard_root: Path, sample_md: Path) -> None:
        inv = Inventory(guard_root)
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        inv.add_record(record)
        # Construct guard BEFORE tampering (Inventory verifies on load)
        guard = RuntimeGuard(guard_root)
        # Now tamper with the inventory HMAC sidecar
        inv_path = inventory_path(guard_root)
        content = inv_path.read_text(encoding="utf-8")
        inv_path.write_text(content.replace('"ACTIVE"', '"REVOKED"'), encoding="utf-8")
        # start() calls verify_all_metadata which should detect the tampering
        with pytest.raises((SealIntegrityError, InventoryCorruptedError)):
            guard.start()


# ── Audit Chain Tests ─────────────────────────────────────────────────────────

class TestAuditChain:
    def test_chain_integrity(self, guard_root: Path) -> None:
        al = AuditLogger(guard_root)
        al.log_read("/test.md", "agent-1", True)
        al.log_write_blocked("/test.md", "agent-1")
        al.log_read("/test2.md", "agent-2", True)
        valid, count, msg = al.verify_chain()
        assert valid is True
        assert count == 3

    def test_chain_detects_deletion(self, guard_root: Path) -> None:
        from agent_context_guard.core.constants import audit_log_path
        al = AuditLogger(guard_root)
        al.log_read("/test.md", "agent-1", True)
        al.log_write_blocked("/test.md", "agent-1")
        al.log_read("/test2.md", "agent-2", True)
        # Delete the middle entry
        log_path = audit_log_path(guard_root)
        lines = log_path.read_text(encoding="utf-8").splitlines(keepends=True)
        assert len(lines) >= 3
        # Remove line 2 (index 1)
        tampered = lines[0] + lines[2]
        log_path.write_text(tampered, encoding="utf-8")
        al2 = AuditLogger(guard_root)
        valid, count, msg = al2.verify_chain()
        assert valid is False
        assert "chain broken" in msg

    def test_chain_detects_modification(self, guard_root: Path) -> None:
        from agent_context_guard.core.constants import audit_log_path
        al = AuditLogger(guard_root)
        al.log_read("/test.md", "agent-1", True)
        al.log_write_blocked("/test.md", "agent-1")
        # Modify the first entry
        log_path = audit_log_path(guard_root)
        content = log_path.read_text(encoding="utf-8")
        tampered = content.replace("agent-1", "agent-HACKED", 1)
        log_path.write_text(tampered, encoding="utf-8")
        al2 = AuditLogger(guard_root)
        valid, count, msg = al2.verify_chain()
        assert valid is False


# ── Verify-and-Read (TOCTOU fix) Tests ────────────────────────────────────────

from agent_context_guard.core.seal import verify_and_read


class TestVerifyAndRead:
    def test_returns_verified_content(self, guard_root: Path, sample_md: Path) -> None:
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        content = verify_and_read(record, guard_root)
        assert "Agent Persona" in content

    def test_detects_tampering(self, guard_root: Path, sample_md: Path) -> None:
        record = seal_file(sample_md, guard_root, state=STATE_ACTIVE)
        sample_md.write_text("TAMPERED", encoding="utf-8")
        with pytest.raises(SealIntegrityError):
            verify_and_read(record, guard_root)
# (InventoryCorruptedError was already imported at the top via test fixtures — 
#  we need to add it to the test file's imports)
