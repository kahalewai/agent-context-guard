"""CLI entry point for agent-context-guard."""

from __future__ import annotations

import glob
import logging
import os
import sys
from pathlib import Path

import click

from agent_context_guard.core.constants import (
    GUARD_DIR_NAME,
    MARKDOWN_EXTENSIONS,
    STATE_ACTIVE,
    guard_dir,
    get_guard_root,
)
from agent_context_guard.core.exceptions import (
    AgentContextGuardError,
    SealIntegrityError,
)
from agent_context_guard.cli.helpers import (
    confirm,
    console,
    format_state,
    format_timestamp,
    make_audit_table,
    make_status_table,
    out_console,
    print_banner,
    print_detail,
    print_error,
    print_header,
    print_info,
    print_muted,
    print_next_steps,
    print_section,
    print_success,
    print_usage_hint,
    print_warning,
)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _find_root() -> Path:
    try:
        return get_guard_root()
    except FileNotFoundError:
        print_error(
            f"No {GUARD_DIR_NAME} directory found.\n"
            "    Run 'agent-context-guard init' in your project root first."
        )
        sys.exit(1)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Main Group
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.version_option(package_name="agent-context-guard")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """agent-context-guard — Runtime protection for AI agent context files.

    Prevents unauthorized viewing, modification, and silent drift of markdown
    files that influence AI agent behavior. Preserves human ownership and
    existing development workflows.

    \b
    Quick start:
      agent-context-guard init
      agent-context-guard protect prompts/*.md
      agent-context-guard run -- python my_agent.py
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)

    if ctx.invoked_subcommand is None:
        _show_main_help(ctx)


def _show_main_help(ctx: click.Context) -> None:
    """Display the main branded overview when no subcommand is given."""
    print_header()

    print_info("Protect markdown files that control AI agent behavior.")
    print_info("Seals files with cryptographic signatures, blocks unauthorized")
    print_info("modifications at runtime, and provides a full audit trail.")

    print_section("Available Commands")

    commands = [
        ("init", "Initialize guard in a directory"),
        ("protect", "Register markdown files for protection"),
        ("run", "Run a command under the runtime guard"),
        ("edit", "Open a human edit session for a protected file"),
        ("status", "Show protection status of files"),
        ("diff", "Show pending proposal diffs"),
        ("approve", "Approve a pending proposal and apply changes"),
        ("reject", "Reject a pending proposal"),
        ("audit", "Display the audit log"),
        ("verify", "CI/CD verification of sealed files and metadata"),
        ("rotate-keys", "Rotate the signing key and re-sign all files"),
    ]

    for cmd, desc in commands:
        console.print(f"    {cmd:<16}", style="cyan", end="")
        console.print(desc, style="dim")

    print_section("Global Options")
    console.print(f"    {'--version':<16}", style="cyan", end="")
    console.print("Show version and exit", style="dim")
    console.print(f"    {'-v, --verbose':<16}", style="cyan", end="")
    console.print("Enable debug logging", style="dim")
    console.print(f"    {'-h, --help':<16}", style="cyan", end="")
    console.print("Show help for any command", style="dim")

    print_next_steps([
        ("agent-context-guard init", "Initialize in your project"),
        ("agent-context-guard <command> --help", "Get help for a specific command"),
    ])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  init
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.option("--path", "-p", default=".", type=click.Path(exists=True),
              help="Directory to initialize (default: cwd).")
def init(path: str) -> None:
    """Initialize agent-context-guard in a directory.

    Creates the .agent-context-guard/ directory, generates the signing key,
    and sets up default policies.
    """
    from agent_context_guard.core.seal import generate_signing_key
    from agent_context_guard.core.audit import AuditLogger
    from agent_context_guard.core.constants import (
        guard_dir as gd_fn, keys_dir, proposals_dir, locks_dir,
        inventory_path, policy_path,
    )

    root = Path(path).resolve()
    gd = gd_fn(root)

    if gd.exists():
        print_header("Initialize")
        print_warning(f"Guard directory already exists at {gd}")
        print_info("This project has already been initialized.")
        print_next_steps([
            ("agent-context-guard protect <files>", "Protect your context files"),
            ("agent-context-guard status", "View currently protected files"),
        ])
        return

    print_header("Initialize")

    print_info(f"Initializing in: {root}")
    console.print()

    print_section("Setting Up")

    gd.mkdir(parents=True)
    keys_dir(root).mkdir(parents=True, exist_ok=True)
    proposals_dir(root).mkdir(parents=True, exist_ok=True)
    locks_dir(root).mkdir(parents=True, exist_ok=True)

    generate_signing_key(root)
    print_success("Signing key generated")

    inventory_path(root).write_text('{"version": 1, "files": {}}', encoding="utf-8")
    print_success("Inventory created")

    policy_text = (
        "# agent-context-guard policy\n"
        "# See documentation for full policy options.\n\n"
        "read:\n  allow: all_agents\n\n"
        "write:\n  allow: none\n\n"
        "propose:\n  allow: all_agents\n\n"
        "approve:\n  allow: humans\n"
    )
    policy_path(root).write_text(policy_text, encoding="utf-8")
    print_success("Default policy created")

    AuditLogger(root).log_runtime("initialized", f"Guard initialized at {root}")
    print_success("Audit log initialized")

    # Sign all guard metadata files (self-protection)
    from agent_context_guard.core.selfprotect import sign_all_metadata
    sign_all_metadata(root)
    print_success("Guard metadata integrity signatures created")

    (gd / ".gitignore").write_text("keys/\nlocks/\n", encoding="utf-8")
    print_success("Created .gitignore (keys excluded from VCS)")

    print_section("Result")

    print_success("Initialization complete!")
    print_detail("Guard directory", str(gd))
    print_detail("Policy file", str(gd / "policy.yaml"))

    print_next_steps([
        ("agent-context-guard protect <path>", "Protect your agent context files"),
        ("agent-context-guard status", "View protection status"),
        ("agent-context-guard run -- <command>", "Run your agent under the guard"),
    ])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  protect
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("files", nargs=-1, required=True)
@click.option("--author", "-a", default="human", help="Author identity for seal records.")
def protect(files: tuple[str, ...], author: str) -> None:
    """Register markdown files for protection.

    \b
    Accepts file paths or glob patterns. Each file is sealed with a
    cryptographic hash and HMAC signature, then added to the inventory.

    \b
    Examples:
      agent-context-guard protect prompts/persona.md
      agent-context-guard protect 'prompts/*.md' 'rules/**/*.md'
    """
    from agent_context_guard.core.seal import seal_file
    from agent_context_guard.core.inventory import Inventory
    from agent_context_guard.core.audit import AuditLogger

    root = _find_root()
    inv = Inventory(root)
    audit = AuditLogger(root)

    print_header("Protect Files")

    print_info("Registering markdown files for cryptographic protection.")
    print_usage_hint(
        "agent-context-guard protect <file|glob> [<file|glob> ...]",
        "Accepts paths or glob patterns such as 'prompts/*.md'",
    )
    console.print()

    print_section("Processing Files")

    expanded: list[Path] = []
    for pattern in files:
        matches = glob.glob(pattern, recursive=True)
        if not matches:
            p = Path(pattern)
            if p.exists():
                matches = [str(p)]
            else:
                print_warning(f"No files matched: {pattern}")
                continue
        for m in matches:
            mp = Path(m).resolve()
            if mp.is_file() and mp.suffix.lower() in MARKDOWN_EXTENSIONS:
                expanded.append(mp)
            elif mp.is_file():
                print_warning(f"Skipping non-markdown file: {mp.name}")

    if not expanded:
        print_error("No markdown files to protect.")
        print_info("Provide paths to .md files or glob patterns.")
        print_usage_hint("agent-context-guard protect prompts/*.md")
        sys.exit(1)

    count = 0
    for fp in expanded:
        resolved = str(fp)
        if inv.has_file(resolved):
            print_warning(f"Already protected: {fp.name}")
            continue
        version = inv.next_version(resolved)
        record = seal_file(fp, root, author=author, version=version, state=STATE_ACTIVE)
        inv.add_record(record)
        audit.log_seal(resolved, author, version, f"Initial protection of {fp.name}")
        print_success(f"Protected: {fp.name} (v{version})")
        count += 1

    print_section("Result")

    if count:
        print_success(f"{count} file(s) now under protection.")
    else:
        print_info("No new files to protect.")

    print_next_steps([
        ("agent-context-guard status", "View all protected files"),
        ("agent-context-guard run -- <command>", "Run your agent under the guard"),
        ("agent-context-guard verify", "Verify integrity of all sealed files"),
    ])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  run
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("command", nargs=-1, required=True)
def run(command: tuple[str, ...]) -> None:
    """Run a command under the runtime guard.

    \b
    Verifies all sealed files, generates ephemeral encryption keys,
    and monitors file access during execution.

    \b
    Examples:
      agent-context-guard run -- python my_agent.py
      agent-context-guard run -- node agent.js --verbose
    """
    from agent_context_guard.core.runtime import RuntimeGuard

    root = _find_root()
    cmd = list(command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not cmd:
        print_header("Run")
        print_error("No command specified.")
        print_usage_hint(
            "agent-context-guard run -- <command>",
            "Use '--' to separate guard options from your command.",
        )
        print_next_steps([
            ("agent-context-guard run -- python my_agent.py", "Run a Python agent"),
            ("agent-context-guard run -- node agent.js", "Run a Node.js agent"),
        ])
        sys.exit(1)

    print_header("Run")

    print_info(f"Command: {' '.join(cmd)}")
    console.print()

    print_section("Starting Guard")

    guard = RuntimeGuard(root)

    try:
        guard.start()
        print_success(f"Guard active — {guard.inventory.file_count} file(s) protected")
        print_info("Monitoring file access during execution...")
        console.print()
        exit_code = guard.run_command(cmd)
    except SealIntegrityError as exc:
        print_section("Integrity Failure")
        print_error(f"Seal verification failed:\n{exc}")
        print_next_steps([
            ("agent-context-guard verify", "Run full integrity check"),
            ("agent-context-guard status", "Review file protection status"),
            ("agent-context-guard audit", "Check the audit log for details"),
        ])
        sys.exit(2)
    except AgentContextGuardError as exc:
        print_error(str(exc))
        sys.exit(1)
    finally:
        guard.stop()

    print_section("Result")

    if exit_code == 0:
        print_success(f"Command completed successfully (exit code: {exit_code})")
    else:
        print_warning(f"Command exited with code: {exit_code}")

    print_info("Runtime guard stopped.")

    print_next_steps([
        ("agent-context-guard verify", "Verify file integrity after run"),
        ("agent-context-guard audit", "Review the audit log"),
        ("agent-context-guard status", "Check protection status"),
    ])

    sys.exit(exit_code)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  edit
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("file", required=True, type=click.Path(exists=True))
@click.option("--author", "-a", default="human", help="Author identity.")
@click.option("--editor", "-e", default=None, help="Editor command (default: $EDITOR).")
def edit(file: str, author: str, editor: str | None) -> None:
    """Open a human edit session for a protected file.

    \b
    The file is locked (blocking agent access), opened in your editor,
    and re-sealed on save. Partial writes are impossible.
    """
    from agent_context_guard.core.edit import EditSession

    root = _find_root()
    resolved = str(Path(file).resolve())

    print_header("Edit Session")

    print_info(f"File: {file}")
    print_info(f"Author: {author}")
    if editor:
        print_info(f"Editor: {editor}")
    else:
        print_info(f"Editor: {os.environ.get('EDITOR', 'vi')} (from $EDITOR)")
    console.print()

    print_section("Opening Edit Session")

    print_info("The file will be locked during editing (agent access blocked).")
    print_info("On save, the file will be re-sealed with a new signature.")
    console.print()

    session = EditSession(resolved, root, author=author, editor=editor)

    try:
        changed = session.execute()

        print_section("Result")

        if changed:
            print_success(f"Saved and re-sealed: {file}")
        else:
            print_info("No changes made. File seal unchanged.")
    except AgentContextGuardError as exc:
        print_section("Error")
        print_error(str(exc))
        sys.exit(1)

    print_next_steps([
        ("agent-context-guard status", "View updated protection status"),
        ("agent-context-guard verify", "Verify integrity of all files"),
        ("agent-context-guard audit", "Review the audit trail"),
    ])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  status
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("files", nargs=-1)
def status(files: tuple[str, ...]) -> None:
    """Show protection status of files.

    With no arguments, shows all protected files.
    """
    from agent_context_guard.core.inventory import Inventory
    from agent_context_guard.core.proposals import ProposalManager

    root = _find_root()
    inv = Inventory(root)
    pm = ProposalManager(root)

    print_header("Protection Status")

    if files:
        print_info(f"Showing status for {len(files)} specified file(s).")
    else:
        print_info("Showing status for all protected files.")
    print_usage_hint(
        "agent-context-guard status [<file> ...]",
        "Omit files to show all, or specify paths to filter.",
    )
    console.print()

    targets = [str(Path(f).resolve()) for f in files] if files else inv.list_protected_files()

    if not targets:
        print_section("Result")
        print_info("No protected files found.")
        print_next_steps([
            ("agent-context-guard protect <path>", "Protect markdown files"),
        ])
        return

    rows = []
    for fp in targets:
        if inv.has_file(fp):
            record = inv.get_active_record(fp)
            pending = pm.list_proposals(file_path=fp, status="pending")
            rows.append({
                "file": fp, "state": record.state, "version": record.version,
                "author": record.author, "timestamp": record.timestamp,
                "pending_proposals": len(pending),
            })
        else:
            rows.append({
                "file": fp, "state": "UNPROTECTED", "version": "—",
                "author": "—", "timestamp": None, "pending_proposals": 0,
            })

    print_section("Files")

    out_console.print(make_status_table(rows))

    # Summary
    protected_count = sum(1 for r in rows if r["state"] != "UNPROTECTED")
    pending_count = sum(r["pending_proposals"] for r in rows)
    console.print()
    print_detail("Total files", str(len(rows)))
    print_detail("Protected", str(protected_count))
    if pending_count:
        print_detail("Pending proposals", str(pending_count))

    print_next_steps([
        ("agent-context-guard diff <file>", "View pending proposal diffs"),
        ("agent-context-guard verify", "Verify integrity of all sealed files"),
        ("agent-context-guard edit <file>", "Edit a protected file"),
    ])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  diff
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("file", required=True, type=click.Path(exists=True))
def diff(file: str) -> None:
    """Show pending proposal diffs for a protected file."""
    from agent_context_guard.core.proposals import ProposalManager

    root = _find_root()
    resolved = str(Path(file).resolve())
    pm = ProposalManager(root)
    pending = pm.list_proposals(file_path=resolved, status="pending")

    print_header("Proposal Diffs")

    print_info(f"File: {file}")
    print_usage_hint(
        "agent-context-guard diff <file>",
        "Path to a protected markdown file.",
    )
    console.print()

    if not pending:
        print_section("Result")
        print_info(f"No pending proposals for {file}")
        print_next_steps([
            ("agent-context-guard status", "View all protected files"),
            ("agent-context-guard audit", "Check the audit log"),
        ])
        return

    print_section(f"Pending Proposals ({len(pending)})")

    for p in pending:
        console.print(f"    Proposal:      ", style="dim", end="")
        console.print(p.proposal_id, style="highlight")
        console.print(f"    Agent:         ", style="dim", end="")
        console.print(p.agent_id, style="accent")
        console.print(f"    Time:          ", style="dim", end="")
        console.print(format_timestamp(p.timestamp), style="muted")
        if p.justification:
            console.print(f"    Justification: ", style="dim", end="")
            console.print(p.justification, style="accent")
        console.print()
        if p.diff:
            from rich.syntax import Syntax
            out_console.print(Syntax(p.diff, "diff", theme="monokai", line_numbers=False))
        else:
            print_muted("  (no diff available)")
        console.print()

    print_next_steps([
        ("agent-context-guard approve <file>", "Approve the latest pending proposal"),
        ("agent-context-guard approve <file> -p <id>", "Approve a specific proposal"),
        ("agent-context-guard reject <file>", "Reject a proposal"),
    ])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  approve
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("file", required=True, type=click.Path(exists=True))
@click.option("--proposal-id", "-p", default=None, help="Specific proposal ID.")
@click.option("--author", "-a", default="human", help="Approver identity.")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
def approve(file: str, proposal_id: str | None, author: str, yes: bool) -> None:
    """Approve a pending proposal and apply changes.

    The proposed content replaces the file, which is then re-sealed.
    """
    from agent_context_guard.core.proposals import ProposalManager
    from agent_context_guard.core.inventory import Inventory
    from agent_context_guard.core.seal import seal_file
    from agent_context_guard.core.audit import AuditLogger

    root = _find_root()
    resolved = str(Path(file).resolve())
    pm = ProposalManager(root)
    inv = Inventory(root)
    audit = AuditLogger(root)

    print_header("Approve Proposal")

    print_info(f"File: {file}")
    print_usage_hint(
        "agent-context-guard approve <file> [-p <proposal-id>] [-a <author>] [-y]",
        "Approves the latest pending proposal, or a specific one with -p.",
    )
    console.print()

    if proposal_id:
        proposal = pm.get_proposal(resolved, proposal_id)
    else:
        proposal = pm.get_latest_pending(resolved)
        if not proposal:
            print_section("Result")
            print_info(f"No pending proposals for {file}")
            print_next_steps([
                ("agent-context-guard status", "View protection status"),
                ("agent-context-guard diff <file>", "Check for proposal diffs"),
            ])
            return

    print_section("Proposal Details")

    console.print(f"    Proposal ID:   ", style="dim", end="")
    console.print(proposal.proposal_id, style="highlight")
    console.print(f"    Agent:         ", style="dim", end="")
    console.print(proposal.agent_id, style="accent")
    console.print(f"    Justification: ", style="dim", end="")
    console.print(proposal.justification or "(none)", style="accent")

    if proposal.diff:
        console.print()
        from rich.syntax import Syntax
        out_console.print(Syntax(proposal.diff, "diff", theme="monokai", line_numbers=False))

    if not yes:
        console.print()
        if not confirm("  Approve this proposal?"):
            print_info("Approval cancelled.")
            return

    # Apply changes
    Path(resolved).write_text(proposal.new_content, encoding="utf-8")
    next_ver = inv.next_version(resolved)
    record = seal_file(Path(resolved), root, author=author, version=next_ver, state=STATE_ACTIVE)
    inv.add_record(record)
    pm.approve(resolved, proposal.proposal_id)
    audit.log_approval(resolved, author, proposal.proposal_id)
    audit.log_seal(resolved, author, next_ver, f"Approved proposal {proposal.proposal_id}")

    print_section("Result")

    print_success(f"Proposal approved. File re-sealed as v{next_ver}.")

    print_next_steps([
        ("agent-context-guard status", "Verify updated protection status"),
        ("agent-context-guard verify", "Run integrity check"),
        ("agent-context-guard audit", "Review the audit trail"),
    ])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  reject
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("file", required=True, type=click.Path(exists=True))
@click.option("--proposal-id", "-p", default=None, help="Specific proposal ID.")
def reject(file: str, proposal_id: str | None) -> None:
    """Reject a pending proposal."""
    from agent_context_guard.core.proposals import ProposalManager
    from agent_context_guard.core.audit import AuditLogger

    root = _find_root()
    resolved = str(Path(file).resolve())
    pm = ProposalManager(root)
    audit = AuditLogger(root)

    print_header("Reject Proposal")

    print_info(f"File: {file}")
    print_usage_hint(
        "agent-context-guard reject <file> [-p <proposal-id>]",
        "Rejects the latest pending proposal, or a specific one with -p.",
    )
    console.print()

    if proposal_id:
        proposal = pm.get_proposal(resolved, proposal_id)
    else:
        proposal = pm.get_latest_pending(resolved)
        if not proposal:
            print_section("Result")
            print_info(f"No pending proposals for {file}")
            print_next_steps([
                ("agent-context-guard status", "View protection status"),
            ])
            return

    print_section("Proposal Details")

    console.print(f"    Proposal ID:   ", style="dim", end="")
    console.print(proposal.proposal_id, style="highlight")
    console.print(f"    Agent:         ", style="dim", end="")
    console.print(proposal.agent_id, style="accent")
    console.print(f"    Justification: ", style="dim", end="")
    console.print(proposal.justification or "(none)", style="accent")
    console.print()

    pm.reject(resolved, proposal.proposal_id)
    audit.log_rejection(resolved, "human", proposal.proposal_id)

    print_section("Result")

    print_success(f"Proposal {proposal.proposal_id} rejected.")

    print_next_steps([
        ("agent-context-guard status", "View protection status"),
        ("agent-context-guard diff <file>", "Check for other pending proposals"),
        ("agent-context-guard audit", "Review the audit trail"),
    ])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  audit
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.option("--event", "-e", default=None, help="Filter by event type.")
@click.option("--file", "-f", "file_filter", default=None, help="Filter by file path.")
@click.option("--actor", "-a", default=None, help="Filter by actor.")
@click.option("--limit", "-n", default=50, type=int, help="Max entries to show.")
def audit(event: str | None, file_filter: str | None, actor: str | None, limit: int) -> None:
    """Display the audit log.

    Shows recent guard events including reads, writes, proposals,
    approvals, and policy denials.
    """
    from agent_context_guard.core.audit import AuditLogger

    root = _find_root()
    al = AuditLogger(root)

    print_header("Audit Log")

    print_info("Showing guard event history (append-only log).")
    print_usage_hint(
        "agent-context-guard audit [-e <event>] [-f <file>] [-a <actor>] [-n <limit>]",
        "All filters are optional. Combine them to narrow results.",
    )
    console.print()

    # Show active filters
    if event or file_filter or actor:
        print_section("Active Filters")
        if event:
            print_detail("Event type", event)
        if file_filter:
            print_detail("File", file_filter)
        if actor:
            print_detail("Actor", actor)
        print_detail("Limit", str(limit))

    resolved_file = str(Path(file_filter).resolve()) if file_filter else None
    entries = list(al.iter_entries(
        event=event, file_path=resolved_file, actor=actor, limit=limit,
    ))

    if not entries:
        print_section("Result")
        print_info("No audit entries found matching the filters.")
        print_next_steps([
            ("agent-context-guard audit", "Show all entries (no filters)"),
            ("agent-context-guard audit -e seal", "Filter by seal events"),
            ("agent-context-guard audit -n 100", "Show more entries"),
        ])
        return

    print_section("Entries")

    rows = [e.to_dict() for e in entries]
    out_console.print(make_audit_table(rows))

    console.print()
    print_muted(f"Showing {len(entries)} of {al.entry_count} total entries")

    print_next_steps([
        ("agent-context-guard audit -e <type>", "Filter by event type"),
        ("agent-context-guard audit -f <file>", "Filter by file path"),
        ("agent-context-guard status", "View current protection status"),
    ])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  verify
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
def verify() -> None:
    """CI/CD verification — check all sealed files and guard metadata.

    Exits with code 0 if all files pass, code 1 if any fail.
    Designed for use in CI pipelines.
    """
    from agent_context_guard.core.inventory import Inventory
    from agent_context_guard.core.seal import verify_seal
    from agent_context_guard.core.audit import AuditLogger
    from agent_context_guard.core.selfprotect import verify_all_metadata

    root = _find_root()

    print_header("Verify Integrity")

    print_info("Running full integrity check on all sealed files and metadata.")
    print_info("Suitable for CI/CD pipelines (exit code 0 = pass, 1 = fail).")
    console.print()

    # Phase 1: Verify guard metadata integrity
    print_section("Phase 1: Metadata Integrity")

    meta_failures = verify_all_metadata(root)
    if meta_failures:
        for mf in meta_failures:
            print_error(f"METADATA FAIL: {mf}")
        console.print()
        print_error("Guard metadata integrity check FAILED.")
        print_error("Cannot trust inventory or policy — resolve before continuing.")
        print_next_steps([
            ("agent-context-guard init", "Re-initialize if metadata is corrupted"),
            ("agent-context-guard audit", "Check audit log for tampering events"),
        ])
        sys.exit(1)
    print_success("Guard metadata integrity verified")

    # Phase 2: Verify sealed files
    print_section("Phase 2: Sealed File Verification")

    inv = Inventory(root)
    audit = AuditLogger(root)

    total = 0
    passed = 0
    failed = 0
    errors: list[str] = []

    for record in inv.iter_active():
        total += 1
        try:
            if verify_seal(record, root):
                passed += 1
                audit.log_verify(record.file_path, True)
                print_success(f"PASS: {record.file_path}")
            else:
                failed += 1
                msg = f"Signature mismatch: {record.file_path}"
                errors.append(msg)
                audit.log_verify(record.file_path, False, msg)
                print_error(f"FAIL: {record.file_path} — signature mismatch")
        except SealIntegrityError as exc:
            failed += 1
            errors.append(str(exc))
            audit.log_verify(record.file_path, False, str(exc))
            print_error(f"FAIL: {record.file_path} — {exc}")

    # Results
    print_section("Result")

    if total == 0:
        print_warning("No sealed files to verify.")
        print_next_steps([
            ("agent-context-guard protect <files>", "Protect files first"),
        ])
        sys.exit(0)

    print_detail("Total files checked", str(total))
    print_detail("Passed", str(passed))
    print_detail("Failed", str(failed))

    console.print()
    if failed:
        print_error("Verification FAILED. Protected files may have been tampered with.")
        print_next_steps([
            ("agent-context-guard status", "Check which files are affected"),
            ("agent-context-guard audit", "Review audit log for unauthorized changes"),
        ])
        sys.exit(1)
    else:
        print_success("All sealed files verified successfully.")
        print_next_steps([
            ("agent-context-guard status", "View protection status"),
            ("agent-context-guard run -- <command>", "Run your agent with confidence"),
        ])
        sys.exit(0)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  rotate-keys
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command("rotate-keys")
@click.option("--author", "-a", default="human", help="Author identity.")
def rotate_keys(author: str) -> None:
    """Rotate the signing key and re-sign all sealed files.

    The old key is replaced and all existing seal records are
    re-signed with the new key.
    """
    from agent_context_guard.core.seal import rotate_signing_key, re_seal, verify_seal as vs
    from agent_context_guard.core.inventory import Inventory
    from agent_context_guard.core.audit import AuditLogger

    root = _find_root()
    inv = Inventory(root)
    audit = AuditLogger(root)

    print_header("Rotate Keys")

    print_info("Generating a new signing key and re-signing all sealed files.")
    print_info("The old key will be replaced. This operation cannot be undone.")
    console.print()

    print_section("Key Rotation")

    old_key, new_key = rotate_signing_key(root)
    print_success("New signing key generated")

    re_signed = 0
    for record in inv.iter_active():
        new_record = re_seal(record, new_key)
        inv.replace_record(record, new_record)
        re_signed += 1
        print_success(f"Re-signed: {record.file_path}")

    audit.log_key_rotation(author, f"Re-signed {re_signed} record(s)")

    # Re-sign guard metadata with the new key
    from agent_context_guard.core.selfprotect import sign_all_metadata
    sign_all_metadata(root)
    print_success("Guard metadata re-signed")

    print_section("Result")

    print_detail("Files re-signed", str(re_signed))
    print_detail("Metadata re-signed", "Yes")
    print_success("Key rotation complete.")

    print_next_steps([
        ("agent-context-guard verify", "Verify integrity with new key"),
        ("agent-context-guard status", "View protection status"),
    ])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Entry Point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main() -> None:
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
