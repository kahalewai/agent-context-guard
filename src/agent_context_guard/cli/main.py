"""
Agent Context Guard — cli/main.py
Version: 1.0.1
Author: Kahalewai

CLI entry point. Base command: ``acg``.

Inputs:
    - CLI arguments and options via Click decorators.
    - Protected files and guard metadata from the .agent-context-guard directory.

Outputs:
    - Formatted terminal output via Rich (helpers.py).
    - File modifications (seal, approve, reject, recover, edit).
    - Audit log entries for every operation.

All commands use the green/orange color scheme defined in helpers.py.
Interactive commands (approve, reject, recover) present numbered selection
lists so users never need to type file paths or proposal IDs from memory.
The --help flag is intercepted at every level to render styled man-page
output instead of Click's default plain-text help.
"""

from __future__ import annotations

import difflib, glob, logging, os, platform, shlex, shutil, subprocess, sys, tempfile
from pathlib import Path

import click

from agent_context_guard.core.constants import (
    GUARD_DIR_NAME, CONTEXT_FILE_EXTENSIONS, STATE_ACTIVE,
    guard_dir, get_guard_root, backups_dir,
)
from agent_context_guard.core.exceptions import AgentContextGuardError, SealIntegrityError
from agent_context_guard.cli.helpers import (
    APP_NAME, APP_VERSION, SHIELD_ICON, confirm, console, format_state,
    format_timestamp, get_editor_guidance, interactive_select,
    make_audit_table, make_diff_table, make_proposals_table,
    make_status_table, make_verify_table, out_console, print_command_help,
    print_detail, print_error, print_header, print_info, print_man_page,
    print_muted, print_next_steps, print_section, print_short_help,
    print_success, print_usage_hint, print_warning, rel_path, render_diff,
    render_file_contents,
)


# ── Logging Setup ────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    """Configure logging level based on the --verbose flag."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S")


# ── Guard Root Detection ─────────────────────────────────────────────────────

def _find_root() -> Path:
    """Locate the project root containing .agent-context-guard, or exit."""
    try:
        return get_guard_root()
    except FileNotFoundError:
        print_error(f"No {GUARD_DIR_NAME} directory found.\n    Run 'acg init' in your project root first.")
        sys.exit(1)


def _get_guard(root: Path | None = None):
    """Instantiate a Guard object for the given or detected root."""
    from agent_context_guard.guard import Guard
    r = root or _find_root()
    try:
        return Guard(r)
    except AgentContextGuardError as exc:
        print_error(str(exc))
        sys.exit(1)


def _silent_verify(guard) -> dict[str, str]:
    """Run verification silently and return file_path -> failure_message dict.

    Used by status and recover commands to detect tampered files without
    printing verification output.
    """
    from agent_context_guard.core.seal import verify_and_read
    failures: dict[str, str] = {}
    for record in guard.inventory.iter_active():
        try:
            verify_and_read(record, guard.root)
        except SealIntegrityError as exc:
            failures[record.file_path] = str(exc)
    return failures


# ── Custom Click help formatter ──────────────────────────────────────────────
# Override Click's built-in help rendering so that `acg --help` and
# `acg <command> --help` produce styled output matching the application theme.

class StyledGroup(click.Group):
    """Click group that shows the styled man page instead of default help."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Override: render the full styled man page for --help."""
        print_man_page()

    def format_usage(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Override: suppress default usage line (man page has its own)."""
        pass


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Main Group — bare `acg` shows short help, `acg --help` shows man page
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@click.group(
    cls=StyledGroup,
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.version_option(version="1.0.1", prog_name="Agent Context Guard")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Agent Context Guard — Integrity verification for AI agent context files."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)
    if ctx.invoked_subcommand is None:
        # Bare `acg` with no subcommand — show the concise help
        print_short_help()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  init
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.option("--path", "-p", default=".", type=click.Path(exists=True), help="Directory to initialize.")
def init(path: str) -> None:
    """Initialize Agent Context Guard in a directory."""
    from agent_context_guard.core.seal import generate_signing_key
    from agent_context_guard.core.audit import AuditLogger
    from agent_context_guard.core.constants import guard_dir as gd_fn, keys_dir, proposals_dir, locks_dir, inventory_path, policy_path
    from agent_context_guard.core.selfprotect import sign_all_metadata

    root = Path(path).resolve()
    gd = gd_fn(root)
    print_header("Initialize")
    if gd.exists():
        print_warning(f"Guard directory already exists at {gd}")
        print_next_steps([("acg protect <files>", "Protect your context files"), ("acg status", "View currently protected files")])
        return
    print_info(f"Initializing in: {root}")
    console.print()
    print_section("Setting Up")
    gd.mkdir(parents=True)
    keys_dir(root).mkdir(parents=True, exist_ok=True)
    proposals_dir(root).mkdir(parents=True, exist_ok=True)
    locks_dir(root).mkdir(parents=True, exist_ok=True)
    backups_dir(root).mkdir(parents=True, exist_ok=True)
    generate_signing_key(root)
    print_success("Signing key generated")
    inventory_path(root).write_text('{"version": 1, "files": {}}', encoding="utf-8")
    print_success("Inventory created")
    policy_text = "# Agent Context Guard policy\n# See documentation for full policy options.\n\nread:\n  allow: all_agents\n\nwrite:\n  allow: none\n\npropose:\n  allow: all_agents\n\napprove:\n  allow: humans\n"
    policy_path(root).write_text(policy_text, encoding="utf-8")
    print_success("Default policy created")
    AuditLogger(root).log_runtime("initialized", f"Guard initialized at {root}")
    print_success("Audit log initialized")
    sign_all_metadata(root)
    print_success("Guard metadata integrity signatures created")
    (gd / ".gitignore").write_text("keys/\nlocks/\nbackups/\n", encoding="utf-8")
    print_success("Created .gitignore (keys excluded from VCS)")
    print_section("Result")
    print_success("Initialization complete!")
    print_detail("Guard directory", str(gd))
    print_next_steps([("acg protect <path>", "Protect your agent context files"), ("acg status", "View protection status")])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  protect — with backup creation on initial protection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("files", nargs=-1, required=True)
@click.option("--author", "-a", default="human", help="Author identity for seal records.")
def protect(files: tuple[str, ...], author: str) -> None:
    """Register context files for protection."""
    from agent_context_guard.core.seal import seal_file
    root = _find_root()
    guard = _get_guard(root)
    print_header("Protect Files")
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
            if mp.is_file() and mp.suffix.lower() in CONTEXT_FILE_EXTENSIONS:
                expanded.append(mp)
            elif mp.is_file():
                print_warning(f"Skipping unsupported file type: {mp.name}")
    if not expanded:
        print_error("No supported context files to protect.")
        sys.exit(1)
    count = 0
    for fp in expanded:
        resolved = str(fp)
        if guard.inventory.has_file(resolved):
            print_warning(f"Already protected: {fp.name}")
            continue
        # Create a backup of the original file before sealing
        guard.backup_file(fp)
        version = guard.inventory.next_version(resolved)
        record = seal_file(fp, root, author=author, version=version, state=STATE_ACTIVE)
        guard.inventory.add_record(record)
        guard.audit.log_seal(resolved, author, version, f"Initial protection of {fp.name}")
        print_success(f"Protected: {fp.name} (v{version})")
        count += 1
    print_section("Result")
    if count:
        print_success(f"{count} file(s) now under protection.")
    else:
        print_info("No new files to protect.")
    print_next_steps([("acg status", "View all protected files"), ("acg run -- python agent.py", "Run your agent under the guard")])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  run
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("command", nargs=-1, required=True)
def run(command: tuple[str, ...]) -> None:
    """Run a command with pre-flight seal verification."""
    root = _find_root()
    cmd = list(command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print_header("Run")
        print_error("No command specified.")
        print_usage_hint("acg run -- <command>")
        sys.exit(1)
    print_header("Run")
    print_info(f"Command: {' '.join(cmd)}")
    console.print()
    print_section("Pre-flight Verification")
    guard = _get_guard(root)
    failures = guard.verify_all()
    if failures:
        print_error(f"Seal verification failed for {len(failures)} file(s):")
        for f in failures:
            print_error(f"  {f}")
        print_next_steps([("acg verify", "Run full integrity check"), ("acg recover", "Recover a tampered file")])
        sys.exit(2)
    print_success(f"All {guard.protected_file_count} file(s) verified")
    print_info("Running command...")
    console.print()
    run_env = {**os.environ, "ACG_GUARD_ROOT": str(root)}
    guard.audit.log_runtime("subprocess_started", f"Command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, env=run_env, cwd=root)
        exit_code = result.returncode
    except FileNotFoundError:
        print_error(f"Command not found: {cmd[0]}")
        exit_code = 127
    except KeyboardInterrupt:
        print_info("Interrupted by user.")
        exit_code = 130
    guard.audit.log_runtime("subprocess_exited", f"Exit code: {exit_code}")
    print_section("Result")
    if exit_code == 0:
        print_success(f"Command completed successfully (exit code: {exit_code})")
    else:
        print_warning(f"Command exited with code: {exit_code}")
    print_next_steps([("acg verify", "Verify file integrity after run"), ("acg audit", "Review the audit log")])
    sys.exit(exit_code)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  edit — with OS-aware editor guidance, backup, and visual diff rendering
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("file", required=True, type=click.Path(exists=True))
@click.option("--author", "-a", default="human", help="Author identity.")
@click.option("--editor", "-e", default=None, help="Editor command (e.g. notepad, nano, 'code --wait').")
def edit(file: str, author: str, editor: str | None) -> None:
    """Open a human edit session for a protected file.

    Launches your editor with a temporary copy of the file. After you save
    and close the editor, acg shows a diff of your changes and asks for
    confirmation before re-sealing.

    The editor is resolved in this order:
      1. --editor flag (e.g. --editor notepad)
      2. $EDITOR environment variable
      3. Platform default (vi on Unix, notepad on Windows)

    For GUI editors like VS Code, use the --wait flag so acg knows when
    you are done editing (e.g. --editor "code --wait").
    """
    from agent_context_guard.core.seal import seal_file
    root = _find_root()
    guard = _get_guard(root)
    resolved = str(Path(file).resolve())

    # Resolve editor: flag > $EDITOR > platform default
    if editor:
        editor_cmd = editor
    elif os.environ.get("EDITOR"):
        editor_cmd = os.environ["EDITOR"]
    elif platform.system().lower() == "windows":
        editor_cmd = "notepad"
    else:
        editor_cmd = "vi"

    print_header("Edit Session")
    print_info(f"File: {file}")
    print_info(f"Editor: {editor_cmd}")

    # TTY check — edit requires an interactive terminal
    if not (hasattr(sys.stdin, "isatty") and sys.stdin.isatty()):
        print_error("Edit sessions require an interactive terminal (TTY).\n    Non-interactive processes cannot edit protected files.")
        sys.exit(1)

    # Read the original file content before editing
    original_content = Path(resolved).read_text(encoding="utf-8")
    guard.audit.log_runtime("edit_started", f"File: {resolved}, Author: {author}")

    # Create a backup before editing so we can recover later
    guard.backup_file(resolved)

    # Create a temp file with the current content for editing
    suffix = Path(resolved).suffix or ".md"
    fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix="acg_edit_")
    os.close(fd)
    tmp = Path(tmp_path)
    try:
        tmp.write_text(original_content, encoding="utf-8")
        # Split the editor command to handle multi-word editors like "code --wait"
        try:
            editor_parts = shlex.split(editor_cmd)
            result = subprocess.run(editor_parts + [str(tmp)])
            if result.returncode != 0:
                print_error(f"Editor exited with code {result.returncode}")
                sys.exit(1)
        except FileNotFoundError:
            print_error(f"Editor '{editor_cmd}' not found.")
            console.print()
            # Show OS-specific guidance for finding/configuring an editor
            print_section("Editor Help")
            guidance = get_editor_guidance()
            for line in guidance.splitlines():
                console.print(f"    {line}", style="dim")
            console.print()
            sys.exit(1)
        new_content = tmp.read_text(encoding="utf-8")
    finally:
        tmp.unlink(missing_ok=True)

    # Check if changes were made
    if new_content == original_content:
        print_info("No changes made.")
        guard.audit.log_runtime("edit_no_changes", f"File: {resolved}")
        return

    # Show visual diff of changes using the custom renderer
    print_section("Changes")
    diff_lines = list(difflib.unified_diff(
        original_content.splitlines(keepends=True), new_content.splitlines(keepends=True),
        fromfile=f"a/{Path(file).name}", tofile=f"b/{Path(file).name}",
    ))
    if diff_lines:
        render_diff("".join(diff_lines))

    # Confirm save
    console.print()
    if not confirm("  Save changes and re-seal?"):
        print_info("Edit cancelled.")
        return

    # Atomic write: temp file in same directory then rename
    fd2, tmp_write = tempfile.mkstemp(dir=Path(resolved).parent, suffix=".tmp", prefix="acg_save_")
    try:
        with open(fd2, "w", encoding="utf-8") as f:
            f.write(new_content)
        Path(tmp_write).replace(resolved)
    except Exception:
        Path(tmp_write).unlink(missing_ok=True)
        raise

    # Re-seal the file with the new content
    next_ver = guard.inventory.next_version(resolved)
    record = seal_file(Path(resolved), root, author=author, version=next_ver, state=STATE_ACTIVE)
    guard.inventory.add_record(record)
    guard.audit.log_runtime("edit_saved", f"File: {resolved}, Version: {next_ver}")
    print_section("Result")
    print_success(f"Saved and re-sealed: {file} (v{next_ver})")
    print_next_steps([("acg status", "View updated protection status"), ("acg verify", "Verify integrity of all files")])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  status — runs silent verify first so TAMPERED state is reflected
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("files", nargs=-1)
def status(files: tuple[str, ...]) -> None:
    """Show protection status of files (includes silent integrity check)."""
    guard = _get_guard()
    print_header("Protection Status")
    targets = [str(Path(f).resolve()) for f in files] if files else guard.inventory.list_protected_files()
    if not targets:
        print_info("No protected files found.")
        print_next_steps([("acg protect <path>", "Protect context files")])
        return
    # Silent verify so status reflects actual integrity
    integrity_failures = _silent_verify(guard)
    rows = []
    tampered_files = []
    for fp in targets:
        info = guard.status(fp)
        state = info.get("state", "UNPROTECTED")
        if fp in integrity_failures:
            state = "TAMPERED"
            tampered_files.append(fp)
        rows.append({
            "file": fp, "state": state, "version": info.get("version", "—"),
            "author": info.get("author", "—"), "timestamp": info.get("timestamp"),
            "pending_proposals": info.get("pending_proposals", 0),
        })
    print_section("Files")
    out_console.print(make_status_table(rows))
    console.print()
    protected = sum(1 for r in rows if r["state"] not in ("UNPROTECTED",))
    pending = sum(r["pending_proposals"] for r in rows)
    print_detail("Total files", str(len(rows)))
    print_detail("Protected", str(protected))
    if tampered_files:
        print_detail("Tampered", str(len(tampered_files)))
        print_warning(f"{len(tampered_files)} file(s) have been modified outside the guard!")
    if pending:
        print_detail("Pending proposals", str(pending))
    # Contextual next steps
    steps = []
    if tampered_files:
        steps.append(("acg recover", "Review and resolve file tampering"))
    if pending:
        steps.append(("acg diff", "View pending proposal diffs"))
    steps.append(("acg verify", "Run full integrity verification"))
    steps.append(("acg edit <file>", "Edit a protected file"))
    print_next_steps(steps)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  diff — visual interface with proposal listing and custom diff rendering
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("file", required=False, default=None, type=click.Path(exists=True))
def diff(file: str | None) -> None:
    """Show pending proposal diffs for protected file(s).

    If no file is specified, lists all files with pending proposals
    so you can select which to review.
    """
    guard = _get_guard()
    print_header("Proposal Diffs")
    if file is None:
        # List all files with pending proposals and let user select
        all_pending = guard.proposals.list_proposals(status="pending")
        if not all_pending:
            print_info("No pending proposals found.")
            print_next_steps([("acg status", "View protection status")])
            return
        # Build unique file list for selection
        file_map: dict[str, list] = {}
        for p in all_pending:
            file_map.setdefault(p.file_path, []).append(p)
        print_section("Files with Pending Proposals")
        items = [
            {"label": Path(fp).name, "detail": f"({len(props)} proposal(s))  {rel_path(fp)}", "file_path": fp}
            for fp, props in file_map.items()
        ]
        selected = interactive_select(items, prompt="Select a file to view diffs")
        if selected is None:
            print_info("No file selected.")
            return
        resolved = selected["file_path"]
        pending = file_map[resolved]
    else:
        resolved = str(Path(file).resolve())
        pending = guard.proposals.list_proposals(file_path=resolved, status="pending")

    print_info(f"File: {rel_path(resolved)}")
    if not pending:
        print_info("No pending proposals for this file.")
        print_next_steps([("acg status", "View protection status")])
        return
    print_section(f"Pending Proposals ({len(pending)})")
    out_console.print(make_proposals_table([p.to_dict() for p in pending]))
    console.print()
    # Show each proposal diff with the custom visual renderer
    for p in pending:
        print_section(f"Diff — {p.proposal_id}")
        console.print(f"    Agent:         ", style="dim", end="")
        console.print(p.agent_id, style="dark_green")
        console.print(f"    Time:          ", style="dim", end="")
        console.print(format_timestamp(p.timestamp), style="muted")
        if p.justification:
            console.print(f"    Justification: ", style="dim", end="")
            console.print(p.justification, style="dark_orange")
        console.print()
        if p.diff:
            render_diff(p.diff)
        console.print()
    print_next_steps([("acg approve", "Approve a pending proposal"), ("acg reject", "Reject a proposal")])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  approve — interactive file and proposal selection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("file", required=False, default=None, type=click.Path(exists=True))
@click.option("--proposal-id", "-p", default=None, help="Specific proposal ID.")
@click.option("--author", "-a", default="human", help="Approver identity.")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
def approve(file: str | None, proposal_id: str | None, author: str, yes: bool) -> None:
    """Approve a pending proposal and apply changes.

    If no file is specified, lists all files with pending proposals and
    lets you select one interactively. If multiple proposals exist for
    the selected file, you can choose which to approve.
    """
    from agent_context_guard.core.seal import seal_file
    root = _find_root()
    guard = _get_guard(root)
    print_header("Approve Proposal")

    # If no file specified, show interactive file selector
    if file is None:
        all_pending = guard.proposals.list_proposals(status="pending")
        if not all_pending:
            print_info("No pending proposals to approve.")
            print_next_steps([("acg status", "View protection status")])
            return
        # Build unique file list for selection
        file_map: dict[str, list] = {}
        for p in all_pending:
            file_map.setdefault(p.file_path, []).append(p)
        print_section("Files with Pending Proposals")
        items = [
            {"label": Path(fp).name, "detail": f"({len(props)} proposal(s))  {rel_path(fp)}", "file_path": fp}
            for fp, props in file_map.items()
        ]
        if not items:
            print_info("No pending proposals to approve.")
            return
        selected = interactive_select(items, prompt="Select a file")
        if selected is None:
            print_info("No file selected.")
            return
        resolved = selected["file_path"]
    else:
        resolved = str(Path(file).resolve())

    # List pending proposals for the selected file
    file_pending = guard.proposals.list_proposals(file_path=resolved, status="pending")
    if not file_pending:
        print_info(f"No pending proposals for {Path(resolved).name}")
        print_next_steps([("acg status", "View protection status")])
        return

    print_section(f"Pending Proposals for {Path(resolved).name}")
    out_console.print(make_proposals_table([p.to_dict() for p in file_pending]))
    console.print()

    # Select specific proposal
    if proposal_id:
        proposal = guard.proposals.get_proposal(resolved, proposal_id)
    elif len(file_pending) == 1:
        proposal = file_pending[0]
    else:
        # Multiple proposals — let user pick
        print_section("Select Proposal to Approve")
        proposal_items = [
            {
                "label": p.proposal_id,
                "detail": f"by {p.agent_id} — {(p.justification or 'no justification')[:50]}",
                "index": str(i),
            }
            for i, p in enumerate(file_pending)
        ]
        selected_p = interactive_select(proposal_items, prompt="Select a proposal")
        if selected_p is None:
            print_info("No proposal selected.")
            return
        proposal = file_pending[int(selected_p["index"])]

    # Show proposal details and diff
    print_section("Proposal to Approve")
    console.print(f"    Proposal ID:   ", style="dim", end="")
    console.print(proposal.proposal_id, style="dark_orange")
    console.print(f"    Agent:         ", style="dim", end="")
    console.print(proposal.agent_id, style="dark_green")
    if proposal.justification:
        console.print(f"    Justification: ", style="dim", end="")
        console.print(proposal.justification, style="dark_orange")
    if proposal.diff:
        console.print()
        render_diff(proposal.diff)

    # Confirm approval
    if not yes:
        console.print()
        if not confirm("  Approve this proposal and apply changes?"):
            print_info("Cancelled.")
            return

    # Backup before applying changes
    guard.backup_file(resolved)

    # Apply changes: write new content, re-seal, update proposal status
    Path(resolved).write_text(proposal.new_content, encoding="utf-8")
    next_ver = guard.inventory.next_version(resolved)
    record = seal_file(Path(resolved), root, author=author, version=next_ver, state=STATE_ACTIVE)
    guard.inventory.add_record(record)
    guard.proposals.approve(resolved, proposal.proposal_id)
    guard.audit.log_approval(resolved, author, proposal.proposal_id)
    guard.audit.log_seal(resolved, author, next_ver, f"Approved proposal {proposal.proposal_id}")
    print_section("Result")
    print_success(f"Proposal approved. File re-sealed as v{next_ver}.")
    print_next_steps([("acg status", "Verify updated status"), ("acg verify", "Run integrity check")])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  reject — interactive file and proposal selection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("file", required=False, default=None, type=click.Path(exists=True))
@click.option("--proposal-id", "-p", default=None, help="Specific proposal ID.")
def reject(file: str | None, proposal_id: str | None) -> None:
    """Reject a pending proposal.

    If no file is specified, lists all files with pending proposals and
    lets you select one interactively. Shows the proposal diff before
    confirming the rejection.
    """
    guard = _get_guard()
    print_header("Reject Proposal")

    # If no file specified, show interactive file selector
    if file is None:
        all_pending = guard.proposals.list_proposals(status="pending")
        if not all_pending:
            print_info("No pending proposals to reject.")
            print_next_steps([("acg status", "View protection status")])
            return
        file_map: dict[str, list] = {}
        for p in all_pending:
            file_map.setdefault(p.file_path, []).append(p)
        print_section("Files with Pending Proposals")
        items = [
            {"label": Path(fp).name, "detail": f"({len(props)} proposal(s))  {rel_path(fp)}", "file_path": fp}
            for fp, props in file_map.items()
        ]
        if not items:
            print_info("No pending proposals to reject.")
            return
        selected = interactive_select(items, prompt="Select a file")
        if selected is None:
            print_info("No file selected.")
            return
        resolved = selected["file_path"]
    else:
        resolved = str(Path(file).resolve())

    # List pending proposals for the selected file
    file_pending = guard.proposals.list_proposals(file_path=resolved, status="pending")
    if not file_pending:
        print_info(f"No pending proposals for {Path(resolved).name}")
        print_next_steps([("acg status", "View protection status")])
        return

    print_section(f"Pending Proposals for {Path(resolved).name}")
    out_console.print(make_proposals_table([p.to_dict() for p in file_pending]))
    console.print()

    # Select specific proposal
    if proposal_id:
        proposal = guard.proposals.get_proposal(resolved, proposal_id)
    elif len(file_pending) == 1:
        proposal = file_pending[0]
    else:
        print_section("Select Proposal to Reject")
        proposal_items = [
            {
                "label": p.proposal_id,
                "detail": f"by {p.agent_id} — {(p.justification or 'no justification')[:50]}",
                "index": str(i),
            }
            for i, p in enumerate(file_pending)
        ]
        selected_p = interactive_select(proposal_items, prompt="Select a proposal")
        if selected_p is None:
            print_info("No proposal selected.")
            return
        proposal = file_pending[int(selected_p["index"])]

    # Show proposal details and diff before rejection
    print_section("Proposal to Reject")
    console.print(f"    Proposal ID:   ", style="dim", end="")
    console.print(proposal.proposal_id, style="dark_orange")
    console.print(f"    Agent:         ", style="dim", end="")
    console.print(proposal.agent_id, style="dark_green")
    if proposal.justification:
        console.print(f"    Justification: ", style="dim", end="")
        console.print(proposal.justification, style="dark_orange")
    if proposal.diff:
        console.print()
        render_diff(proposal.diff)

    # Confirm rejection
    console.print()
    if not confirm("  Reject this proposal?"):
        print_info("Cancelled.")
        return
    guard.proposals.reject(resolved, proposal.proposal_id)
    guard.audit.log_rejection(resolved, "human", proposal.proposal_id)
    print_section("Result")
    print_success(f"Proposal {proposal.proposal_id} rejected.")
    print_next_steps([("acg status", "View updated status"), ("acg diff", "View remaining proposals")])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  recover — interactive file selection with diff and rollback/accept/cancel
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.argument("file", required=False, default=None, type=click.Path(exists=True))
@click.option("--author", "-a", default="human", help="Author identity.")
def recover(file: str | None, author: str) -> None:
    """Recover from file tampering — view diff, then rollback or accept.

    When a protected file has been modified outside the guard, this command
    shows exactly what changed and lets you choose:

      - Rollback: restore the file to its last sealed content
      - Accept: re-seal the file with the current (changed) content
      - Cancel: take no action

    If no file is specified, scans all protected files for tampering and
    presents the tampered files for interactive selection.
    """
    from agent_context_guard.core.seal import seal_file, compute_file_hash
    root = _find_root()
    guard = _get_guard(root)
    print_header("Recover File")

    # If no file specified, detect all tampered files and let user pick
    if file is None:
        integrity_failures = _silent_verify(guard)
        if not integrity_failures:
            print_success("All protected files have valid integrity — no recovery needed.")
            print_next_steps([("acg status", "View protection status")])
            return
        # Present tampered files for selection
        print_warning(f"{len(integrity_failures)} file(s) have been modified outside the guard.")
        print_section("Tampered Files")
        items = [
            {"label": Path(fp).name, "detail": rel_path(fp), "file_path": fp}
            for fp in integrity_failures.keys()
        ]
        selected = interactive_select(items, prompt="Select a file to recover")
        if selected is None:
            print_info("No file selected.")
            return
        resolved = selected["file_path"]
    else:
        resolved = str(Path(file).resolve())

    # Verify the file is protected
    if not guard.inventory.has_file(resolved):
        print_error(f"File is not protected: {rel_path(resolved)}")
        print_next_steps([("acg protect <file>", "Protect the file first")])
        sys.exit(1)

    record = guard.inventory.get_active_record(resolved)

    # Check if file actually needs recovery
    current_hash = compute_file_hash(Path(resolved))
    if current_hash == record.content_hash:
        print_success(f"File integrity OK — no recovery needed for {Path(resolved).name}")
        print_next_steps([("acg status", "View protection status")])
        return

    # File has been changed — show visual summary
    print_warning(f"File has been modified outside the guard: {Path(resolved).name}")
    console.print()
    print_section("Change Summary")
    out_console.print(make_diff_table([{
        "file": resolved, "changed": True,
        "expected_hash": record.content_hash, "current_hash": current_hash,
    }]))
    console.print()

    # Try to get original content for diff display
    current_content = Path(resolved).read_text(encoding="utf-8")
    original_content = _try_get_original(guard, record, root)

    if original_content is not None:
        # Backup exists — show the visual diff so user can see exactly what changed
        print_section("Diff (original → current)")
        diff_lines = list(difflib.unified_diff(
            original_content.splitlines(keepends=True),
            current_content.splitlines(keepends=True),
            fromfile=f"sealed/{Path(resolved).name}", tofile=f"current/{Path(resolved).name}",
        ))
        if diff_lines:
            render_diff("".join(diff_lines))
        console.print()

        # Present full recovery options (rollback available)
        print_section("Recovery Options")
        console.print("    [R] Rollback  — restore file to last sealed version", style="dark_green")
        console.print("    [A] Accept    — re-seal file with current content", style="dark_orange")
        console.print("    [C] Cancel    — take no action", style="dim")
        console.print()
        try:
            choice = input("  Choose action [R/A/C]: ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            choice = "C"
    else:
        # No backup — show current file contents for review, only accept or cancel
        print_warning("No backup of the original sealed content was found.")
        print_info("Showing current file contents for review.")
        console.print()
        render_file_contents(current_content, Path(resolved).name)
        console.print()

        # Without a backup, rollback is not possible
        print_section("Recovery Options")
        console.print("    [A] Accept    — re-seal file with current content", style="dark_orange")
        console.print("    [C] Cancel    — take no action", style="dim")
        console.print()
        try:
            choice = input("  Choose action [A/C]: ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            choice = "C"

    if choice == "R" and original_content is not None:
        # Rollback to original sealed content
        Path(resolved).write_text(original_content, encoding="utf-8")
        guard.audit.log_recover(resolved, author, "rollback", f"Restored to sealed v{record.version}")
        print_section("Result")
        print_success(f"File rolled back to sealed version (v{record.version}).")
        print_next_steps([("acg status", "Verify restored status"), ("acg verify", "Run integrity check")])
    elif choice == "A":
        # Accept current content and re-seal
        next_ver = guard.inventory.next_version(resolved)
        new_record = seal_file(Path(resolved), root, author=author, version=next_ver, state=STATE_ACTIVE)
        guard.inventory.add_record(new_record)
        guard.audit.log_recover(resolved, author, "accept", f"Re-sealed as v{next_ver} with modified content")
        guard.audit.log_seal(resolved, author, next_ver, "Recovery accept — re-sealed modified content")
        # Create a backup of the newly accepted content
        guard.backup_file(resolved)
        print_section("Result")
        print_success(f"File re-sealed with current content as v{next_ver}.")
        print_next_steps([("acg status", "Verify updated status"), ("acg verify", "Run integrity check")])
    else:
        print_info("No action taken.")


def _try_get_original(guard, record, root: Path) -> str | None:
    """Try to retrieve the original sealed content for a file.

    Attempts to locate a backup file whose raw-bytes hash matches the
    sealed record's content_hash. Uses read_bytes() for hash comparison
    to match the behavior of compute_file_hash() — this is critical on
    Windows where read_text() normalizes CRLF to LF, producing a
    different hash than the original raw bytes.

    After finding a matching backup, the content is decoded to a string
    for display and rollback.

    Args:
        guard:  The Guard instance.
        record: The SealRecord for the file.
        root:   The project root path.

    Returns:
        The original file content as a string, or None if no matching backup.
    """
    from agent_context_guard.core.seal import compute_hash
    bdir = backups_dir(root)
    if not bdir.exists():
        return None

    target_hash = record.content_hash
    safe_name = Path(record.file_path).name

    # First pass: try backups matching the filename (most common case)
    for backup in sorted(bdir.glob(f"{safe_name}.*"), reverse=True):
        try:
            raw = backup.read_bytes()
            if compute_hash(raw) == target_hash:
                return raw.decode("utf-8")
        except Exception:
            continue

    # Second pass: scan all backup files for a hash match (fallback)
    for backup in sorted(bdir.iterdir(), reverse=True):
        if not backup.is_file():
            continue
        try:
            raw = backup.read_bytes()
            if compute_hash(raw) == target_hash:
                return raw.decode("utf-8")
        except Exception:
            continue

    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  audit — with archive info and failsafe details
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
@click.option("--event", "-e", default=None, help="Filter by event type.")
@click.option("--file", "-f", "file_filter", default=None, help="Filter by file path.")
@click.option("--actor", "-a", default=None, help="Filter by actor.")
@click.option("--limit", "-n", default=50, type=int, help="Max entries to show.")
@click.option("--archives", is_flag=True, help="List archived audit logs.")
def audit(event: str | None, file_filter: str | None, actor: str | None, limit: int, archives: bool) -> None:
    """Display the audit log."""
    guard = _get_guard()
    print_header("Audit Log")
    if archives:
        archive_list = guard.audit.list_archives()
        if not archive_list:
            print_info("No archived audit logs found.")
        else:
            print_section("Archived Logs")
            for a in archive_list:
                console.print(f"    {a.name}", style="dark_green", end="  ")
                size_kb = a.stat().st_size / 1024
                console.print(f"({size_kb:.1f} KB)", style="muted")
        console.print()
        print_info(f"Audit failsafe: logs auto-archive at {guard.audit._max_entries} entries.")
        print_info("Set ACG_AUDIT_MAX_ENTRIES to adjust the threshold.")
        return
    resolved_file = str(Path(file_filter).resolve()) if file_filter else None
    entries = list(guard.audit.iter_entries(event=event, file_path=resolved_file, actor=actor, limit=limit))
    if not entries:
        print_info("No audit entries found.")
        return
    print_section("Entries")
    out_console.print(make_audit_table([e.to_dict() for e in entries]))
    console.print()
    print_muted(f"Showing {len(entries)} of {guard.audit.entry_count} total entries")
    print_muted(f"Auto-archive threshold: {guard.audit._max_entries} entries")
    print_next_steps([("acg audit --archives", "View archived audit logs"), ("acg audit -n 100", "Show more entries")])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  verify — visual table showing each file and verification result
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command()
def verify() -> None:
    """CI/CD verification — check all sealed files and guard metadata.

    Displays a table showing each protected file, its verification result
    (PASS/FAIL), and hash comparison. Exits with code 0 if all files
    pass, code 1 if any fail.
    """
    from agent_context_guard.core.seal import verify_and_read, compute_file_hash
    guard = _get_guard()
    print_header("Verify Integrity")

    # Verify guard metadata first
    from agent_context_guard.core.selfprotect import verify_all_metadata
    meta_failures = verify_all_metadata(guard.root)

    # Verify each protected file and collect results for the table
    verify_rows: list[dict[str, str]] = []
    file_failures: list[str] = []
    for record in guard.inventory.iter_active():
        expected_hash = record.content_hash
        try:
            actual_hash = compute_file_hash(Path(record.file_path))
        except FileNotFoundError:
            actual_hash = "FILE MISSING"
        try:
            verify_and_read(record, guard.root)
            verify_rows.append({
                "file": record.file_path,
                "result": "PASS",
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
            })
            guard.audit.log_verify(record.file_path, success=True)
        except SealIntegrityError as exc:
            verify_rows.append({
                "file": record.file_path,
                "result": "FAIL",
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
            })
            file_failures.append(str(exc))
            guard.audit.log_verify(record.file_path, success=False, detail=str(exc))

    # Display the verification results table
    print_section("Files")
    if verify_rows:
        out_console.print(make_verify_table(verify_rows))
    else:
        print_info("No protected files to verify.")
    console.print()

    # Summary
    total = len(verify_rows)
    passed = sum(1 for r in verify_rows if r["result"] == "PASS")
    failed = total - passed
    all_failures = meta_failures + file_failures

    print_section("Result")
    print_detail("Total files", str(total))
    print_detail("Passed", str(passed))
    if failed:
        print_detail("Failed", str(failed))
    if meta_failures:
        print_detail("Metadata errors", str(len(meta_failures)))
        for mf in meta_failures:
            print_error(mf)

    if all_failures:
        console.print()
        print_error("Verification FAILED.")
        print_next_steps([("acg recover", "Recover tampered files"), ("acg status", "View protection status")])
        sys.exit(1)
    else:
        console.print()
        print_success("All sealed files verified successfully.")
        print_next_steps([("acg status", "View protection status"), ("acg audit", "Review audit log")])
        sys.exit(0)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  rotate-keys
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command("rotate-keys")
@click.option("--author", "-a", default="human", help="Author identity.")
def rotate_keys(author: str) -> None:
    """Rotate the signing key and re-sign all sealed files."""
    from agent_context_guard.core.seal import rotate_signing_key, re_seal
    from agent_context_guard.core.selfprotect import sign_all_metadata
    root = _find_root()
    guard = _get_guard(root)
    print_header("Rotate Keys")
    print_section("Key Rotation")
    old_key, new_key = rotate_signing_key(root)
    print_success("New signing key generated")
    re_signed = 0
    for record in guard.inventory.iter_active():
        new_record = re_seal(record, new_key)
        guard.inventory.replace_record(record, new_record)
        re_signed += 1
        print_success(f"Re-signed: {record.file_path}")
    guard.audit.log_key_rotation(author, f"Re-signed {re_signed} record(s)")
    sign_all_metadata(root)
    print_success("Guard metadata re-signed")
    print_section("Result")
    print_detail("Files re-signed", str(re_signed))
    print_success("Key rotation complete.")
    print_next_steps([("acg verify", "Verify re-signed files"), ("acg status", "View protection status")])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Entry Point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main() -> None:
    cli()


if __name__ == "__main__":
    main()
