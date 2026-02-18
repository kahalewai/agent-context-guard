"""
Agent Context Guard — cli/helpers.py
Version: 1.0.1
Author: Kahalewai

Terminal output helpers. Provides consistent, branded terminal output
using Rich. All CLI commands use these helpers for uniform formatting.
Separated from main.py to keep command logic readable.

Inputs:
    - Structured data (dicts, lists) for tables, diffs, and selectors.
    - Raw strings for messages and labels.

Outputs:
    - Formatted Rich console output to stderr (status messages) and
      stdout (tables, diffs, interactive selectors).

Color scheme: dark green (primary) and dark orange (accent).
All UI elements strictly use green/orange — no blue, purple, cyan, or magenta.
"""

from __future__ import annotations

import platform
import sys
from datetime import datetime, timezone
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ── Theme — dark green / dark orange ──────────────────────────────────────────
# All colors are constrained to the green/orange palette. File paths use
# dark_green instead of blue, and accent/highlight elements use dark_orange
# instead of purple/magenta. This ensures a visually consistent CLI.

ACG_THEME = Theme({
    "info":             "dark_green",
    "success":          "bold dark_green",
    "warning":          "dark_orange",
    "error":            "bold red",
    "muted":            "dim",
    "highlight":        "bold dark_orange",
    "file":             "dark_green underline",
    "header":           "bold dark_green",
    "accent":           "bold white",
    "brand":            "dark_green",
    "brand_accent":     "dark_orange",
    "command":          "bold dark_green",
    "metavar":          "dark_orange",
    "diff.add":         "bold green",
    "diff.remove":      "bold red",
    "diff.hunk":        "dark_orange",
    "diff.meta":        "dim",
    "state.SEALED":     "dark_green",
    "state.ACTIVE":     "bold dark_green",
    "state.DEPRECATED": "dark_orange",
    "state.REVOKED":    "red",
    "state.UNSEALED":   "dim",
    "state.TAMPERED":   "bold red",
})

console = Console(theme=ACG_THEME, stderr=True, highlight=False)
out_console = Console(theme=ACG_THEME, highlight=False)

APP_NAME = "Agent Context Guard"
APP_VERSION = "v1.0.1"
APP_TAGLINE = "Integrity verification for AI agent context files"
SHIELD_ICON = "🛡️"
HEADER_WIDTH = 60
SECTION_CHAR = "─"

# ── Supported file extension groups (for display in help) ─────────────────────
SUPPORTED_FILES_DISPLAY = (
    "Markdown:   .md  .markdown  .mdown  .mkd  .mkdn\n"
    "    Data:       .yaml  .yml  .json  .jsonl  .toml  .csv  .tsv\n"
    "    Config:     .cfg  .ini  .env  .txt\n"
    "    Template:   .xml  .html  .jinja  .jinja2  .j2\n"
    "    Prompt:     .prompt"
)


# ── Header & Sections ─────────────────────────────────────────────────────────

def print_header(subtitle: str = "") -> None:
    """Print the branded header panel with shield icon and optional subtitle."""
    title_text = Text()
    title_text.append(f"{SHIELD_ICON}  ", style="bold")
    title_text.append(APP_NAME, style="bold dark_green")
    title_text.append(f"  {APP_VERSION}", style="dark_orange")
    lines = [title_text, Text(APP_TAGLINE, style="dim")]
    if subtitle:
        lines.append(Text())
        lines.append(Text(subtitle, style="bold white"))
    content = Text("\n").join(lines)
    console.print()
    console.print(Panel(
        content, border_style="dark_green", box=box.DOUBLE_EDGE,
        padding=(1, 3), width=HEADER_WIDTH,
    ))
    console.print()


def print_section(title: str) -> None:
    """Print a section divider with the title embedded in a dashed line."""
    console.print()
    pad = HEADER_WIDTH - len(title) - 7
    console.print(f"  {SECTION_CHAR * 3} {title} {SECTION_CHAR * max(pad, 3)}", style="dim")
    console.print()


# ── Status Messages ───────────────────────────────────────────────────────────

def print_success(msg: str) -> None:
    """Print a success message with a green checkmark."""
    console.print(f"  ✓ {msg}", style="success")


def print_error(msg: str) -> None:
    """Print an error message with a red cross."""
    console.print(f"  ✗ {msg}", style="error")


def print_warning(msg: str) -> None:
    """Print a warning message with an orange triangle."""
    console.print(f"  ⚠ {msg}", style="warning")


def print_info(msg: str) -> None:
    """Print an informational message in green."""
    console.print(f"  ℹ {msg}", style="info")


def print_muted(msg: str) -> None:
    """Print a dim/muted message for secondary info."""
    console.print(f"    {msg}", style="muted")


def print_detail(label: str, value: str) -> None:
    """Print a key: value detail line with dim label and white value."""
    console.print(f"    {label}: ", style="dim", end="")
    console.print(value, style="accent")


def print_next_steps(steps: list[tuple[str, str]]) -> None:
    """Print a 'What to do next' section with green commands and dim descriptions.

    Commands are rendered in dark_green. Angle-bracket placeholders like
    <file> are rendered in dark_orange to stay within the green/orange palette.
    """
    console.print()
    pad = HEADER_WIDTH - 22
    console.print(f"  {SECTION_CHAR * 3} What to do next {SECTION_CHAR * max(pad, 3)}", style="dim")
    console.print()
    for cmd, desc in steps:
        console.print("    $ ", style="dim", end="")
        # Render angle-bracket placeholders in dark_orange, rest in dark_green
        _print_command_styled(cmd)
        console.print(f"  {desc}", style="dim")
    console.print()


def print_usage_hint(syntax: str, description: str = "") -> None:
    """Print a usage syntax hint with styled command and metavar coloring."""
    console.print("    Syntax: ", style="dim", end="")
    _print_command_styled(syntax)
    console.print()
    if description:
        console.print(f"            {description}", style="dim")


def _print_command_styled(cmd: str) -> None:
    """Render a command string with green text and orange angle-bracket placeholders.

    Parses tokens like <file>, <path>, <command> and renders them in dark_orange
    while the rest of the command text is rendered in dark_green. This prevents
    any blue/purple/magenta default Rich markup from leaking into the UI.
    """
    import re
    parts = re.split(r'(<[^>]+>)', cmd)
    for part in parts:
        if part.startswith('<') and part.endswith('>'):
            console.print(part, style="dark_orange", end="")
        else:
            console.print(part, style="dark_green", end="")


# ── Formatting ────────────────────────────────────────────────────────────────

def format_timestamp(ts: float) -> str:
    """Convert a Unix timestamp to a human-readable UTC string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def rel_path(absolute_path: str) -> str:
    """Convert an absolute file path to a relative path for display.

    Tries to make the path relative to the current working directory first.
    If the file is not under cwd, tries relative to the guard root. Falls
    back to just the filename if neither works.

    Args:
        absolute_path: The absolute file path string.

    Returns:
        A shorter relative path string suitable for table display.
    """
    from pathlib import Path
    p = Path(absolute_path)
    try:
        return str(p.relative_to(Path.cwd()))
    except ValueError:
        pass
    # If not under cwd, just use the filename
    return p.name


def format_state(state: str) -> Text:
    """Return a Rich Text object styled according to file state."""
    style = f"state.{state}" if f"state.{state}" in ACG_THEME.styles else "dim"
    return Text(state, style=style)


# ── Diff Rendering ───────────────────────────────────────────────────────────
# Custom diff renderer that uses green/red/orange coloring and Rich panels
# instead of the default Syntax "monokai" grey box. This provides a more
# readable, visually appealing diff output across all CLI commands.

def render_diff(diff_text: str) -> None:
    """Render a unified diff with custom green/orange/red coloring.

    Lines are colored by type:
        - '+++' / '---' headers: dim (meta info)
        - '@@' hunk markers: dark_orange
        - '+' additions: bold green
        - '-' removals: bold red
        - context lines: default (white/grey)

    The diff is wrapped in a rounded-border panel for visual consistency
    with the rest of the CLI.

    Args:
        diff_text: A unified diff string (e.g. from difflib.unified_diff).
    """
    if not diff_text or not diff_text.strip():
        console.print("    (no differences)", style="dim")
        return

    styled = Text()
    for line in diff_text.splitlines():
        if line.startswith('+++') or line.startswith('---'):
            # File header lines (meta)
            styled.append(line + "\n", style="dim")
        elif line.startswith('@@'):
            # Hunk markers (location in file)
            styled.append(line + "\n", style="dark_orange")
        elif line.startswith('+'):
            # Additions
            styled.append(line + "\n", style="bold green")
        elif line.startswith('-'):
            # Removals
            styled.append(line + "\n", style="bold red")
        else:
            # Context lines
            styled.append(line + "\n", style="dim")

    out_console.print(Panel(
        styled,
        title="[dark_orange]Changes[/dark_orange]",
        border_style="dim",
        box=box.ROUNDED,
        padding=(0, 1),
    ))


def render_file_contents(content: str, filename: str) -> None:
    """Render file contents in a styled panel for review.

    Used by the recover command when no backup is available to show
    the current file contents so the user can decide to accept or cancel.

    Args:
        content:  The file content to display.
        filename: The filename shown in the panel title.
    """
    styled = Text()
    for i, line in enumerate(content.splitlines(), 1):
        styled.append(f"  {i:>4}  ", style="dim")
        styled.append(line + "\n", style="")
    out_console.print(Panel(
        styled,
        title=f"[dark_orange]{filename}[/dark_orange]",
        subtitle="[dim]current contents[/dim]",
        border_style="dim",
        box=box.ROUNDED,
        padding=(0, 1),
    ))


# ── Interactive Selector ─────────────────────────────────────────────────────
# Provides a numbered-list selection interface for approve, reject, and recover
# commands. Users see a numbered list and type the number to select, rather
# than needing to type file paths or proposal IDs from memory.

def interactive_select(
    items: list[dict[str, str]],
    label_key: str = "label",
    detail_key: str | None = "detail",
    prompt: str = "Select",
    allow_empty: bool = True,
) -> dict[str, str] | None:
    """Present a numbered list of items and let the user pick one.

    Args:
        items:      List of dicts, each representing a selectable item.
        label_key:  Dict key whose value is the main display label.
        detail_key: Optional dict key for secondary detail text. None to skip.
        prompt:     Text shown before the number input.
        allow_empty: If True, user can press Enter to cancel.

    Returns:
        The selected item dict, or None if the user cancels.
    """
    if not items:
        print_info("Nothing to select.")
        return None

    for i, item in enumerate(items, 1):
        # Number in dark_orange, label in dark_green
        console.print(f"    [{i}] ", style="dark_orange", end="")
        console.print(item.get(label_key, "?"), style="dark_green", end="")
        if detail_key and item.get(detail_key):
            console.print(f"  {item[detail_key]}", style="dim", end="")
        console.print()

    console.print()
    hint = " (Enter to cancel)" if allow_empty else ""
    try:
        raw = input(f"  {prompt} [1-{len(items)}]{hint}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None

    if not raw and allow_empty:
        return None

    try:
        idx = int(raw)
        if 1 <= idx <= len(items):
            return items[idx - 1]
    except ValueError:
        pass

    print_warning(f"Invalid selection: {raw}")
    return None


# ── Tables ────────────────────────────────────────────────────────────────────
# All tables use the green/orange theme. File columns use "file" style
# (dark_green underline) and highlight columns use "highlight" (dark_orange).

def make_status_table(files: list[dict[str, Any]]) -> Table:
    """Build the Protected Files status table."""
    table = Table(
        title="Protected Files", show_header=True, header_style="bold dark_green",
        border_style="dim", pad_edge=True, box=box.ROUNDED,
    )
    table.add_column("File", style="file", no_wrap=True, max_width=60)
    table.add_column("State", justify="center")
    table.add_column("Version", justify="center")
    table.add_column("Author", justify="center")
    table.add_column("Sealed At", justify="right", style="muted")
    table.add_column("Proposals", justify="center")
    for f in files:
        table.add_row(
            rel_path(f.get("file", "")), format_state(f.get("state", "?")),
            str(f.get("version", "?")), f.get("author", "?"),
            format_timestamp(f["timestamp"]) if f.get("timestamp") else "—",
            str(f.get("pending_proposals", 0)),
        )
    return table


def make_verify_table(results: list[dict[str, Any]]) -> Table:
    """Build the Integrity Verification results table.

    Visually similar to the status table but focused on verification
    outcome: file path, pass/fail result, expected hash, and actual hash.

    Args:
        results: List of dicts with keys: file, result ("PASS" or "FAIL"),
                 expected_hash, actual_hash.

    Returns:
        A Rich Table ready for printing.
    """
    table = Table(
        title="Integrity Verification", show_header=True,
        header_style="bold dark_green",
        border_style="dim", pad_edge=True, box=box.ROUNDED,
    )
    table.add_column("File", style="file", no_wrap=True, max_width=60)
    table.add_column("Result", justify="center")
    table.add_column("Expected Hash", style="muted", max_width=18)
    table.add_column("Actual Hash", style="muted", max_width=18)
    for r in results:
        result_str = r.get("result", "?")
        if result_str == "PASS":
            result_text = Text("✓ PASS", style="bold dark_green")
        else:
            result_text = Text("✗ FAIL", style="bold red")
        expected = r.get("expected_hash", "—")
        actual = r.get("actual_hash", "—")
        # Truncate hashes for display
        exp_display = (expected[:14] + "…") if len(expected) > 14 else expected
        act_display = (actual[:14] + "…") if len(actual) > 14 else actual
        table.add_row(rel_path(r.get("file", "")), result_text, exp_display, act_display)
    return table


def make_audit_table(entries: list[dict[str, Any]]) -> Table:
    """Build the Audit Log table."""
    table = Table(
        title="Audit Log", show_header=True, header_style="bold dark_green",
        border_style="dim", box=box.ROUNDED,
    )
    table.add_column("Time", style="muted", no_wrap=True)
    table.add_column("Event", style="highlight")
    table.add_column("Actor")
    table.add_column("File", style="file", max_width=40)
    table.add_column("Result", justify="center")
    table.add_column("Detail", max_width=40)
    for e in entries:
        result = e.get("result", "")
        style = "dark_green" if result == "allowed" else "red" if result == "denied" else "dim"
        table.add_row(
            format_timestamp(e["timestamp"]) if e.get("timestamp") else "—",
            e.get("event", ""), e.get("actor", ""), rel_path(e.get("file_path", "")),
            Text(result, style=style), e.get("detail", "")[:80],
        )
    return table


def make_proposals_table(proposals: list[dict[str, Any]]) -> Table:
    """Build a proposals summary table."""
    table = Table(
        title="Pending Proposals", show_header=True, header_style="bold dark_green",
        border_style="dim", box=box.ROUNDED,
    )
    table.add_column("Proposal ID", style="highlight", no_wrap=True)
    table.add_column("File", style="file", max_width=40)
    table.add_column("Agent", style="dark_green")
    table.add_column("Submitted", style="muted")
    table.add_column("Justification", max_width=40)
    for p in proposals:
        table.add_row(
            p.get("proposal_id", ""),
            rel_path(p.get("file_path", "")),
            p.get("agent_id", ""),
            format_timestamp(p["timestamp"]) if p.get("timestamp") else "—",
            (p.get("justification", "") or "—")[:40],
        )
    return table


def make_diff_table(diffs: list[dict[str, Any]]) -> Table:
    """Build a file diff summary table for the recover command."""
    table = Table(
        title="File Changes", show_header=True, header_style="bold dark_green",
        border_style="dim", box=box.ROUNDED,
    )
    table.add_column("File", style="file", max_width=50)
    table.add_column("Status", justify="center")
    table.add_column("Expected Hash", style="muted", max_width=16)
    table.add_column("Current Hash", style="muted", max_width=16)
    for d in diffs:
        status_style = "bold red" if d.get("changed") else "bold dark_green"
        status_text = "CHANGED" if d.get("changed") else "OK"
        table.add_row(
            rel_path(d.get("file", "")),
            Text(status_text, style=status_style),
            d.get("expected_hash", "")[:14] + "…",
            d.get("current_hash", "")[:14] + "…",
        )
    return table


# ── Styled Help Output ───────────────────────────────────────────────────────
# Two help modes:
#   print_short_help()  — shown when user types bare `acg` (concise overview)
#   print_man_page()    — shown when user types `acg --help` (full man page)

def print_short_help() -> None:
    """Print a concise branded help screen for bare `acg` invocation.

    Shows: How It Works, Commands, Quick Start, Environment, Supported Files.
    Omits the full description and core principle (those live in --help).
    """
    print_header()

    # ── HOW IT WORKS ──
    print_section("How It Works")
    for step, desc in [
        ("1. Initialize", "Run 'acg init' to create guard metadata in your project."),
        ("2. Protect",    "Run 'acg protect <files>' to seal context files with cryptographic signatures."),
        ("3. Guard",      "Run 'acg run -- <cmd>' for pre-flight verification before agents execute."),
        ("4. Propose",    "Agents call guard.propose() to suggest changes with justifications."),
        ("5. Review",     "Humans run 'acg diff', 'acg approve', or 'acg reject' to manage proposals."),
        ("6. Recover",    "If tampering is detected, 'acg recover' shows diffs and offers rollback."),
        ("7. Audit",      "Every operation is logged to an append-only audit trail."),
    ]:
        console.print(f"    {step:<18}", style="dark_green", end="")
        console.print(desc, style="dim")

    # ── COMMANDS ──
    print_section("Commands")
    for cmd, desc in _COMMAND_LIST:
        console.print(f"    {cmd:<16}", style="dark_green", end="")
        console.print(desc, style="dim")
    console.print()
    console.print("    Run ", style="dim", end="")
    _print_command_styled("acg <command> --help")
    console.print(" for detailed options on any command.", style="dim")

    # ── QUICK START ──
    print_section("Quick Start")
    for cmd, comment in [
        ("acg init",                   "Initialize in your project directory"),
        ("acg protect prompts/*.md",   "Protect your agent context files"),
        ("acg run -- python agent.py", "Run your agent under the guard"),
        ("acg verify",                 "Verify integrity (CI/CD)"),
    ]:
        console.print("    $ ", style="dim", end="")
        console.print(f"{cmd:<36}", style="dark_green", end="")
        console.print(f"# {comment}", style="dim")

    # ── ENVIRONMENT VARIABLES ──
    print_section("Environment")
    for var, desc in [
        ("ACG_GUARD_ROOT",        "Override automatic guard root detection"),
        ("EDITOR",                "Default editor for 'acg edit' sessions"),
        ("ACG_AUDIT_MAX_ENTRIES", "Audit log auto-archive threshold (default: 10000)"),
    ]:
        console.print(f"    {var:<26}", style="dark_orange", end="")
        console.print(desc, style="dim")

    # ── SUPPORTED FILE TYPES ──
    print_section("Supported Files")
    console.print(f"    {SUPPORTED_FILES_DISPLAY}", style="dim")

    console.print()


def print_man_page() -> None:
    """Print a full man-page-style help screen for `acg --help`.

    Includes: Name, Synopsis, Description, Core Principle, How It Works,
    Commands, Quick Start, Options, Environment, Supported Files, Documentation.
    """
    print_header()

    # ── NAME ──
    print_section("Name")
    console.print("    acg — Agent Context Guard command-line interface", style="accent")

    # ── SYNOPSIS ──
    print_section("Synopsis")
    console.print("    acg ", style="dark_green", end="")
    console.print("<command>", style="dark_orange", end="")
    console.print(" [options]", style="dim")
    console.print("    acg ", style="dark_green", end="")
    console.print("--help", style="dark_orange", end="")
    console.print("       Show this help page", style="dim")
    console.print("    acg ", style="dark_green", end="")
    console.print("--version", style="dark_orange", end="")
    console.print("    Show version number", style="dim")

    # ── DESCRIPTION ──
    print_section("Description")
    console.print(
        "    Agent Context Guard is a runtime protection layer for AI agent\n"
        "    context files. Modern AI agents encode critical behavioral controls\n"
        "    in plaintext files — persona definitions, tool instructions, rules,\n"
        "    and skills. These files are implicitly trusted, mutable at runtime,\n"
        "    and typically unprotected.\n"
        "\n"
        "    Agent Context Guard seals these files with cryptographic signatures,\n"
        "    detects tampering at runtime, and ensures that only humans can\n"
        "    approve changes. Agents can propose changes but never apply them\n"
        "    without explicit human approval.",
        style="dim",
    )

    # ── CORE PRINCIPLE ──
    print_section("Core Principle")
    console.print(Panel(
        Text(
            "The agent never gains authority.\n"
            "The human never loses ownership.\n"
            "The guard never acts implicitly.",
            style="bold dark_orange",
            justify="center",
        ),
        border_style="dark_green",
        box=box.ROUNDED,
        padding=(1, 3),
        width=HEADER_WIDTH,
    ))

    # ── HOW IT WORKS ──
    print_section("How It Works")
    for step, desc in [
        ("1. Initialize", "Run 'acg init' to create guard metadata in your project."),
        ("2. Protect",    "Run 'acg protect <files>' to seal files with SHA-256 + HMAC-SHA256."),
        ("3. Guard",      "Run 'acg run -- <cmd>' for pre-flight verification before agents execute."),
        ("4. Propose",    "Agents call guard.propose() to suggest changes with justifications."),
        ("5. Review",     "Humans run 'acg diff', 'acg approve', or 'acg reject' to manage proposals."),
        ("6. Recover",    "If tampering is detected, 'acg recover' shows diffs and offers rollback."),
        ("7. Audit",      "Every operation is logged to an append-only audit trail."),
    ]:
        console.print(f"    {step:<18}", style="dark_green", end="")
        console.print(desc, style="dim")

    # ── COMMANDS ──
    print_section("Commands")
    for cmd, desc in _COMMAND_LIST:
        console.print(f"    {cmd:<16}", style="dark_green", end="")
        console.print(desc, style="dim")
    console.print()
    console.print("    Run ", style="dim", end="")
    _print_command_styled("acg <command> --help")
    console.print(" for detailed options on any command.", style="dim")

    # ── QUICK START ──
    print_section("Quick Start")
    for cmd, comment in [
        ("acg init",                   "Initialize in your project directory"),
        ("acg protect prompts/*.md",   "Protect your agent context files"),
        ("acg run -- python agent.py", "Run your agent under the guard"),
        ("acg verify",                 "Verify integrity (CI/CD)"),
    ]:
        console.print("    $ ", style="dim", end="")
        console.print(f"{cmd:<36}", style="dark_green", end="")
        console.print(f"# {comment}", style="dim")

    # ── GLOBAL OPTIONS ──
    print_section("Global Options")
    for flag, desc in [
        ("--version",        "Show version number and exit"),
        ("-v, --verbose",    "Enable debug logging"),
        ("-h, --help",       "Show this help page and exit"),
    ]:
        console.print(f"    {flag:<26}", style="dark_orange", end="")
        console.print(desc, style="dim")

    # ── ENVIRONMENT VARIABLES ──
    print_section("Environment")
    for var, desc in [
        ("ACG_GUARD_ROOT",        "Override automatic guard root detection"),
        ("EDITOR",                "Default editor for 'acg edit' sessions"),
        ("ACG_AUDIT_MAX_ENTRIES", "Audit log auto-archive threshold (default: 10000)"),
    ]:
        console.print(f"    {var:<26}", style="dark_orange", end="")
        console.print(desc, style="dim")

    # ── SUPPORTED FILE TYPES ──
    print_section("Supported Files")
    console.print(f"    {SUPPORTED_FILES_DISPLAY}", style="dim")

    console.print()


def print_command_help(
    command_name: str,
    description: str,
    usage: str,
    options: list[tuple[str, str]],
    examples: list[tuple[str, str]] | None = None,
    notes: str | None = None,
) -> None:
    """Print a styled help screen for an individual subcommand.

    Args:
        command_name: The subcommand name (e.g. "init", "protect").
        description:  A paragraph describing what the command does.
        usage:        Usage syntax string (e.g. "acg init [--path <dir>]").
        options:      List of (flag_string, description) tuples.
        examples:     Optional list of (command_string, comment) tuples.
        notes:        Optional extra notes paragraph.
    """
    print_header(command_name)

    print_section("Description")
    for line in description.strip().splitlines():
        console.print(f"    {line.strip()}", style="dim")

    print_section("Usage")
    console.print("    ", style="dim", end="")
    _print_command_styled(usage)
    console.print()

    if options:
        print_section("Options")
        for flag, desc in options:
            console.print(f"    {flag:<30}", style="dark_orange", end="")
            console.print(desc, style="dim")

    if examples:
        print_section("Examples")
        for cmd, comment in examples:
            console.print("    $ ", style="dim", end="")
            _print_command_styled(cmd)
            if comment:
                console.print(f"  # {comment}", style="dim", end="")
            console.print()

    if notes:
        print_section("Notes")
        for line in notes.strip().splitlines():
            console.print(f"    {line.strip()}", style="dim")

    console.print()


# ── Shared command list (used by both short help and man page) ────────────────

_COMMAND_LIST = [
    ("init",        "Initialize guard in a directory"),
    ("protect",     "Register context files for protection"),
    ("run",         "Run a command with pre-flight seal verification"),
    ("edit",        "Open a human edit session for a protected file"),
    ("status",      "Show protection status of files (with integrity check)"),
    ("diff",        "Show pending proposal diffs"),
    ("approve",     "Approve a pending proposal and apply changes"),
    ("reject",      "Reject a pending proposal"),
    ("recover",     "Recover from file tampering (rollback or accept)"),
    ("audit",       "Display the audit log"),
    ("verify",      "CI/CD verification of sealed files and metadata"),
    ("rotate-keys", "Rotate the signing key and re-sign all files"),
]


# ── Editor Detection Helpers ─────────────────────────────────────────────────
# Provides OS-aware editor guidance so users can get 'acg edit' working
# on the first try regardless of platform.

def get_editor_guidance() -> str:
    """Return platform-specific editor guidance text.

    Detects the current OS and returns a string describing which editors
    are commonly available and how to configure the EDITOR environment
    variable or use the --editor flag.

    Returns:
        A multi-line string with editor guidance.
    """
    system = platform.system().lower()

    if system == "windows":
        return (
            "On Windows, the default editor ('vi') is typically not available.\n"
            "    Use the --editor flag or set the EDITOR environment variable:\n"
            "\n"
            "    Common Windows editors:\n"
            "      notepad        Built-in, always available\n"
            "      notepad++      If installed and on PATH\n"
            "      code --wait    VS Code (--wait is required so acg waits for close)\n"
            "\n"
            "    Examples:\n"
            "      acg edit myfile.md --editor notepad\n"
            "      acg edit myfile.md --editor \"code --wait\"\n"
            "      set EDITOR=notepad          (cmd.exe, persistent for session)\n"
            "      $env:EDITOR = 'notepad'     (PowerShell, persistent for session)"
        )
    elif system == "darwin":
        return (
            "On macOS, the default editor is determined by $EDITOR (often 'vi').\n"
            "    Use the --editor flag or set the EDITOR environment variable:\n"
            "\n"
            "    Common macOS editors:\n"
            "      nano           Built-in, beginner-friendly\n"
            "      vim / vi       Built-in, modal editor\n"
            "      code --wait    VS Code (--wait is required so acg waits for close)\n"
            "      open -t -W    Opens in default text editor (TextEdit)\n"
            "\n"
            "    Examples:\n"
            "      acg edit myfile.md --editor nano\n"
            "      acg edit myfile.md --editor \"code --wait\"\n"
            "      export EDITOR=nano           (add to ~/.zshrc for persistence)"
        )
    else:
        return (
            "The default editor is determined by $EDITOR (falls back to 'vi').\n"
            "    Use the --editor flag or set the EDITOR environment variable:\n"
            "\n"
            "    Common Linux editors:\n"
            "      nano           Beginner-friendly, widely available\n"
            "      vim / vi       Modal editor, pre-installed on most systems\n"
            "      code --wait    VS Code (--wait is required so acg waits for close)\n"
            "      emacs          GNU Emacs\n"
            "\n"
            "    Examples:\n"
            "      acg edit myfile.md --editor nano\n"
            "      acg edit myfile.md --editor \"code --wait\"\n"
            "      export EDITOR=nano           (add to ~/.bashrc for persistence)"
        )


def confirm(prompt: str, default: bool = False) -> bool:
    """Prompt for yes/no confirmation.

    Args:
        prompt:  The prompt text (displayed before [y/N] or [Y/n]).
        default: The default answer when the user presses Enter.

    Returns:
        True if the user confirms, False otherwise.
    """
    suffix = " [Y/n]: " if default else " [y/N]: "
    try:
        resp = input(prompt + suffix).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return resp in ("y", "yes") if resp else default
