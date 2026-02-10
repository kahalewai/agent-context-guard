"""CLI output helpers using Rich for polished terminal output."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.columns import Columns
from rich.rule import Rule
from rich import box

# ── Theme ─────────────────────────────────────────────────────────────────────
ACG_THEME = Theme({
    "info": "cyan",
    "success": "green bold",
    "warning": "yellow",
    "error": "red bold",
    "muted": "dim",
    "highlight": "magenta bold",
    "file": "blue underline",
    "header": "bold cyan",
    "accent": "bold white",
    "brand": "cyan",
    "state.SEALED": "cyan",
    "state.ACTIVE": "green",
    "state.DEPRECATED": "yellow",
    "state.REVOKED": "red",
    "state.UNSEALED": "dim",
})

console = Console(theme=ACG_THEME, stderr=True)
out_console = Console(theme=ACG_THEME)

# ── Brand Constants ───────────────────────────────────────────────────────────
APP_NAME = "agent-context-guard"
APP_TAGLINE = "Runtime protection for AI agent context files"
HEADER_WIDTH = 60
SECTION_CHAR = "─"


def _header_box(subtitle: str = "") -> Panel:
    """Create a consistent branded header panel."""
    title_text = Text()
    title_text.append("agent-context-guard", style="bold cyan")
    lines = [title_text, Text(APP_TAGLINE, style="dim")]
    if subtitle:
        lines.append(Text())
        lines.append(Text(subtitle, style="bold white"))
    content = Text("\n").join(lines)
    return Panel(
        content,
        border_style="cyan",
        box=box.DOUBLE_EDGE,
        padding=(1, 3),
        width=HEADER_WIDTH,
    )


def print_header(subtitle: str = "") -> None:
    """Print the standard branded header with optional subtitle."""
    console.print()
    console.print(_header_box(subtitle))
    console.print()


def print_banner() -> None:
    """Print the application banner (alias for header)."""
    print_header()


def print_section(title: str) -> None:
    """Print a section divider."""
    console.print()
    console.print(f"  {SECTION_CHAR * 3} {title} {SECTION_CHAR * (HEADER_WIDTH - len(title) - 7)}", style="dim")
    console.print()


def print_success(msg: str) -> None:
    console.print(f"  ✓ {msg}", style="success")


def print_error(msg: str) -> None:
    console.print(f"  ✗ {msg}", style="error")


def print_warning(msg: str) -> None:
    console.print(f"  ⚠ {msg}", style="warning")


def print_info(msg: str) -> None:
    console.print(f"  ℹ {msg}", style="info")


def print_muted(msg: str) -> None:
    console.print(f"    {msg}", style="muted")


def print_detail(label: str, value: str) -> None:
    """Print a key: value detail line."""
    console.print(f"    {label}: ", style="dim", end="")
    console.print(value, style="accent")


def print_next_steps(steps: list[tuple[str, str]]) -> None:
    """Print a 'What to do next' section with command + description pairs."""
    console.print()
    console.print(f"  {SECTION_CHAR * 3} What to do next {SECTION_CHAR * (HEADER_WIDTH - 22)}", style="dim")
    console.print()
    for cmd, desc in steps:
        console.print(f"    $ ", style="dim", end="")
        console.print(cmd, style="cyan", end="")
        console.print(f"  {desc}", style="dim")
    console.print()


def print_usage_hint(syntax: str, description: str = "") -> None:
    """Print a usage/syntax hint."""
    console.print(f"    Syntax: ", style="dim", end="")
    console.print(syntax, style="cyan")
    if description:
        console.print(f"            {description}", style="dim")


def format_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def format_state(state: str) -> Text:
    style = f"state.{state}" if f"state.{state}" in ACG_THEME.styles else "dim"
    return Text(state, style=style)


def make_status_table(files: list[dict[str, Any]]) -> Table:
    table = Table(
        title="Protected Files",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        pad_edge=True,
        box=box.ROUNDED,
    )
    table.add_column("File", style="file", no_wrap=True, max_width=60)
    table.add_column("State", justify="center")
    table.add_column("Version", justify="center")
    table.add_column("Author", justify="center")
    table.add_column("Sealed At", justify="right", style="muted")
    table.add_column("Proposals", justify="center")

    for f in files:
        table.add_row(
            f.get("file", ""),
            format_state(f.get("state", "?")),
            str(f.get("version", "?")),
            f.get("author", "?"),
            format_timestamp(f["timestamp"]) if f.get("timestamp") else "—",
            str(f.get("pending_proposals", 0)),
        )
    return table


def make_audit_table(entries: list[dict[str, Any]]) -> Table:
    table = Table(
        title="Audit Log",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        box=box.ROUNDED,
    )
    table.add_column("Time", style="muted", no_wrap=True)
    table.add_column("Event", style="highlight")
    table.add_column("Actor")
    table.add_column("File", style="file", max_width=40)
    table.add_column("Result", justify="center")
    table.add_column("Detail", max_width=40)

    for e in entries:
        result = e.get("result", "")
        result_style = "green" if result == "allowed" else "red" if result == "denied" else "dim"
        table.add_row(
            format_timestamp(e["timestamp"]) if e.get("timestamp") else "—",
            e.get("event", ""),
            e.get("actor", ""),
            e.get("file_path", ""),
            Text(result, style=result_style),
            e.get("detail", "")[:60],
        )
    return table


def confirm(prompt: str, default: bool = False) -> bool:
    """Prompt for yes/no confirmation."""
    suffix = " [Y/n]: " if default else " [y/N]: "
    try:
        resp = input(prompt + suffix).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if not resp:
        return default
    return resp in ("y", "yes")
