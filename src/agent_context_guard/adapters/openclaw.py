"""
agent_context_guard/adapters/openclaw.py — OpenClaw skill integration.

Provides a factory function that generates a complete OpenClaw-compatible
skill folder, including SKILL.md and a Python helper script. The skill
teaches the OpenClaw agent to read protected markdown files through
agent-context-guard's verification pipeline.

This is particularly relevant for OpenClaw because its configuration,
memory, and skills are all stored as markdown files — exactly the file
type ACG is designed to protect. OpenClaw's own AGENTS.md, SOUL.md, and
memory files are prime candidates for integrity verification.

Usage:
    from agent_context_guard import Guard
    from agent_context_guard.adapters.openclaw import (
        generate_openclaw_skill,
        create_openclaw_handlers,
    )

    # Option 1: Generate the skill folder for installation
    guard = Guard("/path/to/project")
    generate_openclaw_skill(
        output_dir="/path/to/openclaw/skills/context-guard",
        guard_root="/path/to/project",
    )

    # Option 2: Use handlers directly in a custom skill script
    guard = Guard("/path/to/project")
    handlers = create_openclaw_handlers(guard, agent_id="openclaw-agent")
    content = handlers["read"]("prompts/persona.md")

Requirements:
    No additional dependencies for skill generation.
    The generated skill requires agent-context-guard to be pip-installed
    in the OpenClaw environment.
"""

from __future__ import annotations

import json
import logging
import textwrap
from pathlib import Path
from typing import Any, Callable

from agent_context_guard.guard import Guard

logger = logging.getLogger(__name__)

# ── Skill File Content ────────────────────────────────────────────────────────
# The SKILL.md and helper script that get installed into the OpenClaw
# workspace. These are templates — the guard_root path is injected at
# generation time.

_SKILL_MD_TEMPLATE = textwrap.dedent("""\
    ---
    name: context-guard
    description: >
      Read and verify protected markdown files using agent-context-guard.
      Use this skill when you need to access files that are cryptographically
      sealed and integrity-verified. This ensures you are reading authentic,
      human-approved content that has not been tampered with.
    metadata:
      openclaw:
        emoji: "🛡️"
        requires:
          bins: ["python3"]
          env: ["ACG_GUARD_ROOT"]
    ---

    # Context Guard Skill

    This skill provides access to markdown files that are protected by
    agent-context-guard. Protected files are cryptographically sealed
    with SHA-256 hashes and HMAC signatures, ensuring their content
    has not been modified since a human last approved them.

    ## When to Use

    Use this skill whenever you need to read markdown files that control
    your behavior, configuration, or context — especially:

    - System prompts and persona definitions
    - Rules and policy documents
    - Configuration files that influence your actions
    - Any `.md` file in the protected inventory

    ## Tools

    Use the `Bash` tool to run the helper script:

    ### Read a protected file

    ```bash
    python3 {script_dir}/acg_helper.py read "path/to/file.md"
    ```

    ### Propose a change to a protected file

    ```bash
    python3 {script_dir}/acg_helper.py propose "path/to/file.md" "new content" "reason for change"
    ```

    ### Check file status

    ```bash
    python3 {script_dir}/acg_helper.py status "path/to/file.md"
    ```

    ### Verify all protected files

    ```bash
    python3 {script_dir}/acg_helper.py verify
    ```

    ## Important

    - You CANNOT directly modify protected files. Use `propose` to
      submit changes for human review.
    - If a read fails with a SealIntegrityError, the file may have been
      tampered with. Alert the user immediately.
    - All your reads and proposals are logged to a tamper-evident audit trail.
""")

_HELPER_SCRIPT_TEMPLATE = textwrap.dedent("""\
    #!/usr/bin/env python3
    \"\"\"
    acg_helper.py — OpenClaw helper script for agent-context-guard.

    This script is called by the OpenClaw agent via the Bash tool to
    interact with protected markdown files. It wraps the Guard API
    and outputs results as plain text (for reads) or JSON (for
    structured data).

    Usage:
        python3 acg_helper.py read <file_path>
        python3 acg_helper.py propose <file_path> <new_content> [justification]
        python3 acg_helper.py status <file_path>
        python3 acg_helper.py verify
    \"\"\"

    import json
    import os
    import sys

    def main():
        if len(sys.argv) < 2:
            print("Usage: acg_helper.py <command> [args...]", file=sys.stderr)
            sys.exit(1)

        # Resolve the guard root from environment or default
        guard_root = os.environ.get("ACG_GUARD_ROOT", "{guard_root}")

        try:
            from agent_context_guard import Guard
        except ImportError:
            print(
                "Error: agent-context-guard is not installed. "
                "Install with: pip install agent-context-guard",
                file=sys.stderr,
            )
            sys.exit(1)

        try:
            guard = Guard(guard_root)
        except Exception as exc:
            print(f"Error initializing guard: {{exc}}", file=sys.stderr)
            sys.exit(1)

        command = sys.argv[1]
        agent_id = "openclaw-agent"

        try:
            if command == "read":
                if len(sys.argv) < 3:
                    print("Usage: acg_helper.py read <file_path>", file=sys.stderr)
                    sys.exit(1)
                content = guard.read(sys.argv[2], agent_id=agent_id)
                print(content)

            elif command == "propose":
                if len(sys.argv) < 4:
                    print(
                        "Usage: acg_helper.py propose <file_path> <new_content> [justification]",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                justification = sys.argv[4] if len(sys.argv) > 4 else ""
                proposal_id = guard.propose(
                    sys.argv[2],
                    sys.argv[3],
                    agent_id=agent_id,
                    justification=justification,
                )
                print(json.dumps({{
                    "proposal_id": proposal_id,
                    "message": "Proposal submitted for human review.",
                }}))

            elif command == "status":
                if len(sys.argv) < 3:
                    print("Usage: acg_helper.py status <file_path>", file=sys.stderr)
                    sys.exit(1)
                status = guard.status(sys.argv[2])
                print(json.dumps(status, indent=2))

            elif command == "verify":
                failures = guard.verify_all()
                if failures:
                    print("Verification FAILED:")
                    for f in failures:
                        print(f"  - {{f}}")
                    sys.exit(1)
                else:
                    print("All protected files verified successfully.")

            else:
                print(f"Unknown command: {{command}}", file=sys.stderr)
                print("Commands: read, propose, status, verify", file=sys.stderr)
                sys.exit(1)

        except Exception as exc:
            print(f"Error: {{type(exc).__name__}}: {{exc}}", file=sys.stderr)
            sys.exit(1)

    if __name__ == "__main__":
        main()
""")


# ── Skill Generation ──────────────────────────────────────────────────────────

def generate_openclaw_skill(
    output_dir: str | Path,
    guard_root: str | Path,
) -> Path:
    """Generate a complete OpenClaw skill folder for agent-context-guard.

    Creates the following structure::

        output_dir/
        ├── SKILL.md          — Skill definition with instructions
        └── scripts/
            └── acg_helper.py — Python helper script

    The generated skill can be installed by copying it to the OpenClaw
    skills directory (typically ``~/.openclaw/skills/`` or
    ``<workspace>/skills/``).

    Args:
        output_dir: Directory to create the skill in.
        guard_root: Path to the project root with ``.agent-context-guard/``.

    Returns:
        The path to the created skill directory.
    """
    out = Path(output_dir)
    scripts_dir = out / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    resolved_root = str(Path(guard_root).resolve())
    resolved_scripts = str(scripts_dir.resolve())

    # Write SKILL.md with the script directory path injected
    skill_md = _SKILL_MD_TEMPLATE.format(script_dir=resolved_scripts)
    (out / "SKILL.md").write_text(skill_md, encoding="utf-8")

    # Write the helper script with the guard root injected
    helper = _HELPER_SCRIPT_TEMPLATE.format(guard_root=resolved_root)
    helper_path = scripts_dir / "acg_helper.py"
    helper_path.write_text(helper, encoding="utf-8")
    helper_path.chmod(0o755)

    logger.info("Generated OpenClaw skill at: %s", out)
    return out


# ── Direct Handlers ───────────────────────────────────────────────────────────

def create_openclaw_handlers(
    guard: Guard,
    agent_id: str = "openclaw-agent",
) -> dict[str, Callable[..., str]]:
    """Create handler functions for direct use in custom OpenClaw scripts.

    Returns a dict of named handler functions that can be called directly
    from Python code within an OpenClaw skill's scripts/ directory.

    Args:
        guard: An initialized Guard instance.
        agent_id: Identity for policy evaluation and audit logging.

    Returns:
        A dict with keys ``"read"``, ``"propose"``, ``"status"``, ``"verify"``.
    """

    def read(file_path: str) -> str:
        """Read a protected file with full verification."""
        return guard.read(file_path, agent_id=agent_id)

    def propose(file_path: str, new_content: str, justification: str = "") -> str:
        """Propose a change for human review."""
        proposal_id = guard.propose(
            file_path, new_content,
            agent_id=agent_id, justification=justification,
        )
        return json.dumps({
            "proposal_id": proposal_id,
            "message": "Proposal submitted for human review.",
        })

    def status(file_path: str) -> str:
        """Get file protection status as JSON."""
        return json.dumps(guard.status(file_path))

    def verify() -> str:
        """Verify all protected files."""
        failures = guard.verify_all()
        if failures:
            return json.dumps({"verified": False, "failures": failures})
        return json.dumps({"verified": True, "message": "All files verified."})

    return {
        "read": read,
        "propose": propose,
        "status": status,
        "verify": verify,
    }
