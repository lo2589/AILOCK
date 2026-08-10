"""
Custom command name installation.

Generates a platform-specific launcher script so users can
invoke ailatch with a custom name (e.g. 'aa').
"""

import os
import re
import stat
import sys
from pathlib import Path

RESERVED_NAMES = frozenset({
    "sudo", "su", "rm", "del", "cat", "type", "python", "python3",
    "pip", "pip3", "git", "cmd", "powershell", "pwsh", "bash", "sh",
    "zsh", "fish", "node", "npm", "curl", "wget", "chmod", "chown",
    "mv", "cp", "ls", "dir", "echo", "exit", "kill", "taskkill",
})


def validate_command_name(name: str) -> None:
    """Validate that the command name is safe."""
    if not re.match(r"^[a-zA-Z0-9_-]{1,32}$", name):
        raise ValueError(
            f"invalid command name: '{name}' "
            "(only a-z A-Z 0-9 _ - allowed, 1-32 chars)"
        )
    if name.lower() in RESERVED_NAMES:
        raise ValueError(f"reserved command name: '{name}'")


def _install_dir() -> Path:
    """Get the user-local bin directory."""
    if sys.platform == "win32":
        base = Path.home() / ".local" / "bin"
    else:
        base = Path.home() / ".local" / "bin"
    base.mkdir(parents=True, exist_ok=True)
    return base


def write_launcher(target: Path) -> None:
    """Write platform-specific launcher scripts."""
    if sys.platform == "win32":
        # CMD wrapper (for cmd.exe)
        cmd_content = '@echo off\r\npython -m ailatch %*\r\n'
        cmd_target = target.with_suffix(".cmd")
        cmd_target.write_text(cmd_content, encoding="utf-8")

        # PowerShell wrapper (for pwsh / Windows PowerShell)
        ps1_content = (
            '#!/usr/bin/env pwsh\n'
            '# AILatch PowerShell launcher\n'
            'python -m ailatch @args\n'
            'exit $LASTEXITCODE\n'
        )
        ps1_target = target.with_suffix(".ps1")
        ps1_target.write_text(ps1_content, encoding="utf-8")
    else:
        # Unix bash wrapper
        content = '#!/usr/bin/env bash\nexec python3 -m ailatch "$@"\n'
        target.write_text(content, encoding="utf-8")
        os.chmod(target, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)


def install_as(name: str) -> str:
    """Install ailatch as a custom command name. Returns the installed path."""
    validate_command_name(name)

    install_dir = _install_dir()
    target = install_dir / name

    write_launcher(target)

    # Resolve actual path (may have .cmd suffix on Windows)
    if sys.platform == "win32":
        actual = target.with_suffix(".cmd")
        ps1 = target.with_suffix(".ps1")
        return f"{actual} + {ps1}"
    else:
        actual = target

    return str(actual)
