"""
sudo-style file-based key cache.

Caches derived project keys in temp files with TTL expiry.
No background agent required.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


def _find_git_root() -> Path | None:
    """Walk up to find .git directory."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def project_id() -> str:
    """Generate a project ID based on git root or cwd."""
    root = _find_git_root() or Path.cwd()
    return hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()


def _cache_dir() -> Path:
    """Get a writable cache directory path."""
    candidates = []

    for var in ("TMPDIR", "TEMP", "TMP"):
        value = os.environ.get(var)
        if value:
            candidates.append(Path(value) / "aloc-cache")

    candidates.append(Path(tempfile.gettempdir()) / "aloc-cache")

    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            candidates.append(Path(local_app_data) / "AiLock" / "cache")

    candidates.append(Path.home() / ".ailock" / "cache")

    last_error = None
    for base in candidates:
        try:
            base.mkdir(parents=True, exist_ok=True)
            probe = base / f".write-test-{os.getpid()}-{uuid.uuid4().hex}"
            probe.write_text("", encoding="utf-8")
            try:
                probe.unlink()
            except OSError:
                pass
            return base
        except OSError as e:
            last_error = e

    raise OSError(f"no writable AiLock cache directory found: {last_error}")


def _cache_file(pid: str) -> Path:
    """Get the cache file path for a given project ID."""
    short = hashlib.sha256(pid.encode()).hexdigest()[:16]
    return _cache_dir() / short


def cache_get_project_key(pid: str) -> bytes | None:
    """Read cached key if it exists and hasn't expired."""
    path = _cache_file(pid)

    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    if time.time() > data.get("expires_at", 0):
        # Expired, clean up
        try:
            path.unlink()
        except OSError:
            pass
        return None

    try:
        return base64.b64decode(data["key"])
    except (KeyError, ValueError):
        return None


def cache_get_password(pid: str) -> str | None:
    """Read cached password if it exists and hasn't expired."""
    path = _cache_file(pid + "-pw")

    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    if time.time() > data.get("expires_at", 0):
        try:
            path.unlink()
        except OSError:
            pass
        return None

    return data.get("password")


def cache_store_password(pid: str, password: str, ttl: int = 300) -> None:
    """Store password in cache with TTL."""
    path = _cache_file(pid + "-pw")

    data = {
        "password": password,
        "expires_at": time.time() + ttl,
    }

    path.write_text(json.dumps(data), encoding="utf-8")

    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def cache_store_project_key(pid: str, key: bytes, ttl: int = 300) -> None:
    """Store a key in cache with TTL."""
    path = _cache_file(pid)

    data = {
        "key": base64.b64encode(key).decode("ascii"),
        "expires_at": time.time() + ttl,
    }

    path.write_text(json.dumps(data), encoding="utf-8")

    # Restrict file permissions (best-effort on Windows)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def cache_forget(pid: str | None = None) -> None:
    """Clear cached keys and passwords. If pid is None, clear all."""
    if pid is not None:
        for path in (_cache_file(pid), _cache_file(pid + "-pw")):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    else:
        cache_dir = _cache_dir()
        if cache_dir.exists():
            for f in cache_dir.iterdir():
                if f.is_file():
                    try:
                        f.unlink()
                    except OSError:
                        pass
