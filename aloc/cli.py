"""
CLI entry point for aloc.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import sys
import time
from pathlib import Path

from aloc.fileops import read_bytes, atomic_write, safe_backup
from aloc.format import (
    is_locked,
    encode_file,
    parse_locked_file,
    get_version,
    VERSION_V1,
    VERSION_V2,
)
from aloc.crypto import (
    derive_project_key,
    encrypt_payload,
    decrypt_payload,
    generate_file_key,
    wrap_key,
    unwrap_key,
    encrypt_payload_v2,
    decrypt_payload_v2,
)
from aloc.cache import (
    project_id,
    cache_get_project_key,
    cache_store_project_key,
    cache_get_password,
    cache_store_password,
    cache_forget,
)
from aloc.recovery import (
    generate_recovery_key,
    derive_recovery_wrapping_key,
    recover_file_key,
)
from aloc.install import install_as
from aloc.manifest import (
    get_rel_path,
    compute_hash,
    register_lock,
    unregister_lock,
    list_locked_files,
    create_backup,
    restore_from_backup,
)


# ---------------------------------------------------------------------------
# Password prompts
# ---------------------------------------------------------------------------

def prompt_password() -> str:
    if sys.stdin.isatty():
        pw = getpass.getpass("Password: ")
    else:
        pw = sys.stdin.readline().rstrip("\n")
    if not pw:
        raise ValueError("password cannot be empty")
    return pw


def prompt_new_password() -> str:
    if sys.stdin.isatty():
        pw1 = getpass.getpass("New password: ")
        if not pw1:
            raise ValueError("password cannot be empty")
        pw2 = getpass.getpass("Confirm password: ")
    else:
        pw1 = sys.stdin.readline().rstrip("\n")
        if not pw1:
            raise ValueError("password cannot be empty")
        pw2 = sys.stdin.readline().rstrip("\n")
    if pw1 != pw2:
        raise ValueError("passwords do not match")
    return pw1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _unwrap_with_password(header: dict, password: str) -> bytes:
    """Find password wrap, derive wrapping_key, unwrap file_key."""
    key_wraps = header.get("key_wraps", [])
    pw_wrap = None
    for wrap in key_wraps:
        if wrap.get("type") == "password":
            pw_wrap = wrap
            break
    if pw_wrap is None:
        raise ValueError("no password wrap in file")

    salt = base64.b64decode(header["salt"])
    wrapping_key = derive_project_key(password, salt)
    nonce = base64.b64decode(pw_wrap["nonce"])
    wrapped = base64.b64decode(pw_wrap["wrapped"])
    return unwrap_key(wrapping_key, nonce, wrapped)


def _decrypt_v2(header: dict, ciphertext: bytes, file_key: bytes) -> bytes:
    """Decrypt v2 payload using file_key."""
    nonce = base64.b64decode(header["nonce"])
    return decrypt_payload_v2(file_key, nonce, ciphertext)


# ---------------------------------------------------------------------------
# Directory helpers
# ---------------------------------------------------------------------------

# Directories/patterns to skip when recursing
_SKIP_DIRS = {".ailock", "__pycache__", ".git", "node_modules", ".venv", "venv"}
_SKIP_SUFFIXES = {".pyc", ".pyo", ".so", ".dylib", ".dll"}


def _collect_files(path: Path) -> list:
    """Recursively collect all lockable files under a directory."""
    files = []
    for item in sorted(path.rglob("*")):
        if not item.is_file():
            continue
        # Skip hidden/ignored directories
        parts = item.relative_to(path).parts
        if any(p in _SKIP_DIRS or p.startswith(".") for p in parts[:-1]):
            continue
        # Skip certain file types
        if item.suffix in _SKIP_SUFFIXES:
            continue
        files.append(item)
    return files


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_lock(args) -> int:
    path = Path(args.path)

    if not path.exists():
        print(f"error: path not found: {path}", file=sys.stderr)
        return 1

    # Directory: recursive lock
    if path.is_dir():
        return _lock_directory(path, args)

    # Single file
    return _lock_single_file(path, args)


def _lock_directory(dir_path: Path, args) -> int:
    """Recursively lock all files in a directory."""
    files = _collect_files(dir_path)
    if not files:
        print(f"no lockable files found in: {dir_path}", file=sys.stderr)
        return 1

    # Filter out already-locked files
    to_lock = []
    for f in files:
        raw = read_bytes(f)
        if not is_locked(raw):
            to_lock.append(f)

    if not to_lock:
        print(f"all files already locked in: {dir_path}")
        return 0

    print(f"found {len(to_lock)} file(s) to lock in: {dir_path}")
    for f in to_lock:
        print(f"  {f.relative_to(dir_path)}")
    print()

    # Password once for all files
    try:
        password = prompt_new_password()
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # Cache password for subsequent run/show commands
    pid = project_id()
    ttl = getattr(args, "ttl", 300)
    cache_store_password(pid, password, ttl=ttl)

    recovery = getattr(args, "recovery", False)
    locked_count = 0
    recovery_codes = []

    for f in to_lock:
        result = _lock_file_with_password(f, password, recovery)
        if result is not None:
            locked_count += 1
            if result:  # recovery code
                recovery_codes.append((f, result))

    print(f"\nlocked {locked_count}/{len(to_lock)} file(s)")

    if recovery_codes:
        print("\nrecovery keys (save these somewhere safe):")
        for f, code in recovery_codes:
            print(f"  {f.name}: {code}")
        print()

    return 0


def _lock_file_with_password(path: Path, password: str, recovery: bool = False):
    """
    Lock a single file with a given password (no prompting).
    Returns recovery_code if generated, empty string if success without recovery, None on failure.
    """
    raw = read_bytes(path)

    if is_locked(raw):
        return None

    # Compute original hash and create backup
    original_hash = compute_hash(raw)
    rel_path = get_rel_path(path)
    backup_name = create_backup(rel_path, raw, password)

    metadata = {
        "filename": path.name,
        "mode": path.stat().st_mode,
        "mtime": int(path.stat().st_mtime),
    }

    salt = os.urandom(16)
    file_key = generate_file_key()
    nonce, ciphertext = encrypt_payload_v2(file_key, raw, metadata)

    # Wrap file_key with password-derived key
    pw_key = derive_project_key(password, salt)
    pw_nonce, pw_wrapped = wrap_key(pw_key, file_key)

    key_wraps = [
        {
            "type": "password",
            "nonce": base64.b64encode(pw_nonce).decode("ascii"),
            "wrapped": base64.b64encode(pw_wrapped).decode("ascii"),
        }
    ]

    recovery_code = None
    if recovery:
        recovery_code, recovery_raw = generate_recovery_key()
        rec_key = derive_recovery_wrapping_key(recovery_raw, salt)
        rec_nonce, rec_wrapped = wrap_key(rec_key, file_key)
        key_wraps.append({
            "type": "recovery",
            "nonce": base64.b64encode(rec_nonce).decode("ascii"),
            "wrapped": base64.b64encode(rec_wrapped).decode("ascii"),
        })

    header = {
        "kdf": "argon2id",
        "aead": "chacha20poly1305",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "created": int(time.time()),
        "hint": None,
        "key_wraps": key_wraps,
    }

    encrypted = encode_file(header, ciphertext, version=VERSION_V2)
    atomic_write(path, encrypted)

    # Register in manifest
    locked_hash = compute_hash(encrypted)
    register_lock(rel_path, original_hash, locked_hash, backup_name)

    print(f"  locked: {path}")
    return recovery_code or ""


def _lock_single_file(path: Path, args) -> int:
    """Lock a single file (interactive, prompts for password)."""

    # Single file lock
    try:
        password = prompt_new_password()
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # Cache password for subsequent run/show commands
    pid = project_id()
    ttl = getattr(args, "ttl", 300)
    cache_store_password(pid, password, ttl=ttl)

    result = _lock_file_with_password(path, password, getattr(args, "recovery", False))
    if result is None:
        print(f"error: already locked: {path}", file=sys.stderr)
        return 1

    if result:  # recovery code
        print()
        print("recovery key (save this somewhere safe, it will not be shown again):")
        print(f"  {result}")
        print()

    return 0


def cmd_show(args) -> int:
    path = Path(args.path)

    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1

    blob = read_bytes(path)

    if not is_locked(blob):
        print(f"error: not locked: {path}", file=sys.stderr)
        return 1

    # show always requires password (security: exposes plaintext to terminal)
    try:
        password = prompt_password()
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        plaintext = _decrypt_with_password(blob, password)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if hasattr(sys.stdout, "buffer"):
        sys.stdout.buffer.write(plaintext)
    else:
        sys.stdout.write(plaintext.decode("utf-8", errors="replace"))

    return 0


def cmd_unlock(args) -> int:
    path = Path(args.path)

    if not path.exists():
        print(f"error: path not found: {path}", file=sys.stderr)
        return 1

    # Directory: recursive unlock
    if path.is_dir():
        return _unlock_directory(path, args)

    # Single file
    return _unlock_single_file(path, args)


def _unlock_directory(dir_path: Path, args) -> int:
    """Recursively unlock all locked files in a directory."""
    files = _collect_files(dir_path)

    # Filter to only locked files
    to_unlock = []
    for f in files:
        raw = read_bytes(f)
        if is_locked(raw):
            to_unlock.append(f)

    if not to_unlock:
        print(f"no locked files found in: {dir_path}")
        return 0

    print(f"found {len(to_unlock)} locked file(s) in: {dir_path}")
    for f in to_unlock:
        print(f"  {f.relative_to(dir_path)}")
    print()

    # Prompt password once for all files
    try:
        password = prompt_password()
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    unlocked_count = 0
    for f in to_unlock:
        blob = read_bytes(f)
        try:
            plaintext = _decrypt_with_password(blob, password)
        except ValueError as e:
            print(f"  error: {f.name}: {e}", file=sys.stderr)
            continue

        if getattr(args, "backup", False):
            safe_backup(f, blob)

        atomic_write(f, plaintext)
        rel_path = get_rel_path(f)
        unregister_lock(rel_path)
        print(f"  unlocked: {f}")
        unlocked_count += 1

    print(f"\nunlocked {unlocked_count}/{len(to_unlock)} file(s)")
    return 0


def _unlock_single_file(path: Path, args) -> int:
    """Unlock a single file."""

    blob = read_bytes(path)

    if not is_locked(blob):
        print(f"error: not locked: {path}", file=sys.stderr)
        return 1

    try:
        plaintext = _decrypt_with_cache(blob, args)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if getattr(args, "backup", False):
        safe_backup(path, blob)

    atomic_write(path, plaintext)
    rel_path = get_rel_path(path)
    unregister_lock(rel_path)
    print(f"unlocked: {path}")
    return 0


def _decrypt_with_password(blob: bytes, password: str) -> bytes:
    """Decrypt a blob using a given password directly (no prompting, no cache)."""
    version = get_version(blob)
    header, ciphertext = parse_locked_file(blob)
    salt = base64.b64decode(header["salt"])

    if version == VERSION_V1:
        key = derive_project_key(password, salt)
        return decrypt_payload(key, header, ciphertext)

    elif version == VERSION_V2:
        pw_key = derive_project_key(password, salt)
        file_key = _unwrap_with_password_key(header, pw_key)
        return _decrypt_v2(header, ciphertext, file_key)

    else:
        raise ValueError(f"unsupported file version: {version}")


def _decrypt_with_cache(blob: bytes, args) -> bytes:
    """Common decrypt logic with cache + version dispatch."""
    version = get_version(blob)
    header, ciphertext = parse_locked_file(blob)
    pid = project_id()
    ttl = getattr(args, "ttl", 300)

    if version == VERSION_V1:
        # Legacy: project_key directly decrypts payload
        key = cache_get_project_key(pid)
        salt = base64.b64decode(header["salt"])

        if key is None:
            password = prompt_password()
            key = derive_project_key(password, salt)
            try:
                plaintext = decrypt_payload(key, header, ciphertext)
            except ValueError:
                raise
            cache_store_project_key(pid, key, ttl=ttl)
            return plaintext

        try:
            return decrypt_payload(key, header, ciphertext)
        except ValueError:
            # Cached key invalid, re-prompt
            cache_forget(pid)
            password = prompt_password()
            key = derive_project_key(password, salt)
            plaintext = decrypt_payload(key, header, ciphertext)
            cache_store_project_key(pid, key, ttl=ttl)
            return plaintext

    elif version == VERSION_V2:
        # V2: cache stores password-derived key (wrapping key)
        salt = base64.b64decode(header["salt"])
        cached_pw_key = cache_get_project_key(pid)

        if cached_pw_key is not None:
            try:
                file_key = _unwrap_with_password_key(header, cached_pw_key)
                return _decrypt_v2(header, ciphertext, file_key)
            except ValueError:
                cache_forget(pid)

        password = prompt_password()
        pw_key = derive_project_key(password, salt)
        try:
            file_key = _unwrap_with_password_key(header, pw_key)
        except ValueError:
            raise ValueError("wrong password or corrupted file")

        plaintext = _decrypt_v2(header, ciphertext, file_key)
        cache_store_project_key(pid, pw_key, ttl=ttl)
        return plaintext

    else:
        raise ValueError(f"unsupported file version: {version}")


def _unwrap_with_password_key(header: dict, pw_key: bytes) -> bytes:
    """Unwrap file_key using already-derived password key."""
    key_wraps = header.get("key_wraps", [])
    pw_wrap = None
    for wrap in key_wraps:
        if wrap.get("type") == "password":
            pw_wrap = wrap
            break
    if pw_wrap is None:
        raise ValueError("no password wrap in file")

    nonce = base64.b64decode(pw_wrap["nonce"])
    wrapped = base64.b64decode(pw_wrap["wrapped"])
    return unwrap_key(pw_key, nonce, wrapped)


def cmd_status(args) -> int:
    path = Path(args.path)

    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1

    blob = read_bytes(path)

    if is_locked(blob):
        print("locked")
    else:
        print("plain")

    return 0


def cmd_forget(args) -> int:
    if getattr(args, "all", False):
        cache_forget(None)
        print("forgot all cached keys")
    else:
        cache_forget(project_id())
        print("forgot cached key for current project")
    return 0


def cmd_init(args) -> int:
    try:
        target = install_as(args.name)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"installed as: {target}")
    print()
    print("Note: make sure the install directory is in your PATH.")
    if sys.platform == "win32":
        print("  Windows: add %USERPROFILE%\\.local\\bin to PATH")
    else:
        print("  Unix: add ~/.local/bin to PATH")
    return 0


def cmd_config(args) -> int:
    """View or set ailock configuration."""
    from aloc.manifest import load_config, set_backup_dir, get_backup_dir

    key = getattr(args, "key", None)
    value = getattr(args, "value", None)

    if key is None:
        # Show all config
        config = load_config()
        if not config:
            print("no custom config (using defaults)")
            print(f"  backup-dir: {get_backup_dir()}")
        else:
            for k, v in config.items():
                print(f"  {k}: {v}")
        return 0

    if key == "backup-dir":
        if value is None:
            print(f"backup-dir: {get_backup_dir()}")
        else:
            resolved = set_backup_dir(value)
            print(f"backup directory set to: {resolved}")
        return 0

    print(f"error: unknown config key '{key}'", file=sys.stderr)
    print("available keys: backup-dir", file=sys.stderr)
    return 1


def cmd_recover(args) -> int:
    path = Path(args.path)

    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1

    blob = read_bytes(path)

    if not is_locked(blob):
        print(f"error: not locked: {path}", file=sys.stderr)
        return 1

    version = get_version(blob)
    if version != VERSION_V2:
        print("error: recovery is only supported on v2 files", file=sys.stderr)
        return 1

    header, ciphertext = parse_locked_file(blob)

    if sys.stdin.isatty():
        recovery_code = getpass.getpass("Recovery key: ")
    else:
        recovery_code = sys.stdin.readline().rstrip("\n")

    if not recovery_code:
        print("error: recovery key cannot be empty", file=sys.stderr)
        return 1

    try:
        file_key = recover_file_key(header, recovery_code)
        plaintext = _decrypt_v2(header, ciphertext, file_key)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.backup:
        safe_backup(path, blob)

    atomic_write(path, plaintext)
    print(f"recovered: {path}")
    return 0


# ---------------------------------------------------------------------------
# Freelock command - JSON-RPC workspace server
# ---------------------------------------------------------------------------

def cmd_freelock(args) -> int:
    """Start a decrypted workspace server (stdin/stdout JSON-RPC)."""
    import json

    path = Path(args.path).resolve()
    if not path.exists():
        print(f"error: path not found: {path}", file=sys.stderr)
        return 1
    if path.is_file():
        path = path.parent

    password = prompt_password()

    from aloc.workspace import DecryptedWorkspace
    ws = DecryptedWorkspace(path, password)

    lazy = not getattr(args, "eager", False)
    ws.load(lazy=lazy)

    locked_count = sum(1 for f in ws._files.values() if f.is_locked)
    print(json.dumps({
        "status": "ready",
        "directory": str(path),
        "total_files": len(ws._files),
        "locked_files": locked_count,
    }), flush=True)

    # JSON-RPC loop: read one JSON object per line from stdin
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        if line in ("quit", "exit"):
            break

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            response = {"error": f"invalid JSON: {e}"}
            print(json.dumps(response), flush=True)
            continue

        method = request.get("method", "")
        params = request.get("params", {})
        req_id = request.get("id")

        result = ws.handle_tool_call(method, params)

        if req_id is not None:
            result["id"] = req_id

        print(json.dumps(result, ensure_ascii=False), flush=True)

    ws.close()
    return 0


# ---------------------------------------------------------------------------
# Open command - GUI editor
# ---------------------------------------------------------------------------

def cmd_open(args) -> int:
    """Open a directory in the AiLock GUI editor."""
    path = Path(args.path).resolve()

    if not path.exists():
        print(f"error: path not found: {path}", file=sys.stderr)
        return 1

    if path.is_file():
        path = path.parent

    # Prompt for password
    password = prompt_password()

    from aloc.gui import launch_editor
    launch_editor(path, password)
    return 0


# ---------------------------------------------------------------------------
# Run command - memory-only execution
# ---------------------------------------------------------------------------

def _resolve_module_path(module_name: str, search_dir: Path) -> Path | None:
    """Resolve a module name to a file path (like python -m)."""
    parts = module_name.split(".")

    # Try as package: mypackage/__main__.py
    pkg_dir = search_dir / Path(*parts)
    main_file = pkg_dir / "__main__.py"
    if main_file.exists():
        return main_file

    # Try as module: mymodule.py
    if len(parts) == 1:
        module_file = search_dir / f"{parts[0]}.py"
    else:
        module_file = search_dir / Path(*parts[:-1]) / f"{parts[-1]}.py"

    if module_file.exists():
        return module_file

    return None


def cmd_run(args) -> int:
    """Decrypt an encrypted Python file and execute it entirely in memory."""
    module_mode = getattr(args, "module", False)

    if module_mode:
        # python -m style: resolve module name to file path
        search_dir = Path.cwd()
        path = _resolve_module_path(args.path, search_dir)
        if path is None:
            print(f"error: no module named '{args.path}'", file=sys.stderr)
            return 1
        path = path.resolve()
    else:
        path = Path(args.path).resolve()

        # Support directory as target (like `python mypackage/`)
        if path.is_dir():
            main_file = path / "__main__.py"
            if main_file.exists():
                path = main_file
            else:
                print(f"error: directory has no __main__.py: {path}", file=sys.stderr)
                return 1

        if not path.exists():
            print(f"error: file not found: {path}", file=sys.stderr)
            return 1

        if not path.suffix == ".py":
            print(f"error: only .py files are supported: {path}", file=sys.stderr)
            return 1

    blob = read_bytes(path)
    if not is_locked(blob):
        print(f"warning: {path.name} is not encrypted, running as plain Python", file=sys.stderr)

    # For 'run': use cached password (silent), prompt only if no cache
    pid = project_id()
    ttl = getattr(args, "ttl", 300)
    cached_pw = cache_get_password(pid)

    if cached_pw is None:
        # No cached password, prompt
        try:
            cached_pw = prompt_password()
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        cache_store_password(pid, cached_pw, ttl=ttl)

    password = cached_pw

    # Strip leading '--' from script_args if present
    script_args = getattr(args, "script_args", []) or []
    if script_args and script_args[0] == "--":
        script_args = script_args[1:]

    from aloc.runner import run_in_memory
    return run_in_memory(path, password=password, script_args=script_args)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]):
    parser = argparse.ArgumentParser(
        prog="aloc", description="AiLock - encrypt files in place"
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    lock_parser = subparsers.add_parser("lock", help="lock file(s) in place")
    lock_parser.add_argument("path", help="file or directory to lock")
    lock_parser.add_argument(
        "--recovery", action="store_true",
        help="generate a recovery key alongside the password"
    )

    show_parser = subparsers.add_parser("show", help="show decrypted content")
    show_parser.add_argument("path", help="file to show")
    show_parser.add_argument(
        "--ttl", type=int, default=300,
        help="cache TTL in seconds (default: 300)"
    )

    unlock_parser = subparsers.add_parser("unlock", help="unlock file(s) in place")
    unlock_parser.add_argument("path", help="file or directory to unlock")
    unlock_parser.add_argument(
        "--backup", action="store_true", help="create .bak before unlocking"
    )
    unlock_parser.add_argument(
        "--ttl", type=int, default=300,
        help="cache TTL in seconds (default: 300)"
    )

    status_parser = subparsers.add_parser("status", help="check if file is locked")
    status_parser.add_argument("path", help="file to check")

    forget_parser = subparsers.add_parser("forget", help="forget cached keys")
    forget_parser.add_argument(
        "--all", action="store_true", help="forget all projects, not just current"
    )

    init_parser = subparsers.add_parser("init", help="install as a custom command name")
    init_parser.add_argument(
        "--as", dest="name", default="aa", help="command name to install as"
    )

    config_parser = subparsers.add_parser("config", help="view or set configuration")
    config_parser.add_argument("key", nargs="?", default=None, help="config key (e.g. backup-dir)")
    config_parser.add_argument("value", nargs="?", default=None, help="value to set")

    recover_parser = subparsers.add_parser(
        "recover", help="recover a file with a recovery key"
    )
    recover_parser.add_argument("path", help="file to recover")
    recover_parser.add_argument(
        "--backup", action="store_true", help="create .bak before recovering"
    )

    run_parser = subparsers.add_parser(
        "run", help="decrypt and execute a Python file in memory (AI cannot see plaintext)"
    )
    run_parser.add_argument("path", help="encrypted .py file or module name (with -m)")
    run_parser.add_argument(
        "-m", "--module", action="store_true",
        help="run as module (like python -m)"
    )
    run_parser.add_argument(
        "script_args", nargs=argparse.REMAINDER,
        help="arguments passed to the script (after --)"
    )
    run_parser.add_argument(
        "--ttl", type=int, default=300,
        help="cache TTL in seconds (default: 300)"
    )

    open_parser = subparsers.add_parser(
        "open", help="open encrypted files in GUI editor"
    )
    open_parser.add_argument("path", nargs="?", default=".", help="directory to open (default: current)")

    freelock_parser = subparsers.add_parser(
        "freelock", help="start a decrypted workspace server (stdin/stdout JSON-RPC)"
    )
    freelock_parser.add_argument("path", nargs="?", default=".", help="directory to expose (default: current)")
    freelock_parser.add_argument(
        "--eager", action="store_true",
        help="decrypt all files upfront (slower start, faster reads)"
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    args = parse_args(argv)

    if args.cmd == "lock":
        return cmd_lock(args)
    elif args.cmd == "show":
        return cmd_show(args)
    elif args.cmd == "unlock":
        return cmd_unlock(args)
    elif args.cmd == "status":
        return cmd_status(args)
    elif args.cmd == "forget":
        return cmd_forget(args)
    elif args.cmd == "init":
        return cmd_init(args)
    elif args.cmd == "config":
        return cmd_config(args)
    elif args.cmd == "recover":
        return cmd_recover(args)
    elif args.cmd == "run":
        return cmd_run(args)
    elif args.cmd == "open":
        return cmd_open(args)
    elif args.cmd == "freelock":
        return cmd_freelock(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())
