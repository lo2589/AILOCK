"""
CLI entry point for aloc.
"""

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
    cache_forget,
)
from aloc.recovery import (
    generate_recovery_key,
    derive_recovery_wrapping_key,
    recover_file_key,
)
from aloc.install import install_as


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
# Commands
# ---------------------------------------------------------------------------

def cmd_lock(args) -> int:
    path = Path(args.path)

    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1

    raw = read_bytes(path)

    if is_locked(raw):
        print(f"error: already locked: {path}", file=sys.stderr)
        return 1

    try:
        password = prompt_new_password()
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

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
    if getattr(args, "recovery", False):
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
    print(f"locked: {path}")

    if recovery_code:
        print()
        print("recovery key (save this somewhere safe, it will not be shown again):")
        print(f"  {recovery_code}")
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

    try:
        plaintext = _decrypt_with_cache(blob, args)
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
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1

    blob = read_bytes(path)

    if not is_locked(blob):
        print(f"error: not locked: {path}", file=sys.stderr)
        return 1

    try:
        plaintext = _decrypt_with_cache(blob, args)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.backup:
        safe_backup(path, blob)

    atomic_write(path, plaintext)
    print(f"unlocked: {path}")
    return 0


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
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]):
    parser = argparse.ArgumentParser(
        prog="aloc", description="AiLock - encrypt files in place"
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    lock_parser = subparsers.add_parser("lock", help="lock a file in place")
    lock_parser.add_argument("path", help="file to lock")
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

    unlock_parser = subparsers.add_parser("unlock", help="unlock a file in place")
    unlock_parser.add_argument("path", help="file to unlock")
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

    recover_parser = subparsers.add_parser(
        "recover", help="recover a file with a recovery key"
    )
    recover_parser.add_argument("path", help="file to recover")
    recover_parser.add_argument(
        "--backup", action="store_true", help="create .bak before recovering"
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
    elif args.cmd == "recover":
        return cmd_recover(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())
