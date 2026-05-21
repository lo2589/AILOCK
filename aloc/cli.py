import argparse
import base64
import getpass
import os
import sys
import time
from pathlib import Path

from aloc.fileops import read_bytes, atomic_write, safe_backup
from aloc.format import is_locked, encode_file, parse_locked_file
from aloc.crypto import (
    derive_project_key,
    encrypt_payload,
    decrypt_payload,
    verify_key_or_fail,
)


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
    key = derive_project_key(password, salt)
    nonce, ciphertext = encrypt_payload(key, raw, metadata)

    header = {
        "kdf": "argon2id",
        "aead": "chacha20poly1305",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "created": int(time.time()),
        "hint": None,
    }

    encrypted = encode_file(header, ciphertext)
    atomic_write(path, encrypted)
    print(f"locked: {path}")
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
        header, ciphertext = parse_locked_file(blob)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        password = prompt_password()
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    salt = base64.b64decode(header["salt"])
    key = derive_project_key(password, salt)

    try:
        verify_key_or_fail(key, header, ciphertext)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    plaintext = decrypt_payload(key, header, ciphertext)

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

    try:
        header, ciphertext = parse_locked_file(blob)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        password = prompt_password()
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    salt = base64.b64decode(header["salt"])
    key = derive_project_key(password, salt)

    try:
        plaintext = decrypt_payload(key, header, ciphertext)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.backup:
        safe_backup(path, blob)

    atomic_write(path, plaintext)
    print(f"unlocked: {path}")
    return 0


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


def parse_args(argv: list[str]):
    parser = argparse.ArgumentParser(
        prog="aloc", description="AiLock - encrypt files in place"
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    lock_parser = subparsers.add_parser("lock", help="lock a file in place")
    lock_parser.add_argument("path", help="file to lock")

    show_parser = subparsers.add_parser("show", help="show decrypted content")
    show_parser.add_argument("path", help="file to show")

    unlock_parser = subparsers.add_parser("unlock", help="unlock a file in place")
    unlock_parser.add_argument("path", help="file to unlock")
    unlock_parser.add_argument(
        "--backup", action="store_true", help="create .bak before unlocking"
    )

    status_parser = subparsers.add_parser("status", help="check if file is locked")
    status_parser.add_argument("path", help="file to check")

    forget_parser = subparsers.add_parser(
        "forget", help="forget cached keys (placeholder)"
    )

    init_parser = subparsers.add_parser("init", help="install alias (placeholder)")
    init_parser.add_argument(
        "--as", dest="name", default="aa", help="command name to install as"
    )

    recover_parser = subparsers.add_parser(
        "recover", help="recover with recovery key (placeholder)"
    )
    recover_parser.add_argument("path", help="file to recover")

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
        print("forget: cache not implemented in Phase 1")
        return 0
    elif args.cmd == "init":
        print(f"init: installing as '{args.name}' not implemented in Phase 1")
        return 0
    elif args.cmd == "recover":
        print("recover: not implemented in Phase 1")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
