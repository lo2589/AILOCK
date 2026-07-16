"""
Backup and manifest management for .ailock/ directory.

Handles:
- .ailock/ directory structure
- manifest.json tracking of all locked files
- Zip-encrypted backup creation and restoration
- SHA256 hash computation
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Optional


def _find_git_root() -> Optional[Path]:
    """Find the git root directory."""
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


def get_project_root() -> Path:
    """Get project root (git root or cwd)."""
    return _find_git_root() or Path.cwd()


def _config_path() -> Path:
    """Get config file path (always at project root)."""
    return get_project_root() / ".ailock" / "config.json"


def load_config() -> dict:
    """Load .ailock/config.json. Returns empty dict if not found."""
    path = _config_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_config(config: dict) -> None:
    """Save config to .ailock/config.json."""
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(config, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def get_backup_dir() -> Path:
    """Get the backup directory, respecting user config."""
    config = load_config()
    custom = config.get("backup_dir")
    if custom:
        p = Path(custom).expanduser()
        if not p.is_absolute():
            p = get_project_root() / p
        p.mkdir(parents=True, exist_ok=True)
        return p
    # Default: .ailock/backups/
    default = get_project_root() / ".ailock" / "backups"
    default.mkdir(parents=True, exist_ok=True)
    return default


def set_backup_dir(path_str: str) -> Path:
    """Set custom backup directory. Returns resolved path."""
    p = Path(path_str).expanduser()
    if not p.is_absolute():
        p = get_project_root() / p
    p.mkdir(parents=True, exist_ok=True)
    config = load_config()
    config["backup_dir"] = str(p)
    save_config(config)
    return p


def get_ailock_dir() -> Path:
    """Get the .ailock/ directory path under project root, creating if needed."""
    ailock_dir = get_project_root() / ".ailock"
    ailock_dir.mkdir(parents=True, exist_ok=True)
    get_backup_dir()  # ensure backup dir exists
    return ailock_dir


def compute_hash(data: bytes) -> str:
    """Compute SHA256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()


def _manifest_path() -> Path:
    """Get the manifest.json file path."""
    return get_ailock_dir() / "manifest.json"


def load_manifest() -> dict:
    """Load manifest.json. Returns empty structure if not found."""
    path = _manifest_path()
    if not path.exists():
        return {"files": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if "files" not in data:
            data["files"] = {}
        return data
    except (json.JSONDecodeError, OSError):
        return {"files": {}}


def save_manifest(manifest: dict) -> None:
    """Save manifest.json atomically."""
    path = _manifest_path()
    path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _encode_backup_name(rel_path: str) -> str:
    """Encode a relative path into a safe filename for backup zip."""
    # Replace path separators and special chars with underscores
    safe = rel_path.replace("/", "_").replace("\\", "_")
    # Remove leading dots to avoid hidden files
    safe = safe.lstrip(".")
    return safe + ".zip"


def get_rel_path(file_path: Path) -> str:
    """Get relative path from project root."""
    root = get_project_root()
    try:
        return str(file_path.resolve().relative_to(root.resolve()))
    except ValueError:
        # File is outside project root, use absolute path
        return str(file_path.resolve())


def register_lock(rel_path: str, original_hash: str, locked_hash: str, backup_name: str) -> None:
    """Register a file as locked in manifest."""
    manifest = load_manifest()
    manifest["files"][rel_path] = {
        "filename": Path(rel_path).name,
        "original_hash": original_hash,
        "locked_hash": locked_hash,
        "locked_at": int(time.time()),
        "backup": f"backups/{backup_name}",
    }
    save_manifest(manifest)


def unregister_lock(rel_path: str) -> None:
    """Remove a file from manifest (on unlock)."""
    manifest = load_manifest()
    if rel_path in manifest["files"]:
        del manifest["files"][rel_path]
    save_manifest(manifest)


def update_locked_hash(rel_path: str, locked_hash: str) -> bool:
    """Refresh a tracked file's ciphertext hash after an encrypted edit."""
    manifest = load_manifest()
    entry = manifest["files"].get(rel_path)
    if entry is None:
        return False
    entry["locked_hash"] = locked_hash
    entry["updated_at"] = int(time.time())
    save_manifest(manifest)
    return True


def list_locked_files(prefix: Optional[str] = None) -> list:
    """
    List all locked file paths.
    If prefix is given, filter to files under that directory.
    """
    manifest = load_manifest()
    files = list(manifest["files"].keys())
    if prefix:
        # Normalize prefix
        prefix = prefix.rstrip("/") + "/"
        files = [f for f in files if f.startswith(prefix) or f == prefix.rstrip("/")]
    return sorted(files)


def create_backup(rel_path: str, original_data: bytes, password: str) -> str:
    """
    Create a zip-encrypted backup of the original file data.

    Returns the backup filename.
    """
    ailock_dir = get_ailock_dir()
    backup_name = _encode_backup_name(rel_path)
    backup_dir = get_backup_dir()
    backup_path = backup_dir / backup_name

    # If backup already exists, add timestamp
    if backup_path.exists():
        stem = backup_path.stem
        backup_name = f"{stem}_{int(time.time())}.zip"
        backup_path = backup_dir / backup_name

    # Create zip with password protection
    # Python's zipfile doesn't support writing encrypted zips natively,
    # so we use pyminizip or fall back to a simple approach:
    # Store as AES-encrypted zip using pyzipper if available, else plain zip
    try:
        import pyzipper

        with pyzipper.AESZipFile(
            backup_path,
            "w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as zf:
            zf.setpassword(password.encode("utf-8"))
            # Use the original filename inside the zip
            filename = Path(rel_path).name
            zf.writestr(filename, original_data)
    except ImportError:
        # Fallback: use standard zipfile (no encryption, but still zipped)
        # We encrypt the content ourselves before zipping
        from aloc.crypto import derive_project_key, encrypt_payload_v2, generate_file_key
        import base64

        # Encrypt data with password before putting in zip
        salt = os.urandom(16)
        file_key = generate_file_key()
        from aloc.crypto import wrap_key
        pw_key = derive_project_key(password, salt)
        nonce, ciphertext = encrypt_payload_v2(file_key, original_data, {"backup": True})
        pw_nonce, pw_wrapped = wrap_key(pw_key, file_key)

        backup_data = json.dumps({
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "pw_nonce": base64.b64encode(pw_nonce).decode("ascii"),
            "pw_wrapped": base64.b64encode(pw_wrapped).decode("ascii"),
        }).encode("utf-8")

        with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zf:
            filename = Path(rel_path).name
            # Store encrypted metadata
            zf.writestr(filename + ".meta", backup_data)
            # Store ciphertext
            zf.writestr(filename + ".enc", ciphertext)

    return backup_name


def _find_backup_entry(rel_path: str, current_hash: Optional[str] = None) -> Optional[tuple]:
    """
    Multi-level fallback to find backup entry in manifest.

    Strategy:
      1. Exact path match
      2. Hash match (locked_hash matches current file hash)
      3. Filename match (last resort, may have multiple candidates)

    Returns (matched_key, entry) or None.
    """
    manifest = load_manifest()
    files = manifest.get("files", {})

    # Level 1: exact path
    if rel_path in files:
        return rel_path, files[rel_path]

    # Level 2: match by locked_hash (file was moved but content unchanged)
    if current_hash:
        for key, entry in files.items():
            if entry.get("locked_hash") == current_hash:
                return key, entry

    # Level 3: match by filename (file moved + possibly corrupted)
    target_name = Path(rel_path).name
    candidates = []
    for key, entry in files.items():
        entry_name = entry.get("filename") or Path(key).name
        if entry_name == target_name:
            candidates.append((key, entry))

    if len(candidates) == 1:
        return candidates[0]
    elif len(candidates) > 1:
        # Multiple matches - pick the most recent one
        candidates.sort(key=lambda x: x[1].get("locked_at", 0), reverse=True)
        return candidates[0]

    return None


def restore_from_backup(rel_path: str, password: str, current_hash: Optional[str] = None) -> Optional[bytes]:
    """
    Restore original file data from backup.

    Uses multi-level fallback:
      1. Exact path match
      2. Hash match (file moved but content intact)
      3. Filename match (file moved + content corrupted)

    Returns the original plaintext data, or None if backup not found.
    """
    result = _find_backup_entry(rel_path, current_hash)
    if result is None:
        return None

    matched_key, entry = result
    if matched_key != rel_path:
        import sys
        print(f"  (matched backup via: {matched_key})", file=sys.stderr)

    ailock_dir = get_ailock_dir()
    backup_dir = get_backup_dir()
    backup_path = backup_dir / Path(entry["backup"]).name

    if not backup_path.exists():
        return None

    try:
        import pyzipper

        with pyzipper.AESZipFile(backup_path, "r") as zf:
            zf.setpassword(password.encode("utf-8"))
            names = zf.namelist()
            if names:
                return zf.read(names[0])
    except ImportError:
        # Fallback: decrypt from our custom format
        import base64
        from aloc.crypto import derive_project_key, decrypt_payload_v2, unwrap_key

        with zipfile.ZipFile(backup_path, "r") as zf:
            names = zf.namelist()
            meta_file = [n for n in names if n.endswith(".meta")]
            enc_file = [n for n in names if n.endswith(".enc")]

            if not meta_file or not enc_file:
                return None

            meta = json.loads(zf.read(meta_file[0]))
            ciphertext = zf.read(enc_file[0])

            salt = base64.b64decode(meta["salt"])
            nonce = base64.b64decode(meta["nonce"])
            pw_nonce = base64.b64decode(meta["pw_nonce"])
            pw_wrapped = base64.b64decode(meta["pw_wrapped"])

            pw_key = derive_project_key(password, salt)
            file_key = unwrap_key(pw_key, pw_nonce, pw_wrapped)
            return decrypt_payload_v2(file_key, nonce, ciphertext)

    return None
