"""
DecryptedWorkspace - A memory-only decrypted view of an ailock-encrypted directory.

Provides a standard file-operation API that external tools/frameworks can use
to read, write, list, and search encrypted files WITHOUT writing plaintext to disk.

Usage:
    from aloc.workspace import DecryptedWorkspace

    ws = DecryptedWorkspace("/path/to/project", password="xxx")
    ws.load()

    content = ws.read_file("src/secret.py")
    ws.write_file("src/secret.py", new_content)
    files = ws.list_files()
    results = ws.grep("pattern")
    ws.flush()
"""

from __future__ import annotations

import base64
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from aloc.fileops import read_bytes, atomic_write
from aloc.format import is_locked, encode_file


# Directories to skip
_SKIP_DIRS = {".ailock", "__pycache__", ".git", "node_modules", ".venv", "venv"}
_SKIP_SUFFIXES = {".pyc", ".pyo", ".so", ".dylib", ".dll"}


@dataclass
class FileEntry:
    """A file in the workspace."""
    rel_path: str
    abs_path: Path
    is_locked: bool
    content: str | None = None  # decrypted content (None = not loaded)
    dirty: bool = False         # has unsaved modifications


class DecryptedWorkspace:
    """
    In-memory decrypted view of an encrypted directory.

    All file content stays in process memory. External frameworks
    interact through this API — plaintext never touches disk until flush().
    """

    def __init__(self, directory: str | Path, password: str):
        self.directory = Path(directory).resolve()
        self.password = password
        self._files: dict[str, FileEntry] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self, lazy: bool = True):
        """
        Scan directory and optionally decrypt all files.

        Args:
            lazy: If True, only scan file list (decrypt on first read).
                  If False, decrypt everything upfront.
        """
        self._files.clear()
        self._scan_directory(self.directory)
        self._loaded = True

        if not lazy:
            for entry in self._files.values():
                if entry.is_locked and entry.content is None:
                    self._decrypt_entry(entry)

    def close(self):
        """Flush dirty files and clear memory."""
        self.flush()
        self._files.clear()
        self._loaded = False

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def list_files(self, pattern: str | None = None) -> list[str]:
        """
        List all files in workspace.

        Args:
            pattern: Optional glob pattern (e.g. "*.py", "src/**/*.py")

        Returns:
            List of relative paths.
        """
        self._ensure_loaded()
        paths = list(self._files.keys())
        if pattern:
            from fnmatch import fnmatch
            paths = [p for p in paths if fnmatch(p, pattern)]
        return sorted(paths)

    def read_file(self, rel_path: str) -> str:
        """
        Read file content (decrypted if locked).

        Args:
            rel_path: Relative path from workspace root.

        Returns:
            File content as string.

        Raises:
            FileNotFoundError: If file not in workspace.
            ValueError: If decryption fails.
        """
        self._ensure_loaded()
        entry = self._get_entry(rel_path)

        if entry.content is None:
            if entry.is_locked:
                self._decrypt_entry(entry)
            else:
                blob = read_bytes(entry.abs_path)
                try:
                    entry.content = blob.decode("utf-8")
                except UnicodeDecodeError:
                    entry.content = blob.decode("latin-1")

        return entry.content

    def file_info(self, rel_path: str) -> dict:
        """
        Get metadata about a file.

        Returns:
            Dict with keys: rel_path, abs_path, is_locked, dirty, size
        """
        self._ensure_loaded()
        entry = self._get_entry(rel_path)
        return {
            "rel_path": entry.rel_path,
            "abs_path": str(entry.abs_path),
            "is_locked": entry.is_locked,
            "dirty": entry.dirty,
            "loaded": entry.content is not None,
        }

    def grep(self, pattern: str, file_pattern: str | None = None) -> list[dict]:
        """
        Search file contents with regex.

        Args:
            pattern: Regex pattern to search for.
            file_pattern: Optional glob to filter files.

        Returns:
            List of {rel_path, line_number, line, match}
        """
        self._ensure_loaded()
        regex = re.compile(pattern)
        results = []

        targets = self.list_files(file_pattern)
        for rel_path in targets:
            try:
                content = self.read_file(rel_path)
            except (ValueError, UnicodeDecodeError):
                continue

            for i, line in enumerate(content.splitlines(), 1):
                m = regex.search(line)
                if m:
                    results.append({
                        "rel_path": rel_path,
                        "line_number": i,
                        "line": line,
                        "match": m.group(0),
                    })

        return results

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def write_file(self, rel_path: str, content: str):
        """
        Write content to a file (in memory). Call flush() to persist.

        Args:
            rel_path: Relative path from workspace root.
            content: New file content.
        """
        self._ensure_loaded()
        rel_path, abs_path = self._resolve_rel_path(rel_path)

        if rel_path in self._files:
            entry = self._files[rel_path]
            entry.content = content
            entry.dirty = True
        else:
            # New file
            entry = FileEntry(
                rel_path=rel_path,
                abs_path=abs_path,
                is_locked=True,  # new files default to locked
                content=content,
                dirty=True,
            )
            self._files[rel_path] = entry

    def delete_file(self, rel_path: str):
        """Mark a file for deletion on next flush."""
        self._ensure_loaded()
        entry = self._get_entry(rel_path)
        entry.content = None
        entry.dirty = True

    # ------------------------------------------------------------------
    # Flush (persist changes to disk, encrypted)
    # ------------------------------------------------------------------

    def flush(self) -> list[str]:
        """
        Write all dirty files back to disk (encrypted if originally locked).

        Returns:
            List of flushed file paths.
        """
        flushed = []
        for entry in self._files.values():
            if entry.dirty:
                self._flush_entry(entry)
                flushed.append(entry.rel_path)
        return flushed

    def flush_file(self, rel_path: str):
        """Flush a single file to disk."""
        entry = self._get_entry(rel_path)
        if entry.dirty:
            self._flush_entry(entry)

    # ------------------------------------------------------------------
    # JSON-RPC compatible tool interface
    # ------------------------------------------------------------------

    def handle_tool_call(self, method: str, params: dict) -> dict:
        """
        Handle a tool call in JSON-RPC style.

        Supported methods:
            - list_files(pattern?)
            - read_file(path)
            - write_file(path, content)
            - grep(pattern, file_pattern?)
            - file_info(path)
            - flush()
            - flush_file(path)
            - status()

        Returns:
            {"result": ...} or {"error": ...}
        """
        try:
            if method == "list_files":
                result = self.list_files(params.get("pattern"))
            elif method == "read_file":
                result = self.read_file(params["path"])
            elif method == "write_file":
                self.write_file(params["path"], params["content"])
                result = {"status": "ok", "path": params["path"]}
            elif method == "grep":
                result = self.grep(params["pattern"], params.get("file_pattern"))
            elif method == "file_info":
                result = self.file_info(params["path"])
            elif method == "flush":
                flushed = self.flush()
                result = {"flushed": flushed, "count": len(flushed)}
            elif method == "flush_file":
                self.flush_file(params["path"])
                result = {"status": "ok", "path": params["path"]}
            elif method == "status":
                result = {
                    "directory": str(self.directory),
                    "total_files": len(self._files),
                    "locked_files": sum(1 for e in self._files.values() if e.is_locked),
                    "dirty_files": sum(1 for e in self._files.values() if e.dirty),
                    "loaded_files": sum(1 for e in self._files.values() if e.content is not None),
                }
            else:
                return {"error": f"unknown method: {method}"}
            return {"result": result}
        except FileNotFoundError as e:
            return {"error": f"file not found: {e}"}
        except ValueError as e:
            return {"error": f"value error: {e}"}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ensure_loaded(self):
        if not self._loaded:
            self.load(lazy=True)

    def _get_entry(self, rel_path: str) -> FileEntry:
        rel_path, _ = self._resolve_rel_path(rel_path)
        if rel_path not in self._files:
            raise FileNotFoundError(rel_path)
        return self._files[rel_path]

    def _resolve_rel_path(self, rel_path: str) -> tuple[str, Path]:
        """Resolve a workspace-relative path and reject boundary escapes."""
        if not isinstance(rel_path, str) or not rel_path.strip():
            raise ValueError("path must be a non-empty string")

        normalized_input = rel_path.replace("\\", "/")
        relative = Path(normalized_input)
        if relative.is_absolute():
            raise ValueError(f"path must be relative to workspace: {rel_path}")

        resolved = (self.directory / relative).resolve()
        try:
            normalized = resolved.relative_to(self.directory).as_posix()
        except ValueError:
            raise ValueError(f"path escapes workspace: {rel_path}") from None

        if normalized in ("", "."):
            raise ValueError("path must identify a file inside workspace")
        return normalized, resolved

    def _scan_directory(self, base: Path):
        """Recursively scan and register files."""
        for item in sorted(base.rglob("*")):
            if not item.is_file():
                continue
            try:
                resolved_item = item.resolve()
                resolved_item.relative_to(self.directory)
            except (OSError, ValueError):
                # Do not expose symlinks or other paths that resolve outside
                # the workspace boundary.
                continue
            rel_parts = item.relative_to(self.directory).parts
            # Skip ignored dirs
            if any(p in _SKIP_DIRS or p.startswith(".") for p in rel_parts[:-1]):
                continue
            if item.suffix in _SKIP_SUFFIXES:
                continue

            rel_path = "/".join(rel_parts)
            try:
                blob = read_bytes(item)
                locked = is_locked(blob)
            except Exception:
                locked = False

            self._files[rel_path] = FileEntry(
                rel_path=rel_path,
                abs_path=item,
                is_locked=locked,
            )

    def _decrypt_entry(self, entry: FileEntry):
        """Decrypt a file entry into memory."""
        from aloc.cli import _decrypt_with_password

        blob = read_bytes(entry.abs_path)
        plaintext = _decrypt_with_password(blob, self.password)
        entry.content = plaintext.decode("utf-8")

    def _flush_entry(self, entry: FileEntry):
        """Write a single entry back to disk."""
        from aloc.crypto import (
            derive_project_key, generate_file_key,
            encrypt_payload_v2, wrap_key,
        )

        normalized, resolved = self._resolve_rel_path(entry.rel_path)
        entry.rel_path = normalized
        entry.abs_path = resolved

        if entry.content is None:
            # Marked for deletion
            if entry.abs_path.exists():
                entry.abs_path.unlink()
            del self._files[entry.rel_path]
            return

        data = entry.content.encode("utf-8")

        if entry.is_locked:
            # Re-encrypt
            salt = os.urandom(16)
            file_key = generate_file_key()
            metadata = {
                "filename": entry.abs_path.name,
                "mode": entry.abs_path.stat().st_mode if entry.abs_path.exists() else 0o644,
                "mtime": int(time.time()),
            }
            nonce, ciphertext = encrypt_payload_v2(file_key, data, metadata)

            pw_key = derive_project_key(self.password, salt)
            pw_nonce, pw_wrapped = wrap_key(pw_key, file_key)

            header = {
                "kdf": "argon2id",
                "aead": "chacha20poly1305",
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "key_wraps": [
                    {
                        "type": "password",
                        "nonce": base64.b64encode(pw_nonce).decode("ascii"),
                        "wrapped": base64.b64encode(pw_wrapped).decode("ascii"),
                    }
                ],
                "meta": metadata,
            }
            blob = encode_file(header, ciphertext)
            entry.abs_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(entry.abs_path, blob)
        else:
            # Plain file
            entry.abs_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(entry.abs_path, data)

        entry.dirty = False
