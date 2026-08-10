from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from ailatch.format import encode_file, parse_locked_file
from ailatch.gui import AILatchEditor
from ailatch.workspace import DecryptedWorkspace


def _header_with_recovery() -> dict:
    return {
        "kdf": "argon2id",
        "aead": "chacha20poly1305",
        "salt": "c2FsdHNhbHRzYWx0c2FsdA==",
        "nonce": "bm5ubm5ubm5ubm5u",
        "key_wraps": [
            {"type": "password", "nonce": "cHc=", "wrapped": "a2V5"},
            {"type": "recovery", "nonce": "cmVj", "wrapped": "a2V5"},
        ],
    }


def _fake_cli_module() -> types.ModuleType:
    module = types.ModuleType("ailatch.cli")

    def reencrypt(blob, plaintext, password, path):
        header, _ = parse_locked_file(blob)
        header = dict(header)
        header["nonce"] = "dXBkYXRlZG5vbmNl"
        return encode_file(header, b"updated-" + plaintext)

    module._reencrypt_with_password = reencrypt
    return module


def _write_manifest(root: Path, rel_path: str, locked_blob: bytes) -> None:
    ailatch_dir = root / ".ailatch"
    (ailatch_dir / "backups").mkdir(parents=True)
    manifest = {
        "files": {
            rel_path: {
                "filename": Path(rel_path).name,
                "original_hash": "original",
                "locked_hash": hashlib.sha256(locked_blob).hexdigest(),
                "locked_at": 1,
                "backup": f"backups/{Path(rel_path).name}.zip",
            }
        }
    }
    (ailatch_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


class _DeferredRoot:
    def after(self, delay, callback, *args):
        pass


class RecoveryPreservationTests(unittest.TestCase):
    def _assert_preserved_and_manifest_updated(self, root: Path, target: Path):
        updated_blob = target.read_bytes()
        updated_header, _ = parse_locked_file(updated_blob)
        self.assertEqual(
            [item["type"] for item in updated_header["key_wraps"]],
            ["password", "recovery"],
        )
        manifest = json.loads((root / ".ailatch" / "manifest.json").read_text())
        entry = manifest["files"][target.relative_to(root).as_posix()]
        self.assertEqual(entry["locked_hash"], hashlib.sha256(updated_blob).hexdigest())
        self.assertIn("updated_at", entry)

    def test_gui_save_preserves_recovery_and_updates_manifest(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-gui-recovery-") as temp_dir:
            root = Path(temp_dir)
            target = root / "secret.txt"
            original_blob = encode_file(_header_with_recovery(), b"old")
            target.write_bytes(original_blob)
            _write_manifest(root, "secret.txt", original_blob)

            editor = AILatchEditor.__new__(AILatchEditor)
            editor.root = _DeferredRoot()
            editor.password = "password"

            with (
                mock.patch("ailatch.manifest.get_project_root", return_value=root),
                mock.patch.dict(sys.modules, {"ailatch.cli": _fake_cli_module()}),
            ):
                editor._save_async(target, b"edited", True)

            self._assert_preserved_and_manifest_updated(root, target)

    def test_workspace_save_preserves_recovery_and_updates_manifest(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-workspace-recovery-") as temp_dir:
            root = Path(temp_dir)
            target = root / "secret.txt"
            original_blob = encode_file(_header_with_recovery(), b"old")
            target.write_bytes(original_blob)
            _write_manifest(root, "secret.txt", original_blob)

            workspace = DecryptedWorkspace(root, "password")
            workspace.load()
            entry = workspace._files["secret.txt"]
            entry.content = "edited"
            entry.dirty = True

            with (
                mock.patch("ailatch.manifest.get_project_root", return_value=root),
                mock.patch.dict(sys.modules, {"ailatch.cli": _fake_cli_module()}),
            ):
                workspace.flush()

            self._assert_preserved_and_manifest_updated(root, target)


if __name__ == "__main__":
    unittest.main(verbosity=2)
