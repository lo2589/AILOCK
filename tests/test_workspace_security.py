from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from ailatch.format import is_locked
from ailatch.workspace import DecryptedWorkspace


def _fake_crypto_module() -> types.ModuleType:
    module = types.ModuleType("ailatch.crypto")
    module.derive_project_key = lambda password, salt: b"k" * 32
    module.generate_file_key = lambda: b"f" * 32
    module.encrypt_payload_v2 = lambda key, data, metadata: (b"n" * 12, data)
    module.wrap_key = lambda key, file_key: (b"w" * 12, b"x" * 48)
    return module


class WorkspacePathSecurityTests(unittest.TestCase):
    def test_parent_traversal_is_rejected_before_flush(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-workspace-path-") as temp_dir:
            parent = Path(temp_dir)
            root = parent / "workspace"
            root.mkdir()
            workspace = DecryptedWorkspace(root, "password")
            workspace.load()

            with self.assertRaisesRegex(ValueError, "escapes workspace"):
                workspace.write_file("../escaped.txt", "outside")

            self.assertFalse((parent / "escaped.txt").exists())
            self.assertEqual(workspace.flush(), [])

    def test_backslash_parent_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-workspace-backslash-") as temp_dir:
            root = Path(temp_dir) / "workspace"
            root.mkdir()
            workspace = DecryptedWorkspace(root, "password")
            workspace.load()

            with self.assertRaisesRegex(ValueError, "escapes workspace"):
                workspace.write_file("..\\escaped.txt", "outside")

    def test_absolute_path_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-workspace-absolute-") as temp_dir:
            root = Path(temp_dir) / "workspace"
            root.mkdir()
            workspace = DecryptedWorkspace(root, "password")
            workspace.load()

            with self.assertRaisesRegex(ValueError, "must be relative"):
                workspace.write_file(str(Path(temp_dir) / "escaped.txt"), "outside")

    @unittest.skipIf(os.name == "nt", "symlink setup differs on Windows")
    def test_symlink_parent_escape_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-workspace-symlink-") as temp_dir:
            parent = Path(temp_dir)
            root = parent / "workspace"
            outside = parent / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "link").symlink_to(outside, target_is_directory=True)
            workspace = DecryptedWorkspace(root, "password")
            workspace.load()

            with self.assertRaisesRegex(ValueError, "escapes workspace"):
                workspace.write_file("link/escaped.txt", "outside")

            self.assertFalse((outside / "escaped.txt").exists())

    def test_json_rpc_reports_boundary_violation(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-workspace-rpc-") as temp_dir:
            root = Path(temp_dir) / "workspace"
            root.mkdir()
            workspace = DecryptedWorkspace(root, "password")
            workspace.load()

            response = workspace.handle_tool_call(
                "write_file",
                {"path": "../escaped.txt", "content": "outside"},
            )

            self.assertIn("escapes workspace", response["error"])

    def test_valid_nested_path_still_flushes_encrypted(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-workspace-valid-") as temp_dir:
            root = Path(temp_dir) / "workspace"
            root.mkdir()
            workspace = DecryptedWorkspace(root, "password")
            workspace.load()
            workspace.write_file("nested/secret.txt", "inside")

            with mock.patch.dict(sys.modules, {"ailatch.crypto": _fake_crypto_module()}):
                flushed = workspace.flush()

            target = root / "nested" / "secret.txt"
            self.assertEqual(flushed, ["nested/secret.txt"])
            self.assertTrue(target.exists())
            self.assertTrue(is_locked(target.read_bytes()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
