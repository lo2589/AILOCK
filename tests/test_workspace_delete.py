from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aloc.workspace import DecryptedWorkspace


class WorkspaceDeleteTests(unittest.TestCase):
    def test_flush_deletes_file_without_mutating_iteration_error(self):
        with tempfile.TemporaryDirectory(prefix="ailock-delete-one-") as temp_dir:
            root = Path(temp_dir)
            target = root / "delete.txt"
            keep = root / "keep.txt"
            target.write_text("delete", encoding="utf-8")
            keep.write_text("keep", encoding="utf-8")
            workspace = DecryptedWorkspace(root, "password")
            workspace.load()
            workspace.delete_file("delete.txt")

            flushed = workspace.flush()

            self.assertEqual(flushed, ["delete.txt"])
            self.assertFalse(target.exists())
            self.assertTrue(keep.exists())
            self.assertNotIn("delete.txt", workspace._files)

    def test_flush_can_delete_multiple_files(self):
        with tempfile.TemporaryDirectory(prefix="ailock-delete-many-") as temp_dir:
            root = Path(temp_dir)
            for name in ("a.txt", "b.txt", "c.txt"):
                (root / name).write_text(name, encoding="utf-8")
            workspace = DecryptedWorkspace(root, "password")
            workspace.load()
            workspace.delete_file("a.txt")
            workspace.delete_file("c.txt")

            flushed = workspace.flush()

            self.assertEqual(flushed, ["a.txt", "c.txt"])
            self.assertEqual(workspace.list_files(), ["b.txt"])

    def test_close_flushes_pending_deletion(self):
        with tempfile.TemporaryDirectory(prefix="ailock-delete-close-") as temp_dir:
            root = Path(temp_dir)
            target = root / "delete.txt"
            target.write_text("delete", encoding="utf-8")
            workspace = DecryptedWorkspace(root, "password")
            workspace.load()
            workspace.delete_file("delete.txt")

            workspace.close()

            self.assertFalse(target.exists())
            self.assertFalse(workspace._loaded)


if __name__ == "__main__":
    unittest.main(verbosity=2)
