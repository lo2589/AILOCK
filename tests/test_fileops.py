from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from ailatch.fileops import atomic_write


@unittest.skipIf(os.name == "nt", "POSIX permission bits are not portable to Windows")
class AtomicWritePermissionTests(unittest.TestCase):
    def test_atomic_write_preserves_executable_mode(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-mode-exec-") as temp_dir:
            target = Path(temp_dir) / "tool.py"
            target.write_bytes(b"old")
            target.chmod(0o755)

            atomic_write(target, b"new")

            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
            self.assertEqual(target.read_bytes(), b"new")

    def test_atomic_write_preserves_private_mode(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-mode-private-") as temp_dir:
            target = Path(temp_dir) / "secret.txt"
            target.write_bytes(b"old")
            target.chmod(0o600)

            atomic_write(target, b"new")

            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_atomic_write_creates_new_file(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-mode-new-") as temp_dir:
            target = Path(temp_dir) / "new.txt"

            atomic_write(target, b"new")

            self.assertEqual(target.read_bytes(), b"new")


if __name__ == "__main__":
    unittest.main(verbosity=2)
