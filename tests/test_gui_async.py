from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from ailatch.gui import AILatchEditor


class _QueuedRoot:
    def __init__(self):
        self.callbacks = []

    def after(self, delay, callback, *args):
        self.callbacks.append((callback, args))

    def run_all(self):
        while self.callbacks:
            callback, args = self.callbacks.pop(0)
            callback(*args)


def _fake_cli(plaintext: bytes = b"PLAINTEXT_A", error: Exception | None = None):
    module = types.ModuleType("ailatch.cli")

    def decrypt(blob, password):
        if error is not None:
            raise error
        return plaintext

    module._decrypt_with_password = decrypt
    return module


class GUIAsyncSelectionTests(unittest.TestCase):
    def _editor(self, current_file: Path, generation: int):
        editor = AILatchEditor.__new__(AILatchEditor)
        editor.root = _QueuedRoot()
        editor.password = "password"
        editor.current_file = current_file
        editor._load_generation = generation
        return editor

    def test_stale_success_from_previous_file_is_ignored(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-gui-race-") as temp_dir:
            root = Path(temp_dir)
            file_a = root / "a.txt"
            file_b = root / "b.txt"
            editor = self._editor(file_a, 1)
            applied = []
            editor._display_content = applied.append
            editor._set_status = lambda value: None

            with mock.patch.dict(sys.modules, {"ailatch.cli": _fake_cli()}):
                editor._decrypt_async(file_a, b"cipher-a", 1)

            editor.current_file = file_b
            editor._load_generation = 2
            editor.root.run_all()
            self.assertEqual(applied, [])

    def test_old_generation_is_ignored_after_selecting_same_path_again(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-gui-generation-") as temp_dir:
            file_a = Path(temp_dir) / "a.txt"
            editor = self._editor(file_a, 1)
            applied = []
            editor._display_content = applied.append
            editor._set_status = lambda value: None

            with mock.patch.dict(sys.modules, {"ailatch.cli": _fake_cli()}):
                editor._decrypt_async(file_a, b"old-cipher-a", 1)

            editor._load_generation = 3
            editor.root.run_all()
            self.assertEqual(applied, [])

    def test_current_success_is_applied(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-gui-current-") as temp_dir:
            file_a = Path(temp_dir) / "a.txt"
            editor = self._editor(file_a, 4)
            applied = []
            statuses = []
            editor._display_content = applied.append
            editor._set_status = statuses.append

            with mock.patch.dict(
                sys.modules,
                {"ailatch.cli": _fake_cli(plaintext=b"CURRENT")},
            ):
                editor._decrypt_async(file_a, b"cipher-a", 4)

            editor.root.run_all()
            self.assertEqual(applied, ["CURRENT"])
            self.assertEqual(len(statuses), 1)

    def test_stale_error_is_ignored(self):
        with tempfile.TemporaryDirectory(prefix="ailatch-gui-error-") as temp_dir:
            root = Path(temp_dir)
            file_a = root / "a.txt"
            file_b = root / "b.txt"
            editor = self._editor(file_a, 1)
            errors = []
            editor._display_error = errors.append

            with mock.patch.dict(
                sys.modules,
                {"ailatch.cli": _fake_cli(error=ValueError("bad password"))},
            ):
                editor._decrypt_async(file_a, b"cipher-a", 1)

            editor.current_file = file_b
            editor._load_generation = 2
            editor.root.run_all()
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
