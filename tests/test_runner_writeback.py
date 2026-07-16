from __future__ import annotations

import io
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from aloc.format import MAGIC, encode_file, is_locked, parse_locked_file
from aloc.runner import AilockIOPatch, run_in_memory


def _locked_blob(label: bytes = b"ciphertext") -> bytes:
    return MAGIC + b"\x02\x00" + b"0" * 8 + label


class EncryptedWritebackTests(unittest.TestCase):
    def _patch(self, root: Path, plaintext: bytes = b"original"):
        commits = []

        def encrypt_fn(original_blob, edited_plaintext, path):
            commits.append((original_blob, edited_plaintext, path))
            return _locked_blob(b"updated-" + edited_plaintext)

        patch = AilockIOPatch(
            [root],
            decrypt_fn=lambda blob: plaintext,
            encrypt_fn=encrypt_fn,
        )
        return patch, commits

    def test_text_write_is_reencrypted_on_close(self):
        with tempfile.TemporaryDirectory(prefix="ailock-writeback-") as temp_dir:
            root = Path(temp_dir)
            target = root / "secret.txt"
            original_blob = _locked_blob()
            target.write_bytes(original_blob)
            patch, commits = self._patch(root)

            patch.install()
            try:
                with open(target, "w", encoding="utf-8") as stream:
                    stream.write("edited")
            finally:
                patch.uninstall()

            self.assertTrue(is_locked(target.read_bytes()))
            self.assertNotEqual(target.read_bytes(), b"edited")
            self.assertEqual(commits, [(original_blob, b"edited", target.resolve())])

    def test_rplus_persists_the_modified_plaintext(self):
        with tempfile.TemporaryDirectory(prefix="ailock-rplus-") as temp_dir:
            root = Path(temp_dir)
            target = root / "secret.txt"
            target.write_bytes(_locked_blob())
            patch, commits = self._patch(root, plaintext=b"abcdef")

            patch.install()
            try:
                with open(target, "r+", encoding="utf-8") as stream:
                    stream.seek(0)
                    stream.write("XY")
            finally:
                patch.uninstall()

            self.assertEqual(commits[-1][1], b"XYcdef")
            self.assertTrue(is_locked(target.read_bytes()))

    def test_append_writes_at_end_even_after_seek(self):
        with tempfile.TemporaryDirectory(prefix="ailock-append-") as temp_dir:
            root = Path(temp_dir)
            target = root / "secret.txt"
            target.write_bytes(_locked_blob())
            patch, commits = self._patch(root, plaintext=b"before")

            patch.install()
            try:
                with open(target, "a+", encoding="utf-8") as stream:
                    stream.seek(0)
                    stream.write("-after")
            finally:
                patch.uninstall()

            self.assertEqual(commits[-1][1], b"before-after")

    def test_path_write_text_uses_encrypted_writeback(self):
        with tempfile.TemporaryDirectory(prefix="ailock-pathlib-") as temp_dir:
            root = Path(temp_dir)
            target = root / "secret.txt"
            target.write_bytes(_locked_blob())
            patch, commits = self._patch(root)

            patch.install()
            try:
                written = target.write_text("pathlib edit", encoding="utf-8")
            finally:
                patch.uninstall()

            self.assertEqual(written, len("pathlib edit"))
            self.assertEqual(commits[-1][1], b"pathlib edit")
            self.assertTrue(is_locked(target.read_bytes()))

    def test_io_open_uses_encrypted_writeback(self):
        with tempfile.TemporaryDirectory(prefix="ailock-io-open-") as temp_dir:
            root = Path(temp_dir)
            target = root / "secret.bin"
            target.write_bytes(_locked_blob())
            patch, commits = self._patch(root)

            patch.install()
            try:
                with io.open(target, "wb") as stream:
                    stream.write(b"binary edit")
            finally:
                patch.uninstall()

            self.assertEqual(commits[-1][1], b"binary edit")
            self.assertTrue(is_locked(target.read_bytes()))

    def test_write_is_blocked_when_reencryption_is_unavailable(self):
        with tempfile.TemporaryDirectory(prefix="ailock-block-write-") as temp_dir:
            root = Path(temp_dir)
            target = root / "secret.txt"
            original_blob = _locked_blob()
            target.write_bytes(original_blob)
            patch = AilockIOPatch([root], decrypt_fn=lambda blob: b"original")

            patch.install()
            try:
                with self.assertRaises(PermissionError):
                    open(target, "w", encoding="utf-8")
            finally:
                patch.uninstall()

            self.assertEqual(target.read_bytes(), original_blob)

    def test_v2_reencryption_preserves_recovery_wrap(self):
        fake_crypto = types.ModuleType("aloc.crypto")
        fake_crypto.derive_project_key = lambda password, salt: b"p" * 32
        fake_crypto.encrypt_payload = lambda key, data, metadata: (b"1" * 12, b"v1")
        fake_crypto.decrypt_payload = lambda key, header, ciphertext: b"plain"
        fake_crypto.generate_file_key = lambda: b"f" * 32
        fake_crypto.wrap_key = lambda key, file_key: (b"2" * 12, b"wrapped")
        fake_crypto.unwrap_key = lambda key, nonce, wrapped: b"f" * 32
        fake_crypto.encrypt_payload_v2 = lambda key, data, metadata: (b"3" * 12, b"v2")
        fake_crypto.decrypt_payload_v2 = lambda key, nonce, ciphertext: b"plain"

        header = {
            "salt": "c2FsdHNhbHRzYWx0c2FsdA==",
            "nonce": "bm5ubm5ubm5ubm5u",
            "key_wraps": [
                {"type": "password", "nonce": "cHc=", "wrapped": "a2V5"},
                {"type": "recovery", "nonce": "cmVj", "wrapped": "a2V5"},
            ],
        }
        original = encode_file(header, b"old-ciphertext")

        sys.modules.pop("aloc.cli", None)
        sys.modules.pop("aloc.recovery", None)
        try:
            with mock.patch.dict(sys.modules, {"aloc.crypto": fake_crypto}):
                from aloc.cli import _reencrypt_with_password

                updated = _reencrypt_with_password(
                    original,
                    b"edited",
                    "password",
                    Path("secret.txt"),
                )
        finally:
            sys.modules.pop("aloc.cli", None)
            sys.modules.pop("aloc.recovery", None)

        updated_header, _ = parse_locked_file(updated)
        self.assertEqual(updated_header["key_wraps"], header["key_wraps"])

    def test_run_in_memory_wires_encrypted_writeback(self):
        with tempfile.TemporaryDirectory(prefix="ailock-run-writeback-") as temp_dir:
            root = Path(temp_dir)
            entry = root / "main.py"
            target = root / "secret.txt"
            entry.write_text(
                "with open('secret.txt', 'w', encoding='utf-8') as stream:\n"
                "    stream.write('changed by program')\n",
                encoding="utf-8",
            )
            target.write_bytes(_locked_blob())
            commits = []

            def encrypt_fn(original_blob, plaintext, path):
                commits.append((plaintext, path))
                return _locked_blob(b"runtime-" + plaintext)

            result = run_in_memory(
                entry,
                decrypt_fn=lambda blob: b"original",
                encrypt_fn=encrypt_fn,
            )

            self.assertEqual(result, 0)
            self.assertEqual(commits, [(b"changed by program", target.resolve())])
            self.assertTrue(is_locked(target.read_bytes()))

    def test_invalid_encrypted_result_never_replaces_original(self):
        with tempfile.TemporaryDirectory(prefix="ailock-invalid-encrypt-") as temp_dir:
            root = Path(temp_dir)
            target = root / "secret.txt"
            original_blob = _locked_blob()
            target.write_bytes(original_blob)
            patch = AilockIOPatch(
                [root],
                decrypt_fn=lambda blob: b"original",
                encrypt_fn=lambda blob, plaintext, path: b"plaintext by mistake",
            )

            patch.install()
            try:
                with self.assertRaises(ValueError):
                    with open(target, "w", encoding="utf-8") as stream:
                        stream.write("edited")
            finally:
                patch.uninstall()

            self.assertEqual(target.read_bytes(), original_blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
