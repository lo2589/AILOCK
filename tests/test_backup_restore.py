from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aloc.manifest import _encode_backup_name, create_backup


def _fake_crypto_module() -> types.ModuleType:
    module = types.ModuleType("aloc.crypto")
    module.derive_project_key = lambda password, salt: b"p" * 32
    module.encrypt_payload = lambda key, data, metadata: (b"1" * 12, b"v1")
    module.decrypt_payload = lambda key, header, ciphertext: b"plain"
    module.generate_file_key = lambda: b"f" * 32
    module.wrap_key = lambda key, file_key: (b"2" * 12, b"wrapped")
    module.unwrap_key = lambda key, nonce, wrapped: b"f" * 32
    module.encrypt_payload_v2 = lambda key, data, metadata: (b"3" * 12, b"cipher")
    module.decrypt_payload_v2 = lambda key, nonce, ciphertext: b"RESTORED CONTENT"
    return module


def _write_fallback_backup(root: Path, backup_name: str) -> None:
    backup_dir = root / ".ailock" / "backups"
    backup_dir.mkdir(parents=True)
    meta = {
        "salt": "c2FsdHNhbHRzYWx0c2FsdA==",
        "nonce": "bm5ubm5ubm5ubm5u",
        "pw_nonce": "cHdub25jZTEyMw==",
        "pw_wrapped": "d3JhcHBlZA==",
    }
    with zipfile.ZipFile(backup_dir / backup_name, "w") as archive:
        archive.writestr("secret.txt.meta", json.dumps(meta).encode("utf-8"))
        archive.writestr("secret.txt.enc", b"ciphertext")


class BackupRestoreTests(unittest.TestCase):
    def test_distinct_paths_have_distinct_backup_names(self):
        self.assertNotEqual(
            _encode_backup_name("a/b.txt"),
            _encode_backup_name("a_b.txt"),
        )

    def test_repeated_backup_creation_never_reuses_existing_name(self):
        with tempfile.TemporaryDirectory(prefix="ailock-backup-name-") as temp_dir:
            root = Path(temp_dir)
            fake_crypto = _fake_crypto_module()
            with (
                mock.patch("aloc.manifest.get_project_root", return_value=root),
                mock.patch.dict(
                    sys.modules,
                    {"aloc.crypto": fake_crypto, "pyzipper": None},
                ),
                mock.patch("aloc.manifest.time.time_ns", return_value=123456),
            ):
                first = create_backup("src/secret.txt", b"one", "password")
                second = create_backup("src/secret.txt", b"two", "password")
                third = create_backup("src/secret.txt", b"three", "password")

            self.assertEqual(len({first, second, third}), 3)
            for name in (first, second, third):
                self.assertTrue((root / ".ailock" / "backups" / name).exists())

    def test_cli_restore_recovers_a_missing_file_and_clears_manifest(self):
        with tempfile.TemporaryDirectory(prefix="ailock-cli-restore-") as temp_dir:
            root = Path(temp_dir)
            target = root / "secret.txt"
            backup_name = "secret-backup.zip"
            _write_fallback_backup(root, backup_name)
            manifest_path = root / ".ailock" / "manifest.json"
            manifest_path.write_text(
                json.dumps({
                    "files": {
                        "secret.txt": {
                            "filename": "secret.txt",
                            "original_hash": "original",
                            "locked_hash": "locked",
                            "locked_at": 1,
                            "backup": f"backups/{backup_name}",
                        }
                    }
                }),
                encoding="utf-8",
            )

            fake_crypto = _fake_crypto_module()
            sys.modules.pop("aloc.cli", None)
            sys.modules.pop("aloc.recovery", None)
            try:
                with mock.patch.dict(sys.modules, {"aloc.crypto": fake_crypto}):
                    from aloc import cli

                    parsed = cli.parse_args(["restore", str(target)])
                    self.assertEqual(parsed.cmd, "restore")

                    with (
                        mock.patch(
                            "aloc.manifest.get_project_root",
                            return_value=root,
                        ),
                        mock.patch.object(cli, "prompt_password", return_value="password"),
                        mock.patch.dict(sys.modules, {"pyzipper": None}),
                    ):
                        result = cli.cmd_restore(
                            SimpleNamespace(path=str(target), backup=False)
                        )
            finally:
                sys.modules.pop("aloc.cli", None)
                sys.modules.pop("aloc.recovery", None)

            self.assertEqual(result, 0)
            self.assertEqual(target.read_bytes(), b"RESTORED CONTENT")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertNotIn("secret.txt", manifest["files"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
