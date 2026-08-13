import contextlib
import io
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

from ailatch.format import MAGIC
from ailatch.runner import run_in_memory


class ExternalEncryptedImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="ailatch-external-import-")
        self.root = Path(self.tempdir.name)
        self.dependency_root = self.root / "dependency" / "src"
        self.consumer_root = self.root / "consumer"
        self.dependency_root.mkdir(parents=True)
        self.consumer_root.mkdir()
        self.package_name = "protected_" + uuid.uuid4().hex
        self.package_dir = self.dependency_root / self.package_name
        self.package_dir.mkdir()

    def tearDown(self) -> None:
        for name in list(sys.modules):
            if name == self.package_name or name.startswith(self.package_name + "."):
                sys.modules.pop(name, None)
        self.tempdir.cleanup()

    @staticmethod
    def _encrypt_for_test(source: str) -> bytes:
        return MAGIC + source.encode("utf-8")

    @staticmethod
    def _decrypt_for_test(blob: bytes) -> bytes:
        if not blob.startswith(MAGIC):
            raise ValueError("not a test AILatch blob")
        return blob[len(MAGIC):]

    def _run_external_consumer(self, source: str) -> tuple[int, str]:
        consumer = self.consumer_root / "main.py"
        consumer.write_text(source, encoding="utf-8")
        self.assertNotEqual(consumer.parent, self.dependency_root)

        sys.path.insert(0, str(self.dependency_root))
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                result = run_in_memory(
                    consumer,
                    decrypt_fn=self._decrypt_for_test,
                )
        finally:
            sys.path.remove(str(self.dependency_root))
        return result, output.getvalue()

    def test_external_consumer_imports_encrypted_submodule(self) -> None:
        (self.package_dir / "__init__.py").write_text(
            "from .secret import VALUE\n",
            encoding="utf-8",
        )
        (self.package_dir / "secret.py").write_bytes(
            self._encrypt_for_test("VALUE = 'SUBMODULE_OK'\n")
        )

        result, output = self._run_external_consumer(
            f"from {self.package_name} import VALUE\nprint(VALUE)\n"
        )

        self.assertEqual(result, 0)
        self.assertEqual(output.strip(), "SUBMODULE_OK")

    def test_external_consumer_imports_encrypted_package_init(self) -> None:
        (self.package_dir / "__init__.py").write_bytes(
            self._encrypt_for_test("VALUE = 'PACKAGE_OK'\n")
        )

        result, output = self._run_external_consumer(
            f"from {self.package_name} import VALUE\nprint(VALUE)\n"
        )

        self.assertEqual(result, 0)
        self.assertEqual(output.strip(), "PACKAGE_OK")

    def test_external_consumer_dynamic_imports_encrypted_module(self) -> None:
        module_name = "dynamic_" + uuid.uuid4().hex
        (self.dependency_root / f"{module_name}.py").write_bytes(
            self._encrypt_for_test("VALUE = 'DYNAMIC_OK'\n")
        )

        result, output = self._run_external_consumer(
            "import importlib\n"
            f"module = importlib.import_module('{module_name}')\n"
            "print(module.VALUE)\n"
        )

        sys.modules.pop(module_name, None)
        self.assertEqual(result, 0)
        self.assertEqual(output.strip(), "DYNAMIC_OK")


if __name__ == "__main__":
    unittest.main()
