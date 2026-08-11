import subprocess
import sys
import unittest


class LegacyEntrypointTests(unittest.TestCase):
    def test_legacy_aloc_module_imports(self) -> None:
        import aloc

        self.assertTrue(callable(aloc.main))

    def test_legacy_aloc_module_runs_cli(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "aloc", "--help"],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("AILatch (formerly AiLock)", result.stdout)


if __name__ == "__main__":
    unittest.main()
