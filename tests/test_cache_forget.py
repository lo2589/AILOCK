from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from aloc.cache import (
    cache_forget,
    cache_get_password,
    cache_get_project_key,
    cache_store_password,
    cache_store_project_key,
)


class CacheForgetTests(unittest.TestCase):
    def test_forget_project_removes_key_and_plaintext_password(self):
        with tempfile.TemporaryDirectory(prefix="ailock-cache-forget-") as temp_dir:
            with mock.patch.dict(os.environ, {"TMPDIR": temp_dir}):
                project = "project-a"
                cache_store_project_key(project, b"k" * 32)
                cache_store_password(project, "secret-password")

                cache_forget(project)

                self.assertIsNone(cache_get_project_key(project))
                self.assertIsNone(cache_get_password(project))

    def test_forget_project_does_not_remove_another_project(self):
        with tempfile.TemporaryDirectory(prefix="ailock-cache-isolation-") as temp_dir:
            with mock.patch.dict(os.environ, {"TMPDIR": temp_dir}):
                cache_store_project_key("project-a", b"a" * 32)
                cache_store_password("project-a", "password-a")
                cache_store_project_key("project-b", b"b" * 32)
                cache_store_password("project-b", "password-b")

                cache_forget("project-a")

                self.assertEqual(cache_get_project_key("project-b"), b"b" * 32)
                self.assertEqual(cache_get_password("project-b"), "password-b")

    def test_forget_all_removes_every_cache_file(self):
        with tempfile.TemporaryDirectory(prefix="ailock-cache-all-") as temp_dir:
            with mock.patch.dict(os.environ, {"TMPDIR": temp_dir}):
                for project in ("project-a", "project-b"):
                    cache_store_project_key(project, b"k" * 32)
                    cache_store_password(project, f"password-{project}")

                cache_forget(None)

                for project in ("project-a", "project-b"):
                    self.assertIsNone(cache_get_project_key(project))
                    self.assertIsNone(cache_get_password(project))


if __name__ == "__main__":
    unittest.main(verbosity=2)
