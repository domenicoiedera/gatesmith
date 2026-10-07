"""Tests for the frozen-paths guard.

Run from the repo root: ``python -m unittest -v tests.test_frozen``.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from gatesmith.frozen import blocked_files, load_items, match  # noqa: E402


class FrozenMatch(unittest.TestCase):
    def test_directory_prefix_matches_children(self):
        self.assertTrue(match(["src/payments"], "src/payments/capture.py"))

    def test_exact_file_matches(self):
        self.assertTrue(match(["src/tax.ts"], "src/tax.ts"))

    def test_non_prefix_sibling_does_not_match(self):
        self.assertFalse(match(["src/tax.ts"], "src/tax2.ts"))

    def test_trailing_slash_glob_matches_directory(self):
        self.assertTrue(match(["src/hooks/"], "src/hooks/useChat.ts"))

    def test_unrelated_path_does_not_match(self):
        self.assertFalse(match(["src/payments"], "docs/readme.md"))

    def test_blocked_files_reports_item_identity(self):
        items = [{"id": "F1", "area": "payments", "owned_files": ["src/payments"]}]
        hits = blocked_files(items, ["src/payments/x.py", "docs/a.md"])
        self.assertEqual(hits, [("src/payments/x.py", "F1", "payments")])


class FrozenCli(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="frozen-")
        self.registry = os.path.join(self.work, "registry.json")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def run_(self, *paths):
        env = dict(os.environ)
        env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run(
            [sys.executable, "-m", "gatesmith", "frozen", "--registry", self.registry,
             "check", *paths],
            capture_output=True, text=True, env=env, timeout=30)

    def _write(self, payload):
        with open(self.registry, "w") as fh:
            fh.write(payload)

    def test_frozen_path_blocks(self):
        self._write('{"items": [{"id": "F1", "area": "payments", "owned_files": ["src/payments"]}]}')
        result = self.run_("src/payments/x.py")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FROZEN-BLOCKED", result.stdout)

    def test_clear_path_exits_zero(self):
        self._write('{"items": [{"id": "F1", "area": "payments", "owned_files": ["src/payments"]}]}')
        result = self.run_("docs/readme.md")
        self.assertEqual(result.returncode, 0)
        self.assertIn("CLEAR", result.stdout)

    def test_unreadable_registry_is_a_hard_error(self):
        # A registry that exists but is broken must not read as "clear".
        self._write("{not json")
        result = self.run_("src/payments/x.py")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unreadable registry", result.stderr)

    def test_load_items_absent_is_empty(self):
        self.assertEqual(load_items(os.path.join(self.work, "nope.json")), [])

    def test_wrong_type_root_is_a_hard_error(self):
        # Valid JSON, but not an object: must not read as an empty, clear result.
        self._write("[1, 2, 3]")
        result = self.run_("src/payments/x.py")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unreadable registry", result.stderr)

    def test_items_not_a_list_is_a_hard_error(self):
        # Valid JSON object, but 'items' is not a list: same fail-closed path.
        self._write('{"items": "oops"}')
        result = self.run_("src/payments/x.py")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unreadable registry", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
