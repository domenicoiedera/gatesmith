"""Tests for the optional gatesmith.yaml defaults loader.

Run from the repo root: ``python -m unittest -v tests.test_config``.
"""

import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from gatesmith import config  # noqa: E402

SAMPLE = """\
# shared defaults for the repo
review:
  registry: .gatesmith/review-registry.json
evidence:
  registry: .gatesmith/frozen-registry.json
  markers_file: .gatesmith/markers.txt   # inline comment
  report_path_regex: "(^|/)(docs|reports)/|\\\\.(md|rst)$"
lanes:
  registry: .gatesmith/lane-registry.json
  tags: [alpha, beta]
"""


class ConfigLoad(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="config-")
        self.path = os.path.join(self.work, "gatesmith.yaml")
        with open(self.path, "w") as fh:
            fh.write(SAMPLE)

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def test_sections_and_scalars(self):
        cfg = config.load(self.path)
        self.assertEqual(cfg["review"]["registry"], ".gatesmith/review-registry.json")
        self.assertEqual(cfg["lanes"]["registry"], ".gatesmith/lane-registry.json")

    def test_inline_comment_is_stripped(self):
        cfg = config.load(self.path)
        self.assertEqual(cfg["evidence"]["markers_file"], ".gatesmith/markers.txt")

    def test_quoted_value_keeps_hash_and_parens(self):
        cfg = config.load(self.path)
        self.assertIn("docs", cfg["evidence"]["report_path_regex"])

    def test_inline_list(self):
        cfg = config.load(self.path)
        self.assertEqual(cfg["lanes"]["tags"], ["alpha", "beta"])

    def test_missing_file_is_empty(self):
        self.assertEqual(config.load(os.path.join(self.work, "nope.yaml")), {})

    def test_cli_value_wins_over_config(self):
        class Args:
            registry = "explicit.json"

        args = Args()
        args._config = config.load(self.path)
        self.assertEqual(config.get(args, "review", "registry", "default.json"), "explicit.json")

    def test_config_value_used_when_flag_absent(self):
        class Args:
            registry = None

        args = Args()
        args._config = config.load(self.path)
        self.assertEqual(config.get(args, "review", "registry", "default.json"),
                         ".gatesmith/review-registry.json")

    def test_fallback_when_nothing_set(self):
        class Args:
            registry = None

        args = Args()
        args._config = {}
        self.assertEqual(config.get(args, "review", "registry", "default.json"), "default.json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
