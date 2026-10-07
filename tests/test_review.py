"""End-to-end tests for the two-agent review gate.

Runs the ``gatesmith review`` CLI against a throwaway registry. No network.
Run from the repo root: ``python -m unittest -v tests.test_review``.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHA1 = "a" * 64
SHA2 = "b" * 64


def sh(*args, **kw):
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(args, capture_output=True, text=True, env=env,
                          timeout=kw.pop("timeout", 30), **kw)


class ReviewGateTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="revgate-")
        self.reg = os.path.join(self.work, "reg.json")
        self.g = lambda *a: [sys.executable, "-m", "gatesmith", "review", "--registry", self.reg, *a]

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def run_(self, *a):
        return sh(*self.g(*a))

    # ── standing behaviour ──────────────────────────────────────────────────

    def test_open_records_review(self):
        r = self.run_("open", "--id", "r1", "--executor", "backend", "--change", "x", "--owned", "a.ts")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.reg) as f:
            reg = json.load(f)
        self.assertEqual(reg["reviews"][0]["executor"], "backend")
        self.assertEqual(reg["reviews"][0]["status"], "open")

    def test_open_defaults_to_tier_c(self):
        self.run_("open", "--id", "r1", "--executor", "backend", "--change", "x")
        with open(self.reg) as f:
            reg = json.load(f)
        self.assertEqual(reg["reviews"][0]["tier"], "C")

    def test_self_review_is_rejected(self):
        self.run_("open", "--id", "r1", "--executor", "backend", "--change", "x")
        r = self.run_("sign", "--id", "r1", "--reviewer", "backend", "--verdict", "pass")
        self.assertEqual(r.returncode, 1)
        self.assertIn("SELF-REVIEW", r.stderr)

    def test_no_signoff_gate_blocks(self):
        self.run_("open", "--id", "r1", "--executor", "backend", "--change", "x")
        r = self.run_("gate", "--id", "r1", "--target", "deploy", "--executor", "backend")
        self.assertEqual(r.returncode, 1)
        self.assertIn("GATE-BLOCKED", r.stderr)

    def test_block_verdict_gate_blocks(self):
        self.run_("open", "--id", "r1", "--executor", "backend", "--change", "x")
        self.run_("sign", "--id", "r1", "--reviewer", "reviewer1", "--verdict", "block")
        r = self.run_("gate", "--id", "r1", "--target", "deploy", "--executor", "backend")
        self.assertEqual(r.returncode, 1)

    def test_independent_pass_opens_gate(self):
        self.run_("open", "--id", "r1", "--executor", "backend", "--change", "x")
        self.run_("sign", "--id", "r1", "--reviewer", "reviewer1", "--verdict", "pass")
        # D1: the seal is required by default; this fixture is unsealed, so it
        # must opt out explicitly — and the opt-out is loud.
        r = self.run_("gate", "--id", "r1", "--target", "deploy", "--executor", "backend",
                      "--allow-unsealed")
        self.assertEqual(r.returncode, 0)
        self.assertIn("GATE-OPEN", r.stdout)
        self.assertIn("the seal was NOT enforced", r.stderr)

    def test_gate_rejects_wrong_executor_caller(self):
        self.run_("open", "--id", "r1", "--executor", "backend", "--change", "x")
        self.run_("sign", "--id", "r1", "--reviewer", "reviewer1", "--verdict", "pass")
        r = self.run_("gate", "--id", "r1", "--target", "push", "--executor", "frontend")
        self.assertEqual(r.returncode, 1)
        self.assertIn("GATE-BLOCKED", r.stderr)

    def test_gate_blocks_missing_review(self):
        r = self.run_("gate", "--id", "nope", "--target", "migrate", "--executor", "backend")
        self.assertEqual(r.returncode, 1)
        self.assertIn("GATE-BLOCKED", r.stderr)

    def test_list_shows_open_blocked(self):
        self.run_("open", "--id", "r1", "--executor", "backend", "--change", "x")
        out = self.run_("list").stdout
        self.assertIn("r1", out)

    def test_empty_registry_file_is_tolerated(self):
        # Regression: an existing-but-empty registry must not crash the gate.
        open(self.reg, "w").close()
        r = self.run_("open", "--id", "r1", "--executor", "backend", "--change", "x")
        self.assertEqual(r.returncode, 0)
        r2 = self.run_("gate", "--id", "r1", "--target", "deploy", "--executor", "backend")
        self.assertEqual(r2.returncode, 1)  # still fail-closed (no signoff)

    # ── risk tiers ──────────────────────────────────────────────────────────

    def test_tier_recorded_on_open(self):
        self.run_("open", "--id", "rA", "--executor", "backend", "--change", "docs",
                  "--tier", "A", "--diff-sha", SHA1)
        self.run_("open", "--id", "rB", "--executor", "backend", "--change", "code", "--tier", "B")
        with open(self.reg) as f:
            reg = json.load(f)
        tiers = {r["id"]: r.get("tier") for r in reg["reviews"]}
        self.assertEqual(tiers["rA"], "A")
        self.assertEqual(tiers["rB"], "B")

    def test_auto_sign_requires_tier_a(self):
        self.run_("open", "--id", "rc", "--executor", "backend", "--change", "x",
                  "--tier", "C", "--diff-sha", SHA1)
        r = self.run_("sign", "--id", "rc", "--reviewer", "rev1", "--verdict", "pass", "--auto")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not A", r.stderr)

    def test_auto_sign_requires_prior_independent_pass(self):
        self.run_("open", "--id", "rA1", "--executor", "backend", "--change", "docs",
                  "--tier", "A", "--diff-sha", SHA1)
        r = self.run_("sign", "--id", "rA1", "--reviewer", "rev1", "--verdict", "pass", "--auto")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no prior independently-passed", r.stderr)

    def test_auto_sign_works_after_prior_human_pass(self):
        self.run_("open", "--id", "rA1", "--executor", "backend", "--change", "docs",
                  "--tier", "A", "--diff-sha", SHA1)
        self.run_("sign", "--id", "rA1", "--reviewer", "rev1", "--verdict", "pass",
                  "--note", "full evidence")
        self.run_("open", "--id", "rA2", "--executor", "frontend", "--change", "same docs",
                  "--tier", "A", "--diff-sha", SHA1)
        r = self.run_("sign", "--id", "rA2", "--reviewer", "rev2", "--verdict", "pass", "--auto")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("byte-identical", r.stdout)
        gate = self.run_("gate", "--id", "rA2", "--target", "push", "--executor", "frontend",
                         "--allow-unsealed")   # D1: unsealed fixture opts out explicitly
        self.assertEqual(gate.returncode, 0)
        self.assertIn("GATE-OPEN", gate.stdout)

    def test_auto_sign_refused_when_prior_reviewer_is_executor(self):
        self.run_("open", "--id", "rA1", "--executor", "backend", "--change", "docs",
                  "--tier", "A", "--diff-sha", SHA1)
        self.run_("sign", "--id", "rA1", "--reviewer", "rev1", "--verdict", "pass")
        self.run_("open", "--id", "rA2", "--executor", "rev1", "--change", "same docs",
                  "--tier", "A", "--diff-sha", SHA1)
        r = self.run_("sign", "--id", "rA2", "--reviewer", "rev2", "--verdict", "pass", "--auto")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no prior independently-passed", r.stderr)

    def test_auto_sign_refused_when_prior_was_blocked(self):
        self.run_("open", "--id", "rA1", "--executor", "backend", "--change", "docs",
                  "--tier", "A", "--diff-sha", SHA1)
        self.run_("sign", "--id", "rA1", "--reviewer", "rev1", "--verdict", "block")
        self.run_("open", "--id", "rA2", "--executor", "frontend", "--change", "same docs",
                  "--tier", "A", "--diff-sha", SHA1)
        r = self.run_("sign", "--id", "rA2", "--reviewer", "rev2", "--verdict", "pass", "--auto")
        self.assertEqual(r.returncode, 1)

    def test_closed_review_never_gates(self):
        self.run_("open", "--id", "r1", "--executor", "backend", "--change", "x")
        self.run_("sign", "--id", "r1", "--reviewer", "rev1", "--verdict", "pass")
        r = self.run_("close", "--id", "r1", "--note", "superseded by r2")
        self.assertEqual(r.returncode, 0)
        g = self.run_("gate", "--id", "r1", "--target", "deploy", "--executor", "backend")
        self.assertEqual(g.returncode, 1)
        self.assertIn("CLOSED", g.stderr)
        self.assertNotIn("r1:", self.run_("list").stdout)
        self.assertIn("r1:", self.run_("list", "--all").stdout)

    def test_lookup_finds_and_misses(self):
        self.run_("open", "--id", "rA", "--executor", "backend", "--change", "x",
                  "--tier", "A", "--diff-sha", SHA1)
        # D5/G12: `lookup` is informational — 0 when it can report, 2 when the
        # registry is unreadable or unparseable. It makes no gate decision.
        found = self.run_("lookup", "--diff-sha", SHA1)
        self.assertEqual(found.returncode, 0)
        self.assertIn("rA", found.stdout)
        miss = self.run_("lookup", "--diff-sha", SHA2)
        self.assertEqual(miss.returncode, 0)
        self.assertIn("no gates with diff_sha", miss.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
