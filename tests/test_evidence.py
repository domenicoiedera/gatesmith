"""Tests for the evidence check — the check-5 input classification.

Check 5 ("auto-advance markers") once grepped the WHOLE raw diff, so added prose
in a report that quotes the rule ("nothing auto-advances without a human") raised
a warning. A warning is meant to say "look here"; one that fires on the
vocabulary of every report trains the reviewer to ignore the one that matters.

Both directions are asserted, because a classifier that simply stopped firing
would pass the false-positive case and be worse than the bug:

  * report/prose text                     -> no marker
  * not-added lines (removals, context,
    diff headers)                         -> no marker
  * added code/config line                -> marker   (the positive control)
  * the pattern itself is unchanged       -> still matches

Run from the repo root: ``python -m unittest -v tests.test_evidence``.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from gatesmith.evidence import AUTOADV, hitl_hits  # noqa: E402

REPORT_PROSE = """diff --git a/reports/plans/x-build-report.md b/reports/plans/x-build-report.md
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/reports/plans/x-build-report.md
@@ -0,0 +1,3 @@
+# BUILD REPORT
+Nothing auto-advances past `drafted`; the agent drafts and a human approves.
+The reviewer must never skip review, and no gate auto-approves a ship.
"""

DOCS_PROSE = """diff --git a/docs/agents.md b/docs/agents.md
index 1111111..2222222 100644
--- a/docs/agents.md
+++ b/docs/agents.md
@@ -1 +1,2 @@
+# agents
+Nothing auto-advances past drafted — no auto-approve path exists.
"""

ADDED_CODE = """diff --git a/backend/services/gate.py b/backend/services/gate.py
index 1111111..2222222 100644
--- a/backend/services/gate.py
+++ b/backend/services/gate.py
@@ -10,6 +10,7 @@ def decide(job):
     if job.stage == "drafted":
+        AUTO_APPROVE = True  # auto-approve past drafted
         return "approved"
"""

REMOVED_ONLY = """diff --git a/backend/services/gate.py b/backend/services/gate.py
index 1111111..2222222 100644
--- a/backend/services/gate.py
+++ b/backend/services/gate.py
@@ -10,7 +10,6 @@ def decide(job):
-        AUTO_APPROVE = True  # auto-approve past drafted
         return "approved"
"""

CONTEXT_AND_HEADER = """diff --git a/auto-advance-notes/skip-review.md b/auto-advance-notes/skip-review.md
index 1111111..2222222 100644
--- a/auto-advance-notes/skip-review.md
+++ b/backend/services/gate.py
@@ -1,2 +1,1 @@ def f():
 context: never skip review, the runner must not auto-advance
 unchanged line mentioning auto-approve
"""

CONFIG_ADDED = """diff --git a/backend/config/gates.yaml b/backend/config/gates.yaml
index 1111111..2222222 100644
--- a/backend/config/gates.yaml
+++ b/backend/config/gates.yaml
@@ -1,2 +1,3 @@
 hitl: true
+auto_approve_drafted: true   # skip review for trusted agents
"""


class HitlClassification(unittest.TestCase):
    def test_report_prose_is_not_a_marker(self):
        self.assertEqual(hitl_hits(REPORT_PROSE), [])

    def test_docs_prose_is_not_a_marker(self):
        self.assertEqual(hitl_hits(DOCS_PROSE), [])

    def test_removed_line_is_not_a_marker(self):
        self.assertEqual(hitl_hits(REMOVED_ONLY), [])

    def test_context_and_header_text_is_not_a_marker(self):
        self.assertEqual(hitl_hits(CONTEXT_AND_HEADER), [])

    def test_added_code_line_is_a_marker(self):
        hits = hitl_hits(ADDED_CODE)
        self.assertEqual(len(hits), 1, hits)
        path, text = hits[0]
        self.assertEqual(path, "backend/services/gate.py")
        self.assertIn("AUTO_APPROVE", text)

    def test_added_config_line_is_a_marker(self):
        hits = hitl_hits(CONFIG_ADDED)
        self.assertEqual(len(hits), 1, hits)
        self.assertEqual(hits[0][0], "backend/config/gates.yaml")

    def test_the_pattern_itself_is_unchanged(self):
        for sample in (
            "AUTO_APPROVE = True  # auto-approve past drafted",
            "if x: skip review",
            "aUTO advAnCe the job without a human",
        ):
            self.assertTrue(AUTOADV.search(sample), sample)


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)


class EvidenceCli(unittest.TestCase):
    """CLI-level checks: the runbook must block a real frozen change and be
    silent about report prose unless a markers file is supplied."""

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="evidence-")
        self.repo = os.path.join(self.work, "repo")
        os.makedirs(self.repo)
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "t@t")
        git(self.repo, "config", "user.name", "t")
        with open(os.path.join(self.repo, "app.py"), "w") as fh:
            fh.write("print('base')\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "base: verified")
        git(self.repo, "branch", "-m", "base")
        git(self.repo, "checkout", "-qb", "feature")
        with open(os.path.join(self.repo, "app.py"), "a") as fh:
            fh.write("print('change')\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "change: tests pass")
        self.registry = os.path.join(self.work, "frozen.json")
        with open(self.registry, "w") as fh:
            fh.write('{"items": [{"id": "F1", "area": "app core", "owned_files": ["app.py"]}]}')

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def run_(self, *extra):
        env = dict(os.environ)
        env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run(
            [sys.executable, "-m", "gatesmith", "evidence",
             "--repo", self.repo, "--base", "base", "--branch", "feature",
             "--registry", self.registry, *extra],
            capture_output=True, text=True, env=env)

    def test_frozen_change_blocks(self):
        blocked = self.run_("--owned", "app.py")
        self.assertEqual(blocked.returncode, 1, blocked.stdout + blocked.stderr)
        self.assertIn("FAIL  4. frozen", blocked.stdout)
        self.assertIn("VERDICT: BLOCK", blocked.stdout)

    def test_non_frozen_change_clears(self):
        with open(self.registry, "w") as fh:
            fh.write('{"items": []}')
        cleared = self.run_("--owned", "app.py")
        self.assertEqual(cleared.returncode, 0, cleared.stdout + cleared.stderr)
        self.assertIn("VERDICT: PASS", cleared.stdout)

    def test_markers_check_is_opt_in(self):
        without = self.run_("--owned", "app.py")
        self.assertNotIn("2. markers", without.stdout)
        markers = os.path.join(self.work, "markers.txt")
        with open(markers, "w") as fh:
            fh.write("# policy: one regex per line\nbanned-import\nprint\\('change'\\)\n")
        with_markers = self.run_("--owned", "app.py", "--markers-file", markers)
        self.assertIn("WARN  2. markers", with_markers.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
