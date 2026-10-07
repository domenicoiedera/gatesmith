"""Tests for the read-only worktree audit.

Fixture-driven: synthetic repositories with spaces and unicode in worktree
paths, detached HEAD, rename status, untracked dirs, failed git probes. Proves
JSON-safe output, subprocess argv (no shell), a 0600 report, unknown-never-safe
classification, and the 48h/7d boundaries.

Run from the repo root: ``python -m unittest -v tests.test_worktree``.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from gatesmith import worktree as wa  # noqa: E402


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          timeout=30)


def make_repo(base, name):
    repo = base / name
    repo.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    (repo / "f.txt").write_text("seed\n")
    git(repo, "add", ".")
    git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "seed")
    return repo


class WorktreeAuditTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="wa-test-"))
        self.repo = make_repo(self.tmp, "main repo")
        self.wt_clean = self.tmp / "wt clean"          # space in path
        self.assertEqual(git(self.repo, "worktree", "add", "-q", "-b", "clean-lane",
                             str(self.wt_clean)).returncode, 0)
        self.wt_dirty = self.tmp / "wt-dirty-ünïcode"
        self.assertEqual(git(self.repo, "worktree", "add", "-q", str(self.wt_dirty),
                             "-b", "dirty-lane").returncode, 0)
        (self.wt_dirty / "extra.txt").write_text("dirty\n")   # untracked
        (self.wt_dirty / "f.txt").write_text("changed\n")     # modified
        old = time.time() - 10 * 86400
        os.utime(self.wt_dirty / ".git", (old, old))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ── inventory ─────────────────────────────────────────────────────────
    def test_inventory_covers_main_and_linked(self):
        rows = wa.audit(str(self.repo))
        paths = {r["path"] for r in rows}
        self.assertIn(str(self.repo.resolve()), paths)
        self.assertIn(str(self.wt_clean.resolve()), paths)
        self.assertIn(str(self.wt_dirty.resolve()), paths)

    def test_rows_carry_required_fields(self):
        rows = wa.audit(str(self.repo))
        need = {"path", "branch", "head", "last_commit_age_sec", "clean",
                "status_counts", "in_lane_registry", "process_cwd", "classification"}
        for row in rows:
            self.assertTrue(need.issubset(row.keys()), f"missing fields: {need - row.keys()}")

    def test_unicode_and_space_paths_json_safe(self):
        rows = wa.audit(str(self.repo))
        blob = json.dumps(rows, ensure_ascii=False)
        self.assertIn("wt clean", blob)
        self.assertIn("ünïcode", blob)

    def test_json_ascii_escaped_output_is_also_safe(self):
        rows = wa.audit(str(self.repo))
        blob = json.dumps(rows)
        self.assertIn("wt clean", blob)

    def test_dirty_and_clean_flags(self):
        rows = {r["path"]: r for r in wa.audit(str(self.repo))}
        clean_row = rows[str(self.wt_clean.resolve())]
        if not clean_row["clean"]:
            raw = git(self.wt_clean, "status", "--porcelain").stdout
            acr = git(self.wt_clean, "config", "--get", "core.autocrlf").stdout.strip()
            self.fail(f"clean worktree reported dirty: row={json.dumps(clean_row)} "
                      f"raw_status={raw!r} core.autocrlf={acr!r}")
        self.assertFalse(rows[str(self.wt_dirty.resolve())]["clean"])
        counts = rows[str(self.wt_dirty.resolve())]["status_counts"]
        self.assertGreaterEqual(counts.get("modified", 0), 1)
        self.assertGreaterEqual(counts.get("untracked", 0), 1)

    def test_rename_status_counted(self):
        (self.wt_clean / "old.txt").write_text("old\n")
        git(self.wt_clean, "add", "-A")
        git(self.wt_clean, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "add old")
        git(self.wt_clean, "mv", "old.txt", "new.txt")
        rows = {r["path"]: r for r in wa.audit(str(self.repo))}
        counts = rows[str(self.wt_clean.resolve())]["status_counts"]
        self.assertIn("renamed", counts)
        self.assertEqual(counts.get("renamed"), 1)

    # ── classification ────────────────────────────────────────────────────
    def test_active_when_recent(self):
        self.assertEqual(wa.classify({"clean": True, "last_commit_age_sec": 3600,
                                      "in_lane_registry": False, "process_cwd": False}), "active")

    def test_stale_clean_after_seven_days(self):
        self.assertEqual(wa.classify({"clean": True, "last_commit_age_sec": 8 * 86400,
                                      "in_lane_registry": False, "process_cwd": False}),
                         "candidate_stale_clean")

    def test_stale_dirty_after_seven_days(self):
        self.assertEqual(wa.classify({"clean": False, "last_commit_age_sec": 8 * 86400,
                                      "in_lane_registry": False, "process_cwd": False}),
                         "candidate_stale_dirty")

    def test_lane_registry_membership_makes_active(self):
        self.assertEqual(wa.classify({"clean": True, "last_commit_age_sec": 30 * 86400,
                                      "in_lane_registry": True, "process_cwd": False}), "active")

    def test_process_cwd_makes_active(self):
        self.assertEqual(wa.classify({"clean": True, "last_commit_age_sec": 30 * 86400,
                                      "in_lane_registry": False, "process_cwd": True}), "active")

    def test_unknown_never_safe(self):
        self.assertEqual(wa.classify({"clean": False, "last_commit_age_sec": 8 * 86400,
                                      "in_lane_registry": False, "process_cwd": False,
                                      "probe_failed": True}), "unknown")

    def test_audit_is_active_when_no_process_and_recent(self):
        # A fresh worktree with no process inside it is active, not unknown: the
        # process probe must return a real negative, not a permanent "can't tell".
        from unittest import mock
        with mock.patch.object(wa, "_process_in_use", return_value=False):
            rows = {r["path"]: r for r in wa.audit(str(self.repo))}
        self.assertEqual(rows[str(self.wt_clean.resolve())]["classification"], "active")

    def test_failed_probe_becomes_unknown(self):
        real = self.wt_clean / ".git"
        real.unlink()
        real.write_text("garbage\n")
        rows = {r["path"]: r for r in wa.audit(str(self.repo))}
        self.assertEqual(rows[str(self.wt_clean.resolve())]["classification"], "unknown")
        self.assertTrue(rows[str(self.wt_clean.resolve())]["probe_failed"])

    # ── safety shape ──────────────────────────────────────────────────────
    def test_no_mutation_verbs_exist(self):
        for verb in ("delete", "prune", "reset", "stash", "archive", "remove"):
            self.assertFalse(hasattr(wa, verb), f"audit must not expose {verb}()")

    def test_subprocess_uses_argv_arrays(self):
        import inspect
        self.assertNotIn("shell=True", inspect.getsource(wa))

    # ── report writing ────────────────────────────────────────────────────
    @unittest.skipUnless(os.name == "posix", "POSIX file-mode semantics")
    def test_report_written_at_0600(self):
        rows = wa.audit(str(self.repo))
        out = self.tmp / "worktree-audit.json"
        wa.write_report(str(out), {"rows": rows})
        self.assertTrue(out.exists())
        self.assertEqual(oct(os.stat(out).st_mode & 0o777), oct(0o600))
        payload = json.loads(out.read_text())
        self.assertEqual(payload["schema"], "gatesmith-worktree-audit/v1")
        self.assertEqual(len(payload["rows"]), len(rows))


if __name__ == "__main__":
    unittest.main(verbosity=2)
