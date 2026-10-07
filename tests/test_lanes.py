"""End-to-end tests for the guarded parallel-lane mechanism.

Runs the ``gatesmith lanes`` CLI against a throwaway git repo + registries.
Self-contained; no network. Run from the repo root:
``python -m unittest -v tests.test_lanes``.

The frozen registry is a local fixture here on purpose: the frozen check used to
shell out to a script path that disappeared after repackaging, so the frozen
tests passed vacuously (nothing was ever blocked). These tests point the guard
at a real registry and assert that a frozen owned-file actually BLOCKS, with a
non-frozen control that clears — so the block cannot come from a blanket
failure.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sh(*args, **kw):
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(args, capture_output=True, text=True, env=env,
                          timeout=kw.pop("timeout", 30), **kw)


def git(repo, *args):
    result = sh("git", "-C", repo, *args)
    assert result.returncode == 0, result.stderr


class LaneGuardTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="lgtest-")
        self.reg = os.path.join(self.work, "reg.json")
        self.frozen = os.path.join(self.work, "frozen.json")
        with open(self.frozen, "w") as fh:
            json.dump({"items": [
                {"id": "F1", "area": "chat state", "owned_files": ["src/hooks/useChat.ts"]},
            ]}, fh)
        self.repo = os.path.join(self.work, "repo")
        os.makedirs(self.repo)
        self.g = lambda *a: [sys.executable, "-m", "gatesmith", "lanes",
                             "--registry", self.reg, "--frozen-registry", self.frozen, *a]
        self.run_ = lambda *a: sh(*self.g(*a), cwd=self.repo)

        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "t@t")
        git(self.repo, "config", "user.name", "t")
        for name in ("fileA.txt", "fileB.txt", "fileC.txt"):
            with open(os.path.join(self.repo, name), "w") as fh:
                fh.write("base\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "base")
        git(self.repo, "branch", "-m", "base")
        for branch, name in (("feat-a", "fileA.txt"), ("feat-b", "fileB.txt")):
            git(self.repo, "checkout", "-qb", branch)
            with open(os.path.join(self.repo, name), "a") as fh:
                fh.write(branch + "\n")
            git(self.repo, "add", ".")
            git(self.repo, "commit", "-qm", branch)
            git(self.repo, "checkout", "-q", "base")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def start(self, lane, branch, owned):
        self.assertEqual(self.run_("start", "--lane", lane, "--branch", branch,
                                   "--base", "base", "--owner", "dev", "--owned", owned,
                                   "--repo", self.repo).returncode, 0)

    def test_owned_clash_tripwire(self):
        self.start("laneA", "feat-a", "fileA.txt")
        r = self.run_("check", "--lane", "laneB", "--owned", "fileA.txt", "--repo", self.repo)
        self.assertEqual(r.returncode, 1)
        self.assertIn("OWNED-CLASH", r.stdout + r.stderr)

    def test_disjoint_is_clear(self):
        self.assertEqual(self.run_("check", "--lane", "laneB", "--owned", "fileB.txt",
                                   "--repo", self.repo).returncode, 0)

    def test_list_active_lanes(self):
        self.start("laneA", "feat-a", "fileA.txt")
        self.start("laneB", "feat-b", "fileB.txt")
        out = self.run_("list").stdout
        self.assertIn("laneA", out)
        self.assertIn("laneB", out)

    def test_manifest_flags_unowned_drift(self):
        git(self.repo, "checkout", "-qb", "feat-c", "base")
        with open(os.path.join(self.repo, "fileC.txt"), "a") as fh:
            fh.write("c\n")
        with open(os.path.join(self.repo, "baseline.txt"), "w") as fh:
            fh.write("drift\n")   # changed but UNDECLARED by laneC
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "c")
        git(self.repo, "checkout", "-q", "base")
        self.start("laneC", "feat-c", "fileC.txt")
        out = self.run_("manifest", "--lane", "laneC", "--repo", self.repo, "--base", "base").stdout
        self.assertIn("UNOWNED CHANGED", out)
        self.assertIn("baseline.txt", out)

    def test_shared_tree_busy_trip(self):
        with open(os.path.join(self.repo, "fileB.txt"), "a") as fh:
            fh.write("dirty\n")
        r = self.run_("check", "--lane", "laneD", "--owned", "fileB.txt", "--repo", self.repo)
        self.assertEqual(r.returncode, 1)
        self.assertIn("SHARED-TREE-BUSY", r.stdout + r.stderr)

    # ── frozen guard (non-vacuous) ──────────────────────────────────────────

    def test_frozen_owned_file_blocks_check(self):
        # A frozen path blocks even for a brand-new lane...
        blocked = self.run_("check", "--lane", "laneZ", "--owned", "src/hooks/useChat.ts",
                            "--repo", self.repo)
        self.assertEqual(blocked.returncode, 1, blocked.stdout + blocked.stderr)
        self.assertIn("FROZEN-BLOCKED", blocked.stdout + blocked.stderr)

    def test_non_frozen_file_clears_check(self):
        # ...while the same command on a non-frozen file clears: the block above
        # is caused by the frozen entry, not by a guard that always fails.
        clear = self.run_("check", "--lane", "laneZ", "--owned", "src/other.ts",
                          "--repo", self.repo)
        self.assertEqual(clear.returncode, 0, clear.stdout + clear.stderr)
        self.assertIn("CLEAR", clear.stdout)

    def test_close_frees_files(self):
        self.start("laneA", "feat-a", "fileA.txt")
        self.run_("close", "--lane", "laneA", "--status", "merged")
        self.assertEqual(self.run_("check", "--lane", "laneE", "--owned", "fileA.txt",
                                   "--repo", self.repo).returncode, 0)

    def test_close_duplicate_id_fails_closed_then_active_only_closes_active_record(self):
        self.start("laneA", "feat-a", "fileA.txt")
        self.assertEqual(self.run_("close", "--lane", "laneA", "--status", "merged").returncode, 0)
        with open(self.reg) as f:
            reg = json.load(f)
        duplicate = json.loads(json.dumps(reg["lanes"][0]))
        duplicate["status"] = "active"
        duplicate.pop("closed", None)
        reg["lanes"].append(duplicate)
        with open(self.reg, "w") as f:
            json.dump(reg, f)

        with open(self.reg) as f:
            before = f.read()
        ambiguous = self.run_("close", "--lane", "laneA", "--status", "closed")
        self.assertEqual(ambiguous.returncode, 1)
        self.assertIn("exactly one matching record", ambiguous.stdout + ambiguous.stderr)
        with open(self.reg) as f:
            self.assertEqual(before, f.read())

        active_only = self.run_("close", "--lane", "laneA", "--only-active", "--status", "closed")
        self.assertEqual(active_only.returncode, 0)
        with open(self.reg) as f:
            statuses = [lane["status"] for lane in json.load(f)["lanes"]]
        self.assertEqual(statuses, ["merged", "closed"])

    def test_close_active_only_requires_exactly_one_active_record(self):
        self.start("laneA", "feat-a", "fileA.txt")
        with open(self.reg) as f:
            reg = json.load(f)
        reg["lanes"].append(json.loads(json.dumps(reg["lanes"][0])))
        with open(self.reg, "w") as f:
            json.dump(reg, f)

        multiple = self.run_("close", "--lane", "laneA", "--only-active", "--status", "closed")
        self.assertEqual(multiple.returncode, 1)
        self.assertIn("exactly one active record", multiple.stdout + multiple.stderr)

        with open(self.reg) as f:
            reg = json.load(f)
        for lane in reg["lanes"]:
            lane["status"] = "merged"
        with open(self.reg, "w") as f:
            json.dump(reg, f)
        zero = self.run_("close", "--lane", "laneA", "--only-active", "--status", "closed")
        self.assertEqual(zero.returncode, 1)
        self.assertIn("exactly one active record", zero.stdout + zero.stderr)

    def test_claim_adds_free_file_to_one_active_lane(self):
        self.start("laneA", "feat-a", "fileA.txt")
        claimed = self.run_("claim", "--lane", "laneA", "--owned", "fileC.txt", "--repo", self.repo)
        self.assertEqual(claimed.returncode, 0, claimed.stdout + claimed.stderr)
        with open(self.reg) as f:
            lane = json.load(f)["lanes"][0]
        self.assertEqual(lane["owned_files"], ["fileA.txt", "fileC.txt"])
        self.assertEqual(lane["status"], "active")
        self.assertEqual(lane["branch"], "feat-a")

    def test_claim_rejects_another_active_owner_without_saving(self):
        self.start("laneA", "feat-a", "fileA.txt")
        self.start("laneB", "feat-b", "fileB.txt")
        with open(self.reg) as f:
            before = f.read()
        blocked = self.run_("claim", "--lane", "laneA", "--owned", "fileB.txt", "--repo", self.repo)
        self.assertEqual(blocked.returncode, 1)
        self.assertIn("OWNED-CLASH", blocked.stdout + blocked.stderr)
        with open(self.reg) as f:
            self.assertEqual(before, f.read())

    def test_claim_rejects_shared_tree_dirty_file_without_saving(self):
        self.start("laneA", "feat-a", "fileA.txt")
        with open(os.path.join(self.repo, "fileC.txt"), "a") as fh:
            fh.write("dirty\n")
        with open(self.reg) as f:
            before = f.read()
        blocked = self.run_("claim", "--lane", "laneA", "--owned", "fileC.txt", "--repo", self.repo)
        self.assertEqual(blocked.returncode, 1)
        self.assertIn("SHARED-TREE-BUSY", blocked.stdout + blocked.stderr)
        with open(self.reg) as f:
            self.assertEqual(before, f.read())

    def test_claim_rejects_frozen_path_without_saving(self):
        self.start("laneA", "feat-a", "fileA.txt")
        with open(self.reg) as f:
            before = f.read()
        blocked = self.run_("claim", "--lane", "laneA", "--owned", "src/hooks/useChat.ts",
                            "--repo", self.repo)
        self.assertEqual(blocked.returncode, 1)
        self.assertIn("FROZEN-BLOCKED", blocked.stdout + blocked.stderr)
        with open(self.reg) as f:
            self.assertEqual(before, f.read())

    def test_claim_requires_exactly_one_active_lane_without_saving(self):
        missing = self.run_("claim", "--lane", "missing", "--owned", "fileC.txt", "--repo", self.repo)
        self.assertEqual(missing.returncode, 1)
        self.assertIn("exactly one active record", missing.stdout + missing.stderr)

        self.start("laneA", "feat-a", "fileA.txt")
        with open(self.reg) as f:
            reg = json.load(f)
        reg["lanes"].append(json.loads(json.dumps(reg["lanes"][0])))
        with open(self.reg, "w") as f:
            json.dump(reg, f)
        with open(self.reg) as f:
            before = f.read()
        multiple = self.run_("claim", "--lane", "laneA", "--owned", "fileC.txt", "--repo", self.repo)
        self.assertEqual(multiple.returncode, 1)
        self.assertIn("exactly one active record", multiple.stdout + multiple.stderr)
        with open(self.reg) as f:
            self.assertEqual(before, f.read())

    def test_signoff_records_verdict(self):
        self.start("laneA", "feat-a", "fileA.txt")
        self.assertEqual(self.run_("signoff", "--lane", "laneA", "--reviewer", "r1",
                                   "--verdict", "block", "--note", "drift").returncode, 0)
        with open(self.reg) as f:
            lane = next(l for l in json.load(f)["lanes"] if l["id"] == "laneA")
        self.assertEqual(lane["manifest"]["signoff"], "block")
        self.assertIn("drift", lane["manifest"]["notes"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
