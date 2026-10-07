"""Permanent tests for the wave-1 fix round: the H1-H5 attacks, ported.

Each method maps to an acceptance criterion F1-F9 (see the fix spec). They are
written to discriminate: ``tools/mutation_check.py`` proves each guard's test
goes RED when that guard is disabled. No network; no private paths. Seal tests
are guarded with ``@unittest.skipUnless(shutil.which("ssh-keygen"), ...)`` so a
runner without OpenSSH stays green.

Run: ``python3.12 -m unittest -v tests.test_attacks``.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from gatesmith import chain  # noqa: E402

HAS_SSH_KEYGEN = shutil.which("ssh-keygen") is not None
REG = "reg.json"


class AttackBase(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="attacks-")
        self.env = dict(os.environ)
        self.env["PYTHONPATH"] = ROOT + os.pathsep + self.env.get("PYTHONPATH", "")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def path(self, *parts):
        return os.path.join(self.work, *parts)

    def gs(self, *args, env=None, cwd=None, registry=REG):
        return subprocess.run(
            [sys.executable, "-m", "gatesmith", "review", "--registry", registry, *args],
            cwd=cwd or self.work, env=env or self.env, capture_output=True,
            shell=False, encoding="utf-8", errors="replace", timeout=30)

    def key(self, name):
        priv = self.path(name)
        result = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", name + "@test", "-f", priv, "-q"],
            stdin=subprocess.DEVNULL, capture_output=True, shell=False,
            encoding="utf-8", errors="replace", timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return priv

    def allowed(self, name, principal, private_key):
        with open(private_key + ".pub", encoding="utf-8") as handle:
            pub = handle.read().strip()
        dest = self.path(name)
        with open(dest, "w", encoding="utf-8") as handle:
            handle.write(f"{principal} {pub}\n")
        return dest

    def open_sign(self, rid="r1", executor="backend", reviewer="rev1"):
        self.assertEqual(self.gs("open", "--id", rid, "--executor", executor,
                                 "--change", "c").returncode, 0)
        self.assertEqual(self.gs("sign", "--id", rid, "--reviewer", reviewer,
                                 "--verdict", "pass").returncode, 0)

    def restamp_in_place(self, mutate):
        """Load the registry, apply ``mutate``, re-stamp the chain, rewrite."""
        with open(self.path(REG), encoding="utf-8") as handle:
            reg = json.load(handle)
        mutate(reg)
        reg["gatesmith_registry"] = {"v": chain.CHAIN_VERSION}
        chain.stamp(reg["reviews"])
        with open(self.path(REG), "w", encoding="utf-8") as handle:
            json.dump(reg, handle, indent=2)


# ── H1 / F1: the executor-never-seals attack ─────────────────────────────────
class SealRequiredTest(AttackBase):
    def test_F1_executor_never_seals_is_blocked(self):
        self.open_sign()
        r = self.gs("gate", "--id", "r1", "--target", "push")
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("no seal", r.stderr.lower())
        self.assertIn("--allow-unsealed", r.stderr)

    def test_F1_allow_unsealed_admits_with_a_loud_warning(self):
        self.open_sign()
        r = self.gs("gate", "--id", "r1", "--target", "push", "--allow-unsealed")
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertIn("the seal was NOT enforced", r.stderr)
        self.assertIn("GATE-OPEN", r.stdout)


# ── H1-downgrade / F2: sealed, re-stamped, sidecars deleted ──────────────────
class DowngradeTest(AttackBase):
    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_F2_three_entry_last_forgery_plus_deleted_sidecars_blocks(self):
        rev = self.key("rev1")
        anchor = self.allowed("real_allowed", "rev1", rev)
        for rid, change in (("r1", "a"), ("r2", "b"), ("r3", "c")):
            self.assertEqual(self.gs("open", "--id", rid, "--executor", "backend",
                                     "--change", change).returncode, 0)
            self.assertEqual(self.gs("sign", "--id", rid, "--reviewer", "rev1",
                                     "--verdict", "pass").returncode, 0)
        self.assertEqual(self.gs("seal", "--key", rev).returncode, 0)
        self.assertEqual(self.gs("gate", "--id", "r3", "--target", "push",
                                 "--allowed-signers", anchor).returncode, 0)
        # byte-match replacement: forge the LAST entry, re-stamp, delete both sidecars
        self.restamp_in_place(lambda reg: reg["reviews"][2].__setitem__("change", "HACKED-LAST"))
        os.remove(self.path(REG + ".sig"))
        os.remove(self.path(REG + ".digest"))
        r = self.gs("gate", "--id", "r3", "--target", "push", "--allowed-signers", anchor)
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("no seal", r.stderr.lower())


# ── H2 / F3: no verb may be a false "ADMITTED" oracle ────────────────────────
class FalseOracleTest(AttackBase):
    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_F3_status_never_prints_a_bare_gate_open_on_a_stale_seal(self):
        rev = self.key("rev1")
        self.allowed("real_allowed", "rev1", rev)
        self.open_sign()
        self.assertEqual(self.gs("seal", "--key", rev).returncode, 0)
        # a stale seal: tamper the entry and re-stamp the chain, sidecars kept
        self.restamp_in_place(lambda reg: reg["reviews"][0].__setitem__("change", "TAMPERED"))
        status = self.gs("status", "--id", "r1")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("GATE:", status.stdout)
        self.assertNotIn("GATE: OPEN\n", status.stdout)             # never bare OPEN
        self.assertNotIn("OPEN (seal VERIFIED)", status.stdout)     # nothing verified it
        self.assertIn("UNVERIFIED", status.stdout)                  # G1: say what was done
        gate = self.gs("gate", "--id", "r1", "--target", "push", "--allowed-signers",
                       "real_allowed")
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))
        # G1: with the anchor, status re-derives the gate's own verdict (BLOCKED)
        checked = self.gs("status", "--id", "r1", "--allowed-signers", "real_allowed")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("GATE: BLOCKED", checked.stdout)
        self.assertNotIn("OPEN", checked.stdout)


# ── G1 / H-A: no informational verb may claim a verification it did not run ──
class InformationalSealTest(AttackBase):
    def test_G1_unverified_seal_is_not_reported_as_verified(self):
        """A present `.sig` with no anchor must read UNVERIFIED, never VERIFIED.

        This is the H-A false-oracle class: the old renderer turned "a `.sig`
        file exists and the `.digest` matches the head" into `GATE: OPEN
        (sealed)` / `seal: sealed` without ever checking the signature — a
        zero-byte `.sig` satisfied it. No anchor here, so NO verification may be
        claimed. Needs no ssh-keygen: the point is that the verb does not check.
        """
        self.open_sign()
        # a sidecar that exists but was never checked (deliberately not verified)
        with open(self.path(REG + ".sig"), "w", encoding="utf-8") as handle:
            handle.write("")                                   # zero-byte signature
        with open(self.path(REG + ".digest"), "w", encoding="utf-8") as handle:
            handle.write("not a real digest")
        status = self.gs("status", "--id", "r1")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("OPEN (seal present, UNVERIFIED)", status.stdout)
        self.assertNotIn("OPEN (seal VERIFIED)", status.stdout)     # never a check it did not do
        self.assertNotIn("(sealed)", status.stdout)                 # the old false oracle
        listing = self.gs("list", "--all")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertIn("present (UNVERIFIED", listing.stdout)
        self.assertNotIn("seal: sealed", listing.stdout)
        self.assertNotIn("seal: VERIFIED", listing.stdout)
        # an anchor that cannot be read is a FAILED check, not a false VERIFIED
        failed = self.gs("status", "--id", "r1", "--allowed-signers", "absent-anchor")
        self.assertEqual(failed.returncode, 0, failed.stderr)
        self.assertIn("GATE: BLOCKED", failed.stdout)

    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_G1_status_with_anchor_re_derives_the_gate_decision(self):
        """With `--allowed-signers`, status reports exactly what the gate decides."""
        rev = self.key("rev1")
        anchor = self.allowed("real_allowed", "rev1", rev)
        self.open_sign()
        self.assertEqual(self.gs("seal", "--key", rev).returncode, 0)
        # green: a real signature verifies, and status agrees with the gate
        ok = self.gs("status", "--id", "r1", "--allowed-signers", anchor)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("GATE: OPEN (seal VERIFIED)", ok.stdout)
        self.assertEqual(self.gs("gate", "--id", "r1", "--target", "push",
                                 "--allowed-signers", anchor).returncode, 0)
        # the attack: re-stamp a forgery, forge the digest, zero-byte .sig
        self.restamp_in_place(lambda reg: reg["reviews"][0].__setitem__("change", "HACKED"))
        with open(self.path(REG + ".digest"), "w", encoding="utf-8") as handle:
            from gatesmith import chain, seal
            with open(self.path(REG), encoding="utf-8") as src:
                reg = json.load(src)
            handle.write(seal.preimage(chain.head_hash(reg["reviews"]),
                                       len(reg["reviews"]), REG))
        with open(self.path(REG + ".sig"), "w", encoding="utf-8") as handle:
            handle.write("")                                   # ZERO-BYTE signature
        # the enforced verb blocks...
        gate = self.gs("gate", "--id", "r1", "--target", "push", "--allowed-signers", anchor)
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))
        # ...and status, given the same anchor, re-derives the SAME verdict
        status = self.gs("status", "--id", "r1", "--allowed-signers", anchor)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("GATE: BLOCKED", status.stdout)
        self.assertNotIn("OPEN (seal VERIFIED)", status.stdout)
        # without the anchor status refuses to claim either way
        unverified = self.gs("status", "--id", "r1")
        self.assertIn("OPEN (seal present, UNVERIFIED)", unverified.stdout)


# ── H3 / F4: anchor inside a repo, registry outside any repo ─────────────────
class AnchorWarningTest(AttackBase):
    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_F4_anchor_inside_a_repo_is_warned_though_the_registry_is_outside(self):
        project = self.path("project")
        os.makedirs(os.path.join(project, ".git"))
        vault = self.path("vault")            # no .git ancestor
        os.makedirs(vault)
        rev = self.key("rev1")
        with open(rev + ".pub", encoding="utf-8") as handle:
            pub = handle.read().strip()
        anchor = os.path.join(project, "allowed")
        with open(anchor, "w", encoding="utf-8") as handle:
            handle.write(f"rev1 {pub}\n")
        for verb in (("open", "--id", "r1", "--executor", "backend", "--change", "x"),
                     ("sign", "--id", "r1", "--reviewer", "rev1", "--verdict", "pass"),
                     ("seal", "--key", rev)):
            r = self.gs(*verb, cwd=vault)
            self.assertEqual(r.returncode, 0, (verb, r.stdout, r.stderr))
        r = self.gs("gate", "--id", "r1", "--target", "push", "--allowed-signers",
                    anchor, cwd=vault)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertIn("WARNING", r.stderr)
        self.assertIn("INSIDE", r.stderr)


# ── H4 / F5: one exit taxonomy ───────────────────────────────────────────────
class ExitTaxonomyTest(AttackBase):
    def _write(self, body):
        with open(self.path(REG), "w", encoding="utf-8") as handle:
            handle.write(body)

    def test_F5_gate_exit_taxonomy(self):
        # broken chain (entry 0 edited with a downstream entry) -> 1
        for rid in ("r1", "r2"):
            self.gs("open", "--id", rid, "--executor", "backend", "--change", "x")
        self.gs("sign", "--id", "r1", "--reviewer", "rev1", "--verdict", "pass")
        self.restamp_in_place(lambda reg: reg["reviews"][0].__setitem__("change", "tampered"))
        # undo the re-stamp: leave the registry in a genuinely broken state
        with open(self.path(REG), encoding="utf-8") as handle:
            reg = json.load(handle)
        reg["reviews"][0]["change"] = "tampered-again"      # no re-stamp now
        with open(self.path(REG), "w", encoding="utf-8") as handle:
            json.dump(reg, handle, indent=2)
        r = self.gs("gate", "--id", "r1", "--target", "push")
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("chain broken", r.stderr)

        # stripped chain field -> 1 (structure, not "legacy")
        os.remove(self.path(REG))
        for rid in ("r1", "r2"):
            self.gs("open", "--id", rid, "--executor", "backend", "--change", "x")
        with open(self.path(REG), encoding="utf-8") as handle:
            reg = json.load(handle)
        del reg["reviews"][0]["prev_hash"]
        with open(self.path(REG), "w", encoding="utf-8") as handle:
            json.dump(reg, handle, indent=2)
        r = self.gs("gate", "--id", "r1", "--target", "push")
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("chain broken", r.stderr)
        self.assertNotIn("predates", r.stderr)

        # no marker (legacy) -> 1
        os.remove(self.path(REG))
        self.gs("open", "--id", "r1", "--executor", "backend", "--change", "x")
        with open(self.path(REG), encoding="utf-8") as handle:
            reg = json.load(handle)
        del reg["gatesmith_registry"]
        with open(self.path(REG), "w", encoding="utf-8") as handle:
            json.dump(reg, handle, indent=2)
        r = self.gs("gate", "--id", "r1", "--target", "push")
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("predates the chain", r.stderr)

        # missing `id` (valid chain) -> 2, clean message, never a traceback
        os.remove(self.path(REG))
        reg = {"gatesmith_registry": {"v": chain.CHAIN_VERSION},
               "reviews": [{"executor": "a", "change": "x", "status": "done",
                            "signoff": {"reviewer": "b", "verdict": "pass",
                                        "note": "", "at": None, "auto": False}}]}
        chain.stamp(reg["reviews"])
        with open(self.path(REG), "w", encoding="utf-8") as handle:
            json.dump(reg, handle, indent=2)
        r = self.gs("gate", "--id", "r1", "--target", "push")
        self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
        self.assertIn("missing required field", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_G2_malformed_shapes_exit_2_and_never_0(self):
        """G2: every malformed SHAPE is exit 2; no malformed shape may clear (0).

        Shape (root not an object, ``reviews`` not a list, non-object entry,
        missing field, wrong field type) is usage-class → **2**, distinct from
        integrity (chain broken/structure/legacy) → **1**. Before G2 a
        present-but-non-list ``reviews`` fell through to the chain layer and
        exited 1.
        """
        base = {"id": "r1", "executor": "backend", "change": "x", "status": "done",
                "signoff": {"reviewer": "rev1", "verdict": "pass", "note": "",
                            "at": None, "auto": False}}

        def chained(entry):
            reviews = [dict(entry)]
            chain.stamp(reviews)
            return {"gatesmith_registry": {"v": chain.CHAIN_VERSION}, "reviews": reviews}

        shape_cases = {
            "reviews is a dict": {"gatesmith_registry": {"v": 2}, "reviews": {"a": 1}},
            "reviews is a string": {"gatesmith_registry": {"v": 2}, "reviews": "nope"},
            "reviews holds a non-object": {"gatesmith_registry": {"v": 2}, "reviews": [1, 2]},
            "missing id": chained({k: v for k, v in base.items() if k != "id"}),
            "id wrong type": chained(dict(base, id=7)),
            "signoff non-dict": chained(dict(base, signoff="pass")),
            "signoff.verdict wrong type": chained(dict(
                base, signoff=dict(base["signoff"], verdict=1))),
        }
        for label, body in shape_cases.items():
            self._write(json.dumps(body))
            r = self.gs("gate", "--id", "r1", "--target", "push")
            self.assertEqual(r.returncode, 2, (label, r.stdout, r.stderr))
            self.assertNotIn("Traceback", r.stderr, label)
        # root not a JSON object -> 2 (store rejects it before anything else)
        for label, text in {"root array": "[1, 2, 3]", "root string": '"x"'}.items():
            self._write(text)
            r = self.gs("gate", "--id", "r1", "--target", "push")
            self.assertEqual(r.returncode, 2, (label, r.stdout, r.stderr))
            self.assertNotIn("Traceback", r.stderr, label)

        # the sweep: NO single-field malformed shape may ever clear (0)
        for field in ("id", "executor", "change", "status", "signoff"):
            for bad in (None, 7, [], {}):
                entry = dict(base)
                entry[field] = bad
                self._write(json.dumps(chained(entry)))
                r = self.gs("gate", "--id", "r1", "--target", "push")
                self.assertNotEqual(r.returncode, 0, (field, bad, r.stdout, r.stderr))


# ── H5 / F6: no leading-dash path reaches argv ───────────────────────────────
class ArgvGuardTest(AttackBase):
    def _gs_raw(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "gatesmith", "review", *args],
            cwd=self.work, env=self.env, capture_output=True, shell=False,
            encoding="utf-8", errors="replace", timeout=30)

    def test_F6_leading_dash_registry_is_a_usage_error(self):
        self.open_sign()
        r = self._gs_raw("--registry=-evil.json", "gate", "--id", "r1", "--target", "push")
        self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
        self.assertIn("begin with '-'", r.stderr)
        self.assertFalse(os.path.exists(self.path("-evil.json.digest")))

    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_F6_leading_dash_registry_never_reaches_ssh_keygen(self):
        rev = self.key("rev1")
        r = self._gs_raw("--registry=-dash.json", "seal", "--key", rev)
        self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
        self.assertFalse(os.path.exists(self.path("-dash.json.digest")))
        self.assertFalse(os.path.exists(self.path("-dash.json.sig")))

    def test_G4_abbreviated_danger_flag_is_rejected(self):
        """G4: allow_abbrev=False — no prefix may enable --allow-unsealed."""
        self.open_sign()
        for abbrev in ("--allow-u", "--allow-unseal", "--allow-unsealed-extra"):
            r = self.gs("gate", "--id", "r1", "--target", "push", abbrev)
            self.assertEqual(r.returncode, 2, (abbrev, r.stdout, r.stderr))
            self.assertIn("unrecognized", (r.stderr or "").lower(), abbrev)
        # control: the exact DANGER flag is still accepted, and still warns
        full = self.gs("gate", "--id", "r1", "--target", "push", "--allow-unsealed")
        self.assertEqual(full.returncode, 0, (full.stdout, full.stderr))
        self.assertIn("NOT enforced", full.stderr)

    def test_G5_allow_unsealed_help_is_exact(self):
        """G5: the help must not claim the flag skips a present seal."""
        r = subprocess.run([sys.executable, "-m", "gatesmith", "review", "gate", "--help"],
                           cwd=self.work, env=self.env, capture_output=True, shell=False,
                           encoding="utf-8", errors="replace", timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        flat = " ".join(r.stdout.split())
        self.assertIn("admit a registry that has NO seal", flat)
        self.assertIn("a PRESENT seal is still verified and can still block", flat)
        self.assertNotIn("skips the seal entirely", flat)      # the old, false wording


# ── F7: the signed preimage uses a normalized path ───────────────────────────
class PathNormalizationTest(AttackBase):
    def test_F7_normalize_path_collapses_and_slashes(self):
        from gatesmith import seal
        self.assertEqual(seal.normalize_path("./reg.json"), "reg.json")
        self.assertEqual(seal.normalize_path("a/./b/../reg.json"), "a/reg.json")
        self.assertEqual(seal.normalize_path("reg\\sub.json"), "reg/sub.json")

    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_F7_seal_plain_verify_dot_slash_roundtrips(self):
        self.open_sign()
        rev = self.key("rev1")
        anchor = self.allowed("real_allowed", "rev1", rev)
        self.assertEqual(self.gs("seal", "--key", rev).returncode, 0)     # sealed as reg.json
        r = self.gs("verify", "--allowed-signers", anchor, registry="./reg.json")
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))


# ── F8: every subprocess call is bounded ─────────────────────────────────────
class TimeoutTest(AttackBase):
    def test_F8_slow_subprocess_is_a_usage_error_not_a_hang(self):
        from gatesmith import seal
        shim_dir = self.path("bin")
        os.makedirs(shim_dir, exist_ok=True)
        # A PORTABLE shim (G3): the old one was a `#!/bin/sh` script, which never
        # runs on Windows. This one re-invokes the running interpreter and sleeps,
        # so the bounded `_run` timeout is what stops it, on any OS.
        if os.name == "nt":
            shim = os.path.join(shim_dir, "ssh-keygen.bat")
            body = f'@echo off\r\n"{sys.executable}" -c "import time; time.sleep(5)"\r\n'
        else:
            shim = os.path.join(shim_dir, "ssh-keygen")
            body = f"#!{sys.executable}\nimport time\ntime.sleep(5)\n"
        with open(shim, "w", encoding="utf-8", newline="") as handle:
            handle.write(body)
        if os.name == "posix":                       # the exec bit is POSIX-only
            os.chmod(shim, 0o755)
        reg = self.path(REG)
        with open(reg, "w", encoding="utf-8") as handle:
            json.dump({"gatesmith_registry": {"v": 2}, "reviews": []}, handle)
        key = self.path("dummy-key")
        with open(key, "w", encoding="utf-8") as handle:
            handle.write("not-a-real-key\n")
        old_path = os.environ.get("PATH", "")
        old_timeout = seal.SUB_TIMEOUT
        os.environ["PATH"] = shim_dir + os.pathsep + old_path
        seal.SUB_TIMEOUT = 0.5
        started = time.monotonic()
        try:
            code, detail = seal.seal(reg, [], key)
        finally:
            seal.SUB_TIMEOUT = old_timeout
            os.environ["PATH"] = old_path
        self.assertEqual(code, 2, detail)
        self.assertIn("timed out", detail)
        self.assertLess(time.monotonic() - started, 4.0)   # did not hang on the 5s sleep


# ── F9: seal I/O is fail-closed ──────────────────────────────────────────────
class IoFailClosedTest(AttackBase):
    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    @unittest.skipUnless(os.name == "posix",
                         "a chmod(0o500) read-only DIRECTORY is a no-op on Windows (G3)")
    def test_F9_readonly_registry_dir_exits_2_cleanly(self):
        self.open_sign()
        rev = self.key("rev1")            # created before the dir goes read-only
        os.chmod(self.work, 0o500)
        try:
            r = self.gs("seal", "--key", rev)
        finally:
            os.chmod(self.work, 0o700)
        self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
        self.assertIn("SEAL-FAILED", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
