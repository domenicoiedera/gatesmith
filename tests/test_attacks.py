"""Permanent tests for the wave-1 fix round: the H1-H5 attacks, ported.

Each method maps to an acceptance criterion F1-F14 / G1-G13 (see the fix
specs). They are
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


def write_slow_shim(shim_dir, interpreter, seconds=5):
    """Write an ``ssh-keygen`` shim that sleeps past any bounded timeout.

    Portable (G3): a ``.bat`` on Windows, a POSIX script elsewhere. Space-safe
    (G13): a shebang cannot carry an interpreter path containing a space — the
    kernel splits it at the first space and fails with ``bad interpreter`` — so
    the POSIX shim indirects through ``/bin/sh``, which QUOTES the path when it
    execs it. The old body (``#!{sys.executable}``) was green only because this
    machine's interpreter path happens to have no space.
    """
    if os.name == "nt":
        shim = os.path.join(shim_dir, "ssh-keygen.bat")
        body = (f'@echo off\r\n"{interpreter}" -c '
                f'"import time; time.sleep({seconds})"\r\n')
    else:
        shim = os.path.join(shim_dir, "ssh-keygen")
        body = ("#!/bin/sh\n"
                f'exec "{interpreter}" -c "import time; time.sleep({seconds})"\n')
    with open(shim, "w", encoding="utf-8", newline="") as handle:
        handle.write(body)
    if os.name == "posix":                       # the exec bit is POSIX-only
        os.chmod(shim, 0o755)
    return shim


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
        # A PORTABLE shim (G3: `.bat` on Windows, POSIX script elsewhere) that
        # re-invokes the running interpreter and sleeps, so the bounded `_run`
        # timeout — not the shim — is what stops it. Space-safe (G13).
        write_slow_shim(shim_dir, sys.executable, seconds=5)
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
        # The BOUND is what stops it, and that fired above (hard error 2). The
        # wall clock is not portable: on POSIX the killed child releases its
        # stdout pipe at once, but on Windows the shim is a `.bat` whose own
        # child holds the inherited pipe until the sleep ends — so the elapsed
        # time includes that tail even though the timeout already fired. Keep a
        # real bound per platform rather than asserting a Windows artifact.
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 4.0 if os.name == "posix" else 9.0)

    @unittest.skipUnless(os.name == "posix", "POSIX shebang semantics (G13)")
    def test_G13_posix_shim_survives_a_space_in_the_interpreter_path(self):
        """A raw ``#!{interpreter}`` shim dies if the path has a space (G13).

        We build the shim against an interpreter path that CONTAINS A SPACE (a
        symlink to the running interpreter). The old body
        (``#!{sys.executable}``) would split at the first space and fail with
        ``bad interpreter``; the ``/bin/sh`` indirection quotes the path and
        runs it. This is discriminating on a machine whose real interpreter path
        has no space, because the sampled path here does.
        """
        spaced = self.path("sp ace")
        os.makedirs(spaced, exist_ok=True)
        interp = os.path.join(spaced, "python")
        os.symlink(sys.executable, interp)
        shim_dir = self.path("g13bin")
        os.makedirs(shim_dir, exist_ok=True)
        shim = write_slow_shim(shim_dir, interp, seconds=0)
        r = subprocess.run([shim], capture_output=True, shell=False,
                           encoding="utf-8", errors="replace", timeout=30)
        self.assertEqual(r.returncode, 0, (shim, r.stdout, r.stderr))
        self.assertNotIn("bad interpreter", r.stderr)


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


# ── G9: list/lookup must bind the sealing principal to the ENTRY's reviewer ──
class InformationalBindingTest(AttackBase):
    """The surviving G1 false-oracle variant: ``list``/``lookup`` routed through
    ``_seal_label`` with a hard-coded ``reviewer=None``, so they printed a bare
    ``seal: VERIFIED`` where the gate BLOCKED on the principal→reviewer binding.
    These tests exercise BOTH verbs (round 2 tested only ``status``) plus the
    wildcard-principal trigger."""

    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_G9_bound_reviewer_is_reported_as_binding(self):
        rev1 = self.key("rev1")
        anchor = self.allowed("real_allowed", "rev1", rev1)
        self.open_sign()                          # reviewer 'rev1' == sealing principal
        self.assertEqual(self.gs("seal", "--key", rev1).returncode, 0)
        listing = self.gs("list", "--all", "--allowed-signers", anchor)
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertIn("VERIFIED (principal=rev1; binds reviewer rev1)", listing.stdout)

    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_G9_list_and_lookup_do_not_claim_verified_when_the_reviewer_is_unbound(self):
        rev1 = self.key("rev1")
        anchor = self.allowed("real_allowed", "rev1", rev1)
        self.assertEqual(self.gs("open", "--id", "r1", "--executor", "backend",
                                 "--change", "x", "--diff-sha", "abcd1234").returncode, 0)
        # reviewer 'rev2' is NOT the sealing principal 'rev1' — the gate blocks.
        self.assertEqual(self.gs("sign", "--id", "r1", "--reviewer", "rev2",
                                 "--verdict", "pass").returncode, 0)
        self.assertEqual(self.gs("seal", "--key", rev1).returncode, 0)
        gate = self.gs("gate", "--id", "r1", "--target", "push", "--allowed-signers", anchor)
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))
        self.assertIn("sealing principal", gate.stderr)
        expected = ("seal: signature valid (principal=rev1) — "
                    "does NOT bind reviewer 'rev2'")
        # `list --all`, `list` (which HIDES the done entry — a filter must not
        # smuggle the bare VERIFIED back), and `lookup`:
        for verb in (("list", "--all"), ("list",), ("lookup", "--diff-sha", "abcd1234")):
            r = self.gs(*verb, "--allowed-signers", anchor)
            self.assertEqual(r.returncode, 0, (verb, r.stdout, r.stderr))
            self.assertIn(expected, r.stdout, verb)
            self.assertNotIn("seal: VERIFIED", r.stdout, verb)

    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_G9_wildcard_principal_does_not_bind_a_named_reviewer(self):
        rev1 = self.key("rev1")
        with open(rev1 + ".pub", encoding="utf-8") as handle:
            pub = handle.read().strip()
        wild = self.path("wild")
        with open(wild, "w", encoding="utf-8") as handle:
            handle.write(f"* {pub}\n")            # principal literally '*'
        self.assertEqual(self.gs("open", "--id", "r1", "--executor", "backend",
                                 "--change", "x", "--diff-sha", "deadbeef").returncode, 0)
        self.assertEqual(self.gs("sign", "--id", "r1", "--reviewer", "rev1",
                                 "--verdict", "pass").returncode, 0)
        self.assertEqual(self.gs("seal", "--key", rev1).returncode, 0)
        gate = self.gs("gate", "--id", "r1", "--target", "push", "--allowed-signers", wild)
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))
        self.assertIn("sealing principal", gate.stderr)
        for verb in (("list", "--all"), ("lookup", "--diff-sha", "deadbeef")):
            r = self.gs(*verb, "--allowed-signers", wild)
            self.assertEqual(r.returncode, 0, (verb, r.stdout, r.stderr))
            self.assertIn("does NOT bind reviewer 'rev1'", r.stdout, verb)
            self.assertNotIn("seal: VERIFIED", r.stdout, verb)


# ── G10: a bounded git that hangs is exit 2, never a traceback or a 1 ────────
class GitTimeoutTest(AttackBase):
    @unittest.skipUnless(os.name == "posix", "POSIX shell shim (G10)")
    def test_G10_a_hung_git_is_a_hard_error_exit_2_never_a_traceback(self):
        """``subprocess.TimeoutExpired`` is a ``SubprocessError``, NOT an
        ``OSError``; before G10 the ``timeout=30`` added to ``evidence.git``
        raised it straight past ``cli.main``'s handlers — an uncaught traceback
        and exit 1 (which a caller reads as "blocked"). It must exit 2."""
        from gatesmith import cli, evidence
        shim_dir = self.path("bin")
        os.makedirs(shim_dir, exist_ok=True)
        shim = os.path.join(shim_dir, "git")
        with open(shim, "w", encoding="utf-8", newline="") as handle:
            handle.write("#!/bin/sh\nexec sleep 5\n")
        os.chmod(shim, 0o755)
        repo = self.path("repo")
        os.makedirs(repo, exist_ok=True)
        old_path = os.environ.get("PATH", "")
        old_timeout = evidence.GIT_TIMEOUT
        os.environ["PATH"] = shim_dir + os.pathsep + old_path
        evidence.GIT_TIMEOUT = 0.5
        try:
            code = cli.main(["evidence", "--repo", repo, "--base", "base", "--branch", "b"])
        finally:
            evidence.GIT_TIMEOUT = old_timeout
            os.environ["PATH"] = old_path
        self.assertEqual(code, 2, "a hung git must exit 2, not 1 or a traceback")


# ── G11: a CLOSED review is blocked in EVERY reporting verb ──────────────────
class ClosedReviewTest(AttackBase):
    def test_G11_a_closed_review_is_blocked_in_every_reporting_verb(self):
        self.assertEqual(self.gs("open", "--id", "r1", "--executor", "backend",
                                 "--change", "x", "--diff-sha", "f00d").returncode, 0)
        self.assertEqual(self.gs("sign", "--id", "r1", "--reviewer", "rev1",
                                 "--verdict", "pass").returncode, 0)
        self.assertEqual(self.gs("close", "--id", "r1", "--note", "superseded").returncode, 0)
        # status (no anchor) must NOT say OPEN once the review is closed
        status = self.gs("status", "--id", "r1")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("GATE: BLOCKED", status.stdout)
        self.assertIn("closed", status.stdout.lower())
        self.assertNotIn("GATE: OPEN", status.stdout)
        # list / lookup never present the closed entry as gating
        listing = self.gs("list", "--all")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertIn("r1: [closed]", listing.stdout)
        self.assertIn("does not gate", listing.stdout)
        lookup = self.gs("lookup", "--diff-sha", "f00d")
        self.assertEqual(lookup.returncode, 0, lookup.stderr)
        self.assertIn("r1: [closed]", lookup.stdout)
        self.assertIn("does not gate", lookup.stdout)
        # and the enforced gate agrees
        gate = self.gs("gate", "--id", "r1", "--target", "push")
        self.assertEqual(gate.returncode, 1, gate.stderr)
        self.assertIn("CLOSED", gate.stderr)


# ── G12: pin the informational exit taxonomy (0 readable / 2 unreadable) ─────
class InformationalTaxonomyTest(AttackBase):
    def test_G12_informational_verbs_exit_2_when_the_artifact_is_unreadable(self):
        for rid in ("r1", "r2"):
            self.assertEqual(self.gs("open", "--id", rid, "--executor", "backend",
                                     "--change", "x").returncode, 0)
        with open(self.path(REG), encoding="utf-8") as handle:
            reg = json.load(handle)
        reg["reviews"][0]["change"] = "TAMPER-NO-RESTAMP"     # break the chain
        with open(self.path(REG), "w", encoding="utf-8") as handle:
            json.dump(reg, handle, indent=2)
        for verb in (("status", "--id", "r1"), ("list",), ("lookup", "--diff-sha", "x")):
            r = self.gs(*verb)
            self.assertEqual(r.returncode, 2, (verb, r.stdout, r.stderr))
            self.assertNotIn("Traceback", r.stderr, verb)
            self.assertIn("chain broken", r.stderr, verb)
        # the DECISION verb (gate) still blocks with 1 — the class split is real
        gate = self.gs("gate", "--id", "r1", "--target", "push")
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))

    def test_G12_docstring_states_the_taxonomy_not_always_zero(self):
        from gatesmith import review
        doc = review.__doc__ or ""
        self.assertNotIn("always 0", doc)
        self.assertIn("INFORMATIONAL", doc)
        self.assertIn("cannot be read", doc)


# ── F13: `verify` states its scope; a 0 is not an admission decision ─────────
class VerifyScopeTest(AttackBase):
    """`verify` answers chain+seal only. For a registry whose reviewer the seal
    does not bind, `gate` blocks (1) while `verify` still exits 0 — so its
    OUTPUT must say admission was not evaluated and name how many held entries
    would NOT bind, or a caller using `verify` as a pre-check reads a false
    green. (F13.)"""

    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_F13_verify_states_scope_and_the_unbound_binding(self):
        rev1 = self.key("rev1")
        anchor = self.allowed("real_allowed", "rev1", rev1)
        self.assertEqual(self.gs("open", "--id", "r1", "--executor", "backend",
                                 "--change", "x", "--diff-sha", "d1").returncode, 0)
        self.assertEqual(self.gs("sign", "--id", "r1", "--reviewer", "rev2",
                                 "--verdict", "pass").returncode, 0)
        self.assertEqual(self.gs("seal", "--key", rev1).returncode, 0)
        # the enforced gate blocks on the principal→reviewer binding...
        gate = self.gs("gate", "--id", "r1", "--target", "push",
                       "--allowed-signers", anchor)
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))
        self.assertIn("does not bind", gate.stderr)
        # ...verify still exits 0 (chain+seal), but must NOT read as a green light
        verified = self.gs("verify", "--allowed-signers", anchor)
        self.assertEqual(verified.returncode, 0, (verified.stdout, verified.stderr))
        self.assertIn("chain: sound", verified.stdout)
        self.assertIn("seal: valid (principal=rev1)", verified.stdout)
        self.assertIn("ADMISSION: not evaluated — run 'gate'", verified.stdout)
        self.assertIn("entries: 1, of which 1 would NOT bind — the gate will block those entries",
                      verified.stdout)
        # never the old, admission-shaped "verify OK" line
        self.assertNotIn("verify OK", verified.stdout)

    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_F13_verify_scope_when_every_held_reviewer_is_bound(self):
        rev1 = self.key("rev1")
        anchor = self.allowed("real_allowed", "rev1", rev1)
        self.open_sign(reviewer="rev1")                     # reviewer == principal
        self.assertEqual(self.gs("seal", "--key", rev1).returncode, 0)
        self.assertEqual(self.gs("gate", "--id", "r1", "--target", "push",
                                 "--allowed-signers", anchor).returncode, 0)
        verified = self.gs("verify", "--allowed-signers", anchor)
        self.assertEqual(verified.returncode, 0, (verified.stdout, verified.stderr))
        # still names the scope, but no "would NOT bind" clause when none would
        self.assertIn("ADMISSION: not evaluated — run 'gate'", verified.stdout)
        self.assertNotIn("would NOT bind", verified.stdout)


# ── F14: an entry with no reviewer is UNBINDABLE, never a bare VERIFIED ───────
class EmptyReviewerTest(AttackBase):
    """`sign --reviewer ""` leaves the entry with no reviewer; `gate` blocks
    ("has no reviewer"), so no reporting verb may print a bare
    `seal: VERIFIED` for it — it must say there is no reviewer to bind and that
    the gate will block. (F14.)"""

    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_F14_empty_reviewer_entry_is_unbindable_not_bare_verified(self):
        rev1 = self.key("rev1")
        anchor = self.allowed("real_allowed", "rev1", rev1)
        self.assertEqual(self.gs("open", "--id", "r1", "--executor", "backend",
                                 "--change", "x", "--diff-sha", "d1").returncode, 0)
        self.assertEqual(self.gs("sign", "--id", "r1", "--reviewer", "",
                                 "--verdict", "pass").returncode, 0)
        self.assertEqual(self.gs("seal", "--key", rev1).returncode, 0)
        gate = self.gs("gate", "--id", "r1", "--target", "push",
                       "--allowed-signers", anchor)
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))
        self.assertIn("has no reviewer", gate.stderr)
        for verb in (("list", "--all"), ("lookup", "--diff-sha", "d1")):
            r = self.gs(*verb, "--allowed-signers", anchor)
            self.assertEqual(r.returncode, 0, (verb, r.stdout, r.stderr))
            lines = [ln for ln in r.stdout.splitlines() if ln.startswith("seal: ")]
            self.assertEqual(len(lines), 1, (verb, r.stdout))
            self.assertIn("no reviewer on this entry to bind — gate will block",
                          lines[0], verb)
            # the bare form the old renderer printed is gone
            self.assertNotEqual(lines[0], "seal: VERIFIED (principal=rev1)", verb)


# ── F15: `verify --signer` must not assert a verdict the gate won't reach ────
class VerifySignerScopeTest(AttackBase):
    """``--signer`` narrows the principals ``verify`` validated, but the gate
    evaluates ALL matched principals. With an aliased anchor (two principals on
    one key) the narrowed view reports an entry unbound while the unrestricted
    gate ADMITS — so ``verify --signer`` must name the restriction instead of
    asserting "gate will block". A false block is still a false statement.
    (Round-5 re-attack, Finding A.)"""

    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_F15_verify_signer_narrowing_does_not_assert_the_gates_verdict(self):
        key = self.key("k1")
        anchor = self.allowed("aliased_allowed", "rev1,rev2", key)
        self.assertEqual(self.gs("open", "--id", "r1", "--executor", "backend",
                                 "--change", "x", "--diff-sha", "d1").returncode, 0)
        self.assertEqual(self.gs("sign", "--id", "r1", "--reviewer", "rev2",
                                 "--verdict", "pass").returncode, 0)
        self.assertEqual(self.gs("seal", "--key", key).returncode, 0)
        # the unrestricted gate ADMITS: rev2 is among the matched principals
        gate = self.gs("gate", "--id", "r1", "--target", "push",
                       "--allowed-signers", anchor)
        self.assertEqual(gate.returncode, 0, (gate.stdout, gate.stderr))
        # narrowed to rev1: verify must NOT claim the gate will block
        verified = self.gs("verify", "--allowed-signers", anchor,
                           "--signer", "rev1")
        self.assertEqual(verified.returncode, 0, (verified.stdout, verified.stderr))
        self.assertNotIn("gate will block", verified.stdout)
        self.assertIn("would NOT bind --signer 'rev1'", verified.stdout)
        self.assertIn("the gate evaluates all matched principals", verified.stdout)


# ── F16: the shipped CLI must report the version it ships ────────────────────
class VersionTest(AttackBase):
    """``gatesmith --version`` and ``gatesmith.__version__`` must agree with
    ``pyproject.toml``. An output that contradicts the release it ships is the
    same class of defect as a verb that overclaims — the version lives in two
    files, so it is pinned rather than remembered. (Round-5 Finding F1.)"""

    def test_F16_version_matches_pyproject_and_the_cli(self):
        import re
        from gatesmith import __version__
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
            pyproject = handle.read()
        match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
        self.assertIsNotNone(match, "no version in pyproject.toml")
        assert match is not None                      # narrow for the type checker
        expected = match.group(1)
        self.assertEqual(__version__, expected)
        out = subprocess.run([sys.executable, "-m", "gatesmith", "--version"],
                             cwd=self.work, env=self.env, capture_output=True,
                             shell=False, encoding="utf-8", errors="replace",
                             timeout=30)
        self.assertEqual(out.returncode, 0, (out.stdout, out.stderr))
        self.assertIn(expected, out.stdout)


# ── F17: the output bytes must not depend on the host code page ──────────────
class OutputEncodingTest(AttackBase):
    """Windows defaults stdout to the ANSI code page, so the ``·``/``—``
    separators were written as cp1252 bytes and every UTF-8 consumer saw U+FFFD
    — the same command produced different output per platform (found by the CI
    matrix, 4/4 Windows jobs red while macOS/Linux were green). ``PYTHONIOENCODING``
    reproduces the Windows condition on any host, so this guard runs everywhere.
    (Round-7.)"""

    def test_F17_output_is_utf8_even_when_the_host_code_page_is_not(self):
        env = dict(self.env)
        env["PYTHONIOENCODING"] = "cp1252"     # the Windows default in CI
        opened = self.gs("open", "--id", "r1", "--executor", "backend",
                         "--change", "x", env=env)
        self.assertEqual(opened.returncode, 0, (opened.stdout, opened.stderr))
        self.assertNotIn("\ufffd", opened.stdout)
        self.assertIn("—", opened.stdout)      # the em dash survives the trip
        status = self.gs("status", "--id", "r1", env=env)
        self.assertEqual(status.returncode, 0, (status.stdout, status.stderr))
        self.assertNotIn("\ufffd", status.stdout + status.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
