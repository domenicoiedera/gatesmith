"""Wave-1 acceptance tests: hash chain + ssh-keygen seal + gate enforcement.

One test per acceptance criterion A1-A8, plus the pinned fixed-vector seal test.
Each test is written to discriminate: it must fail if the guard it targets is
removed. Seal/verify tests are guarded with ``@unittest.skipUnless`` on
``shutil.which("ssh-keygen")`` so the CI matrix stays green on runners without
OpenSSH. No network is used anywhere.

Run: ``python3.12 -m unittest -v tests.test_chain_seal``.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from gatesmith import chain, seal, store  # noqa: E402

HAS_SSH_KEYGEN = shutil.which("ssh-keygen") is not None
GENESIS = "0" * 64

# ── pinned fixed vector (do not regenerate these by hand lightly) ─────────────
# A minimal two-entry registry under the canonical form; the literals below are
# the frozen expected values. If the canonical form or the preimage changes,
# these assertions fail — that is the point.
FV_E1 = {"change": "x", "closed": None, "created": "2026-01-01T00:00:00+00:00",
         "diff_sha": None, "executor": "backend", "id": "r1", "owned": [],
         "signoff": {"at": None, "auto": False, "note": "", "reviewer": None, "verdict": None},
         "status": "open", "tier": "C"}
FV_E2 = {"change": "y", "closed": None, "created": "2026-01-02T00:00:00+00:00",
         "diff_sha": None, "executor": "backend", "id": "r2", "owned": [],
         "signoff": {"at": None, "auto": False, "note": "", "reviewer": None, "verdict": None},
         "status": "open", "tier": "C"}
FV_E1_CANONICAL = ('{"change":"x","closed":null,"created":"2026-01-01T00:00:00+00:00",'
                   '"diff_sha":null,"executor":"backend","id":"r1","owned":[],'
                   '"signoff":{"at":null,"auto":false,"note":"","reviewer":null,"verdict":null},'
                   '"status":"open","tier":"C"}')
FV_E1_HASH = "3f70153c99f39f6c82970630a9dfef96ca005a09da7e5c137557eeb2e5fa1e56"
FV_E2_HASH = "c4351bd4f99cb08616b3b513c35ad8f4fba44bf22ebbbb1008b2c926b02353e3"
FV_HEAD_HASH = "47c67a93d298a3ba1d6643ae43ccd8fb8aa27c756e9e1f9b3791377e9130d03a"
FV_PREIMAGE = ("gatesmith-seal:v1:"
               "47c67a93d298a3ba1d6643ae43ccd8fb8aa27c756e9e1f9b3791377e9130d03a"
               ":2:reg.json")


def sha256_file(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def restamp(entries):
    """Independent re-implementation of the chain stamping, for forgery tests."""
    prev = GENESIS
    for index, entry in enumerate(entries):
        entry["seq"] = index
        entry["prev_hash"] = prev
        body = {k: v for k, v in entry.items() if k not in ("seq", "prev_hash")}
        prev = hashlib.sha256(json.dumps(body, sort_keys=True,
                                         separators=(",", ":")).encode("utf-8")).hexdigest()
    return entries


class ChainSealBase(unittest.TestCase):
    REG = "reg.json"  # relative + cwd=work, so the sealed path component is fixed

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="chainseal-")
        self.env = dict(os.environ)
        self.env["PYTHONPATH"] = ROOT + os.pathsep + self.env.get("PYTHONPATH", "")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def path(self, *parts):
        return os.path.join(self.work, *parts)

    def review(self, *args, env=None, registry=None):
        reg = registry if registry is not None else self.REG
        return subprocess.run(
            [sys.executable, "-m", "gatesmith", "review", "--registry", reg, *args],
            cwd=self.work, env=env or self.env, capture_output=True, shell=False,
            encoding="utf-8", errors="replace", timeout=30)

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

    def load(self):
        with open(self.path(self.REG), encoding="utf-8") as handle:
            return json.load(handle)

    def read_bytes(self):
        with open(self.path(self.REG), "rb") as handle:
            return handle.read()

    def write_bytes(self, blob):
        with open(self.path(self.REG), "wb") as handle:
            handle.write(blob)

    def dump(self, data):
        with open(self.path(self.REG), "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)

    def open_two(self):
        for rid in ("r1", "r2"):
            result = self.review("open", "--id", rid, "--executor", "backend",
                                 "--change", "c-" + rid)
            self.assertEqual(result.returncode, 0, result.stderr)


class ChainIntegrityTest(ChainSealBase):
    # ── A1 ────────────────────────────────────────────────────────────────────
    def test_A1_content_edit_breaks_the_chain_for_every_verb(self):
        """A canonical-content edit (not whitespace/formatting) breaks the chain.

        Entry 0 is edited with a downstream entry present, so the break is
        detected at entry 1 (0-based). Every review verb must exit 2.
        """
        self.open_two()
        original = self.read_bytes()
        before = hashlib.sha256(original).hexdigest()
        data = self.load()
        data["reviews"][0]["change"] = "tampered"   # a canonical field, not reformatting
        self.dump(data)
        tampered = sha256_file(self.path(self.REG))
        self.assertNotEqual(tampered, before)

        verbs = [
            ("status", "--id", "r1"),
            ("list",),
            ("lookup", "--diff-sha", "a" * 64),
            ("open", "--id", "r3", "--executor", "backend", "--change", "z"),
            ("sign", "--id", "r1", "--reviewer", "rev1", "--verdict", "pass"),
            ("close", "--id", "r1", "--note", "n"),
            ("seal", "--key", self.path("no-key")),
        ]
        for verb in verbs:
            result = self.review(*verb)
            self.assertEqual(result.returncode, 2, (verb, result.stdout, result.stderr))
            self.assertIn("chain broken at entry 1", result.stderr, verb)
        # `verify` is a verification verb: a chain failure is a block (1), per D5.
        result = self.review("verify", "--allowed-signers", self.path("no-anchor"))
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
        self.assertIn("chain broken at entry 1", result.stderr)

        # RED -> GREEN: restore the exact bytes; the digest is identical again.
        self.write_bytes(original)
        after = sha256_file(self.path(self.REG))
        self.assertEqual(after, before)
        self.assertEqual(self.review("status", "--id", "r1").returncode, 0)

    # ── A2 ────────────────────────────────────────────────────────────────────
    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_A2_chain_preserving_forgery_is_caught_by_the_seal(self):
        self.open_two()
        self.assertEqual(self.review("sign", "--id", "r1", "--reviewer", "rev1",
                                     "--verdict", "pass").returncode, 0)
        rev1 = self.key("rev1")
        anchor = self.allowed("allowed_real", "rev1", rev1)
        self.assertEqual(self.review("seal", "--key", rev1).returncode, 0)
        # green baseline
        self.assertEqual(self.review("verify", "--allowed-signers", anchor).returncode, 0)
        self.assertEqual(self.review("gate", "--id", "r1", "--target", "push",
                                     "--executor", "backend", "--allowed-signers",
                                     anchor).returncode, 0)
        # forge: edit entry 0 AND recompute seq/prev_hash downstream
        data = self.load()
        data["reviews"][0]["change"] = "MALICIOUS"
        restamp(data["reviews"])
        self.dump(data)
        # chain is now VALID — a chain-only verb clears
        self.assertEqual(self.review("status", "--id", "r1").returncode, 0)
        # ...but the seal was over the old head: it is now invalid
        verify = self.review("verify", "--allowed-signers", anchor)
        self.assertEqual(verify.returncode, 1, verify.stderr)
        self.assertIn("does not match", verify.stderr)
        gate = self.review("gate", "--id", "r1", "--target", "push", "--executor",
                           "backend", "--allowed-signers", anchor)
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))

    # ── A6 ────────────────────────────────────────────────────────────────────
    def test_A6_legacy_and_partial_chain_are_hard_errors(self):
        # (a) a v1 registry (no marker) is never silently accepted
        legacy = {"reviews": [{"id": "r1", "executor": "backend", "change": "x",
                               "owned": [], "tier": "C", "diff_sha": None,
                               "created": "2020-01-01T00:00:00+00:00", "status": "open",
                               "signoff": {"reviewer": None, "verdict": None, "note": "",
                                           "at": None, "auto": False}, "closed": None}]}
        self.dump(legacy)
        result = self.review("status", "--id", "r1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("predates the chain", result.stderr)
        # (b) a v2 marker with a stripped chain field is a BREAK, not "legacy"
        os.remove(self.path(self.REG))
        self.open_two()
        data = self.load()
        del data["reviews"][0]["prev_hash"]
        self.dump(data)
        result = self.review("status", "--id", "r1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("chain broken at entry 0", result.stderr)
        self.assertNotIn("predates", result.stderr)


class GateEnforcementTest(ChainSealBase):
    # ── A3 ────────────────────────────────────────────────────────────────────
    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_A3_gate_blocks_tampered_chain_and_untrusted_anchor(self):
        self.open_two()
        self.assertEqual(self.review("sign", "--id", "r1", "--reviewer", "rev1",
                                     "--verdict", "pass").returncode, 0)
        rev1 = self.key("rev1")
        anchor = self.allowed("allowed_real", "rev1", rev1)
        self.assertEqual(self.review("seal", "--key", rev1).returncode, 0)
        # green: valid chain + trusted anchor
        self.assertEqual(self.review("gate", "--id", "r1", "--target", "push",
                                     "--executor", "backend", "--allowed-signers",
                                     anchor).returncode, 0)
        # (a) tampered registry -> gate exit 1 (not 0, not 2)
        original = self.read_bytes()
        data = self.load()
        data["reviews"][0]["change"] = "tampered"
        self.dump(data)
        gate = self.review("gate", "--id", "r1", "--target", "push", "--executor",
                           "backend", "--allowed-signers", anchor)
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))
        self.assertIn("chain broken", gate.stderr)
        self.write_bytes(original)
        # (b) valid chain + an anchor that does NOT hold the sealing key -> gate 1
        other = self.key("other")
        wrong_anchor = self.allowed("allowed_wrong", "rev1", other)
        gate = self.review("gate", "--id", "r1", "--target", "push", "--executor",
                           "backend", "--allowed-signers", wrong_anchor)
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))

    # ── A4 ────────────────────────────────────────────────────────────────────
    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_A4_principal_binding(self):
        self.assertEqual(self.review("open", "--id", "r1", "--executor", "backend",
                                     "--change", "x").returncode, 0)
        self.assertEqual(self.review("sign", "--id", "r1", "--reviewer", "rev1",
                                     "--verdict", "pass").returncode, 0)
        rev1 = self.key("rev1")
        self.assertEqual(self.review("seal", "--key", rev1).returncode, 0)
        # sealing principal "imposter" != signoff.reviewer "rev1" -> block
        impostor = self.allowed("allowed_impostor", "imposter", rev1)
        gate = self.review("gate", "--id", "r1", "--target", "push", "--executor",
                           "backend", "--allowed-signers", impostor)
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))
        self.assertIn("sealing principal", gate.stderr)
        # green: all three agree (principal == reviewer != executor)
        real = self.allowed("allowed_real", "rev1", rev1)
        self.assertEqual(self.review("gate", "--id", "r1", "--target", "push",
                                     "--executor", "backend", "--allowed-signers",
                                     real).returncode, 0)
        # reviewer == executor is blocked (and cannot even be signed via CLI)
        self.assertEqual(self.review("open", "--id", "r9", "--executor", "rev1",
                                     "--change", "y").returncode, 0)
        self.assertEqual(self.review("sign", "--id", "r9", "--reviewer", "rev1",
                                     "--verdict", "pass").returncode, 1)
        data = self.load()
        entry = [e for e in data["reviews"] if e["id"] == "r9"][0]
        entry["signoff"] = {"reviewer": "rev1", "verdict": "pass", "note": "",
                            "at": "2026-01-01T00:00:00+00:00", "auto": False}
        entry["status"] = "done"
        chain.stamp(data["reviews"])
        self.dump(data)
        gate = self.review("gate", "--id", "r9", "--target", "push", "--executor", "rev1")
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))
        self.assertIn("is the executor", gate.stderr)

    # ── A5 ────────────────────────────────────────────────────────────────────
    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_A5_forged_self_approval_boundary(self):
        rev1 = self.key("rev1")
        mallory = self.key("mallory")
        real_anchor = self.allowed("allowed_real", "rev1", rev1)
        forger_anchor = self.allowed("allowed_forger", "rev1", mallory)
        self.assertEqual(self.review("open", "--id", "r1", "--executor", "attacker",
                                     "--change", "x").returncode, 0)
        self.assertEqual(self.review("sign", "--id", "r1", "--reviewer", "rev1",
                                     "--verdict", "pass").returncode, 0)
        # the forger signs with its own key while claiming reviewer "rev1"
        self.assertEqual(self.review("seal", "--key", mallory).returncode, 0)
        # against the REAL anchor the forger's key is not trusted -> block
        gate = self.review("gate", "--id", "r1", "--target", "push", "--executor",
                           "attacker", "--allowed-signers", real_anchor)
        self.assertEqual(gate.returncode, 1, (gate.stdout, gate.stderr))
        # passing the forger's OWN anchor validates it — the documented boundary
        # (the trust root is external; the gate cannot conjure it)
        gate = self.review("gate", "--id", "r1", "--target", "push", "--executor",
                           "attacker", "--allowed-signers", forger_anchor)
        self.assertEqual(gate.returncode, 0, (gate.stdout, gate.stderr))


class SealRoundTripTest(ChainSealBase):
    # ── A7 ────────────────────────────────────────────────────────────────────
    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_A7_seal_roundtrip_and_failure_modes(self):
        self.open_two()
        self.assertEqual(self.review("sign", "--id", "r1", "--reviewer", "rev1",
                                     "--verdict", "pass").returncode, 0)
        rev1 = self.key("rev1")
        anchor = self.allowed("allowed_real", "rev1", rev1)
        self.assertEqual(self.review("seal", "--key", rev1).returncode, 0)
        # green: round trip
        self.assertEqual(self.review("verify", "--allowed-signers", anchor).returncode, 0)
        # red 1: tampered registry — a chain failure at `verify` is a block (1), D5
        original = self.read_bytes()
        data = self.load()
        data["reviews"][0]["change"] = "tampered"
        self.dump(data)
        result = self.review("verify", "--allowed-signers", anchor)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("chain broken", result.stderr)
        self.write_bytes(original)
        self.assertEqual(self.review("verify", "--allowed-signers", anchor).returncode, 0)
        # red 2: missing .sig sidecar — no seal present is a block (1), D5
        os.remove(self.path(self.REG + ".sig"))
        result = self.review("verify", "--allowed-signers", anchor)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("no seal present", result.stderr)
        # red 3: unreadable anchor (re-seal first, so this is the anchor at fault)
        self.assertEqual(self.review("seal", "--key", rev1).returncode, 0)
        result = self.review("verify", "--allowed-signers", self.path("absent-anchor"))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("allowed_signers", result.stderr)

    # ── A8 ────────────────────────────────────────────────────────────────────
    def test_A8_seal_fails_closed_without_ssh_keygen(self):
        self.assertEqual(self.review("open", "--id", "r1", "--executor", "backend",
                                     "--change", "x").returncode, 0)
        empty_bin = self.path("empty-bin")
        os.makedirs(empty_bin, exist_ok=True)
        dummy_key = self.path("a-key")
        with open(dummy_key, "w", encoding="utf-8") as handle:
            handle.write("not a real key\n")   # exists, so absence is the tool, not the key
        env = dict(self.env)
        env["PATH"] = empty_bin  # ssh-keygen is not on this PATH — simulated, not uninstalled
        result = self.review("seal", "--key", dummy_key, env=env)
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertIn("ssh-keygen", result.stderr)

    # ── A9 ────────────────────────────────────────────────────────────────────
    def test_A9_store_load_json_stays_chain_free(self):
        """The chain must not leak into store.load_json (shared by other gates)."""
        path = self.path("plain.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"anything": 1, "reviews": []}, handle)
        # a marker-less, chain-less registry is still a plain JSON object to store
        self.assertEqual(store.load_json(path, {"d": 1}), {"anything": 1, "reviews": []})


class FixedVectorTest(ChainSealBase):
    def test_fixed_vector_seal_preimage_is_pinned(self):
        self.assertEqual(chain.canonical_bytes(FV_E1).decode("utf-8"), FV_E1_CANONICAL)
        self.assertEqual(chain.entry_hash(FV_E1), FV_E1_HASH)
        self.assertEqual(chain.entry_hash(FV_E2), FV_E2_HASH)
        reviews = [dict(FV_E1, seq=0, prev_hash=GENESIS),
                   dict(FV_E2, seq=1, prev_hash=FV_E1_HASH)]
        self.assertEqual(chain.head_hash(reviews), FV_HEAD_HASH)
        self.assertEqual(seal.preimage(FV_HEAD_HASH, 2, "reg.json"), FV_PREIMAGE)
        # hand-written registry (no CLI): the seal must sign exactly FV_PREIMAGE
        self.dump({"gatesmith_registry": {"v": 2}, "reviews": reviews})
        self.assertEqual(self.review("status", "--id", "r1").returncode, 0)

    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not available")
    def test_fixed_vector_seal_digest_matches_pinned_preimage(self):
        reviews = [dict(FV_E1, seq=0, prev_hash=GENESIS),
                   dict(FV_E2, seq=1, prev_hash=FV_E1_HASH)]
        self.dump({"gatesmith_registry": {"v": 2}, "reviews": reviews})
        key = self.key("vec")
        self.assertEqual(self.review("seal", "--key", key).returncode, 0)
        with open(self.path(self.REG + ".digest"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), FV_PREIMAGE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
