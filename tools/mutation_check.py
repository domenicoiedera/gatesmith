#!/usr/bin/env python3
"""Falsification harness: prove the load-bearing guards can actually fail.

A validation that cannot fail is a fabrication. This tool disables each guard in
turn, asserts the matching test goes RED, restores the file byte-identically,
asserts it goes GREEN again, and prints the sha256 of the file before and after
the restore. If a guard cannot be falsified this way, the guard or its test is
decoration.

Run:  python3.12 tools/mutation_check.py

Guards covered (G7 extends the original three with the round-2 two; G15 adds the
round-3 three):

  * chain-break detection            (tests.test_chain_seal, A1)
  * principal binding                (tests.test_chain_seal, A4)
  * seal requirement (D1)            (tests.test_attacks, F1)
  * informational seal honesty (G1)  (tests.test_attacks, G1)  <- NEW in round 2
  * shape->2 vs integrity->1 (G2)    (tests.test_attacks, G2)  <- NEW in round 2
  * principal-binding threading (G9) (tests.test_attacks, G9)  <- NEW in round 3
  * closed-status blocking (G11)     (tests.test_attacks, G11) <- NEW in round 3
  * timeout -> exit 2 mapping (G10)  (tests.test_attacks, G10) <- NEW in round 3

Some target tests seal, so ``ssh-keygen`` must be on PATH. Exits 0 only when
every guard goes RED when disabled and GREEN, byte-identical, when restored.
"""

import hashlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (label, relative path, exact original text, mutated text, test id)
MUTATIONS = [
    (
        "chain-break detection",
        "gatesmith/chain.py",
        '        if entry["prev_hash"] != prev:',
        '        if False:  # MUTATION: chain-break detection disabled',
        "tests.test_chain_seal.ChainIntegrityTest."
        "test_A1_content_edit_breaks_the_chain_for_every_verb",
    ),
    (
        "principal binding",
        "gatesmith/review.py",
        '        if reviewer and reviewer not in principals:',
        '        if False:  # MUTATION: principal binding disabled',
        "tests.test_chain_seal.GateEnforcementTest.test_A4_principal_binding",
    ),
    (
        "seal requirement (D1)",
        "gatesmith/review.py",
        '    if not has_seal and not allow_unsealed:',
        '    if False:  # MUTATION: seal requirement disabled',
        "tests.test_attacks.SealRequiredTest.test_F1_executor_never_seals_is_blocked",
    ),
    (
        "informational seal honesty (G1)",
        "gatesmith/review.py",
        '        return ("unverified", NO_ANCHOR_DETAIL, principals)',
        '        return ("verified", NO_ANCHOR_DETAIL, principals)'
        '  # MUTATION: informational seal honesty disabled',
        "tests.test_attacks.InformationalSealTest."
        "test_G1_unverified_seal_is_not_reported_as_verified",
    ),
    (
        "shape->2 vs integrity->1 (G2)",
        "gatesmith/review.py",
        '        raise MalformedRegistryError("registry \'reviews\' must be a list of '
        'JSON objects")',
        '        pass  # MUTATION: shape->2 taxonomy disabled',
        "tests.test_attacks.ExitTaxonomyTest."
        "test_G2_malformed_shapes_exit_2_and_never_0",
    ),
    (
        "principal-binding threading (G9)",
        "gatesmith/review.py",
        '        unbound = [reviewer for reviewer in known if reviewer not in principals]',
        '        unbound = []  # MUTATION: list/lookup binding threading disabled',
        "tests.test_attacks.InformationalBindingTest."
        "test_G9_list_and_lookup_do_not_claim_verified_when_the_reviewer_is_unbound",
    ),
    (
        "closed-status blocking (G11)",
        "gatesmith/review.py",
        '    if entry["status"] == "closed":\n        return False',
        '    if False:  # MUTATION: closed-status blocking disabled\n        return False',
        "tests.test_attacks.ClosedReviewTest."
        "test_G11_a_closed_review_is_blocked_in_every_reporting_verb",
    ),
    (
        "timeout -> exit 2 mapping (G10)",
        "gatesmith/cli.py",
        '        print(f"gatesmith: timed out — {exc}", file=sys.stderr)\n'
        '        return 2',
        '        raise  # MUTATION: timeout mapping disabled',
        "tests.test_attacks.GitTimeoutTest."
        "test_G10_a_hung_git_is_a_hard_error_exit_2_never_a_traceback",
    ),
]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def run_test(test_id):
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "unittest", "-v", test_id],
        cwd=ROOT, env=env, capture_output=True, shell=False,
        encoding="utf-8", errors="replace", timeout=30)


def main():
    failures = 0
    for label, relpath, original, mutated, test_id in MUTATIONS:
        path = os.path.join(ROOT, relpath)
        with open(path, "rb") as handle:
            before = handle.read()
        before_hash = sha256(before)
        if original.encode("utf-8") not in before:
            print(f"ABORT [{label}]: pattern not found in {relpath}")
            failures += 1
            continue
        green = run_test(test_id)
        if "skipped" in (green.stdout + green.stderr).lower():
            print(f"ABORT [{label}]: {test_id} is SKIPPED here (needs ssh-keygen)")
            failures += 1
            continue
        if green.returncode != 0:
            print(f"ABORT [{label}]: {test_id} is already RED before mutation "
                  f"(exit {green.returncode})")
            failures += 1
            continue
        try:
            with open(path, "wb") as handle:
                handle.write(before.replace(original.encode("utf-8"),
                                            mutated.encode("utf-8"), 1))
            red = run_test(test_id)
        finally:
            with open(path, "wb") as handle:
                handle.write(before)
        with open(path, "rb") as handle:
            after = handle.read()
        after_hash = sha256(after)
        restored = after_hash == before_hash
        green_after = run_test(test_id)          # GREEN again once restored
        ok = red.returncode != 0 and restored and green_after.returncode == 0
        if not ok:
            failures += 1
        print(f"[{'PASS' if ok else 'FAIL'}] guard={label}")
        print(f"        test={test_id}")
        print(f"        disabled -> exit {red.returncode} (RED means non-zero)")
        print(f"        restored -> exit {green_after.returncode} (GREEN means 0)")
        print(f"        restored byte-identical={restored}  "
              f"sha256 before={before_hash}  after={after_hash}")
    print()
    if failures:
        print(f"MUTATION HARNESS: {failures} guard(s) FAILED — a guard did not "
              f"falsify as expected.")
        return 1
    print("MUTATION HARNESS: all guards falsify — RED when disabled, GREEN and "
          "byte-identical when restored.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
