#!/usr/bin/env python3
"""Falsification harness: prove the load-bearing guards can actually fail.

A validation that cannot fail is a fabrication. This tool disables each guard in
turn, asserts the matching test goes RED, restores the file byte-identically,
asserts it goes GREEN again, and prints the sha256 of the file before and after
the restore. If a guard cannot be falsified this way, the guard or its test is
decoration.

Run:  python3.12 tools/mutation_check.py

Requires ``ssh-keygen`` on PATH (two of the three target tests seal). Exits 0
only when every guard goes RED when disabled and GREEN, byte-identical, when
restored.
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
        '    if signoff["reviewer"] not in principals:',
        '    if False:  # MUTATION: principal binding disabled',
        "tests.test_chain_seal.GateEnforcementTest.test_A4_principal_binding",
    ),
    (
        "seal requirement (D1)",
        "gatesmith/review.py",
        '    if not has_seal and not allow_unsealed:',
        '    if False:  # MUTATION: seal requirement disabled',
        "tests.test_attacks.SealRequiredTest.test_F1_executor_never_seals_is_blocked",
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
        encoding="utf-8", errors="replace")


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
