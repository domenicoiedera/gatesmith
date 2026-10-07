"""Pre-review evidence check.

The mechanical facts an independent reviewer checks before signing the review
gate: the diff stays inside its declared ownership, the branch carries a
verification note, no frozen path is touched, and no added line smuggles an
auto-advance marker past review.

Every check is PASS or FAIL. Any FAIL means the reviewer must sign a block, not
a pass. WARN means "look here" — it does not by itself block, but a warning
that fires on the vocabulary of every report is noise that hides the one that
matters, so the classification is narrow on purpose.

Two checks are opt-in and ship off: a marker check (any regexes you choose —
vendor residency, banned imports, whatever your policy is) driven by
``--markers-file``, and the report-path regex used to keep report prose out of
the auto-advance scan.

Usage::

  gatesmith evidence --repo P --base B --branch BR [--owned f,g] \
      [--registry FROZEN-registry.json] [--markers-file markers.txt] \
      [--report-path-regex RX]

Exit codes: 0 all checks pass (may sign pass), 1 at least one FAIL (must
block), 2 usage.
"""

import os
import re
import subprocess

from . import config, frozen

DEFAULT_FROZEN = "./FROZEN-registry.json"

# Auto-advance markers: a change that would move work forward without a human.
AUTOADV = re.compile(r"auto.*(approve|advance)|skip.*review", re.I)

# Paths whose added lines are prose. Quoting a rule is not violating it, so a
# report that documents "nothing auto-advances" must not raise the warning.
DEFAULT_REPORT_PATH = r"(^|/)(docs|reports?)/|\.(md|markdown|rst)$"

VERIFICATION_HINT = re.compile(r"baseline|verified|verify|test|checked|lint|build", re.I)


def added_lines(diff):
    """Yield ``(path, text)`` for every ADDED line.

    Diff headers, hunk markers, and context lines are not additions; reading
    them as additions makes a fix look like the defect it removes.
    """
    path = ""
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            continue
        if raw.startswith("--- ") or raw.startswith("@@") or raw.startswith("diff --git"):
            continue
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        yield path, raw[1:]


def hitl_hits(diff, report_path=None):
    """Added code/config lines carrying an auto-advance marker.

    ``report_path`` is a compiled regex; prose paths are excluded. The marker
    pattern itself is never narrowed — only the input is.
    """
    report_rx = report_path if report_path is not None else re.compile(DEFAULT_REPORT_PATH, re.I)
    return [(path, text) for path, text in added_lines(diff)
            if not report_rx.search(path) and AUTOADV.search(text)]


def marker_hits(diff, patterns):
    """Added lines matching any user-supplied marker regex."""
    return [(path, text) for path, text in added_lines(diff)
            if any(rx.search(text) for rx in patterns)]


def load_markers(path):
    """Compile one regex per line; blank lines and ``#`` comments are skipped."""
    patterns = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(re.compile(line, re.I))
    return patterns


def git(repo, *argv):
    return subprocess.run(["git", "-C", repo, *argv], capture_output=True, text=True)


def _parse_owned(raw):
    parts = raw if isinstance(raw, list) else [raw]
    return [item.strip() for chunk in parts for item in chunk.split(",") if item.strip()]


def cmd_check(args):
    repo = args.repo
    base = args.base
    branch = args.branch
    registry = config.get(args, "evidence", "registry", DEFAULT_FROZEN)
    report_rx = re.compile(
        config.get(args, "evidence", "report_path_regex", DEFAULT_REPORT_PATH), re.I)
    markers_file = config.get(args, "evidence", "markers_file", None)
    owned = _parse_owned(args.owned or [])
    passes, fails, warns = [], [], []

    def check(label, ok, note):
        (passes if ok else fails).append((label, note))
        print(f"{'PASS' if ok else 'FAIL'}  {label} — {note}")

    def warn(label, note):
        warns.append((label, note))
        print(f"WARN  {label} — {note}")

    print("== GATESMITH EVIDENCE RUNBOOK ==")
    print(f"repo={repo}  base={base}  branch={branch}\n")

    merge_base = git(repo, "merge-base", base, branch)
    changed = []
    if merge_base.returncode != 0:
        check("1. diff-in-scope", False, f"no merge-base between {base} and {branch}")
    else:
        sha = merge_base.stdout.strip()
        changed = [line.strip() for line in
                   git(repo, "diff", "--name-only", sha, branch).stdout.splitlines()
                   if line.strip()]

    # 1. diff in scope / ownership
    if merge_base.returncode == 0:
        if not changed:
            warn("1. diff-in-scope", "no changed files vs base — confirm the branch carries the change")
        else:
            outside = [f for f in changed
                       if not any(f == o or f.startswith(o) or o.endswith("/" + f) for o in owned)]
            check("1. diff-in-scope", not outside,
                  "all changed files within declared ownership" if not outside
                  else f"files OUTSIDE ownership: {','.join(outside)}")

    # 2. opt-in markers — off unless a markers file is configured
    if merge_base.returncode == 0 and markers_file:
        diff = git(repo, "diff", merge_base.stdout.strip(), branch).stdout
        hits = marker_hits(diff, load_markers(markers_file))
        if hits:
            warn("2. markers", f"configured marker in {len(hits)} added line(s) — REVIEW MANUALLY")
        else:
            check("2. markers", True, "no configured markers in added lines")

    # 3. verification note
    if merge_base.returncode == 0:
        log = git(repo, "log", f"{merge_base.stdout.strip()}..{branch}", "--oneline").stdout
        if VERIFICATION_HINT.search(log):
            check("3. verification", True, "commits mention a verification step")
        else:
            warn("3. verification", "no verification note in commits — confirm the check ran")

    # 4. frozen paths
    if os.path.isfile(registry):
        items = frozen.load_items(registry)
        hits = frozen.blocked_files(items, changed)
        check("4. frozen", not hits,
              "no changed file is frozen" if not hits
              else f"changed frozen file(s): {','.join(p for p, _, _ in hits)}")
    else:
        warn("4. frozen", f"no frozen registry at {registry}")

    # 5. auto-advance markers in added code
    if merge_base.returncode == 0:
        diff = git(repo, "diff", merge_base.stdout.strip(), branch).stdout
        hits = hitl_hits(diff, report_rx)
        if hits:
            shown = "; ".join(f"{p}: {t.strip()[:60]}" for p, t in hits[:3])
            warn("5. HITL", f"auto-advance marker in {len(hits)} added code line(s) — "
                            f"REVIEW MANUALLY [{shown}]")
        else:
            check("5. HITL", True, "no auto-advance markers in added code lines")

    print()
    if fails:
        print(f"VERDICT: BLOCK — {len(fails)} failing check(s); reviewer must sign --verdict block")
        return 1
    suffix = f"; {len(warns)} warning(s)" if warns else ""
    print(f"VERDICT: PASS ({len(passes)} checks pass{suffix}) — may sign pass")
    return 0


def add_parser(subparsers):
    parser = subparsers.add_parser("evidence", help="pre-review evidence checks; any FAIL must block")
    parser.add_argument("--repo", required=True, help="repository to inspect")
    parser.add_argument("--base", required=True, help="base branch to diff against")
    parser.add_argument("--branch", required=True, help="branch under review")
    parser.add_argument("--owned", action="append",
                        help="declared ownership path or comma-list; repeatable")
    parser.add_argument("--registry", default=None,
                        help=f"frozen-paths registry (default: {DEFAULT_FROZEN})")
    parser.add_argument("--markers-file", default=None,
                        help="opt-in file of regexes, one per line, scanned against added lines")
    parser.add_argument("--report-path-regex", default=None,
                        help="regex of prose paths excluded from the auto-advance scan")
    parser.set_defaults(fn=cmd_check)
    return parser
