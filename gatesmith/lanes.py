"""Guarded parallel lanes.

Makes worktree parallelism a mechanism instead of a hope. Each lane registers
the files it owns before it starts; a tripwire refuses a second lane that would
touch a file another active lane owns, a file held uncommitted in the shared
tree, or a frozen path. A manifest records what the lane changed against the
shared branch, and a reviewer signs it before the lane merges.

The frozen check is an in-process call into :mod:`gatesmith.frozen` — it used
to shell out to a separate script whose path silently vanished after
repackaging, which made the guard fail open and every frozen test pass
vacuously. There is no path to miss now.

Commands
--------
  check   --lane L --owned FILE[,FILE ...] --repo P
  start   --lane L --branch B --base B --repo P [--worktree W] [--owner R] --owned ...
  claim   --lane L --owned FILE[,FILE ...] --repo P
  list
  manifest --lane L --repo P [--base B]
  signoff --lane L --reviewer R --verdict pass|block [--note TEXT]
  close   --lane L [--only-active] [--status merged|closed]
  worktrees --repo P [--json] [--out FILE]

Exit codes: 0 clear / success, 1 block / failure, 2 usage.
"""

import datetime
import os
import subprocess
import sys

from . import config, frozen, store, worktree

DEFAULT_REGISTRY = "./lane-registry.json"
DEFAULT_FROZEN = "./FROZEN-registry.json"
ACTIVE = {"active", "in_progress", "working"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _registry(args):
    return config.get(args, "lanes", "registry", DEFAULT_REGISTRY)


def _frozen_registry(args):
    return config.get(args, "lanes", "frozen_registry", DEFAULT_FROZEN)


def load_reg(path):
    return store.load_json(path, {"lanes": []})


def save_reg(path, reg):
    store.save_json(path, reg)


def lane_by_id(reg, lane_id):
    for lane in reg.get("lanes", []):
        if lane["id"] == lane_id:
            return lane
    return None


def _git(repo, *argv):
    return subprocess.run(["git", "-C", repo, *argv], capture_output=True, text=True,
                          timeout=30)


def _uncommitted_in(repo):
    """Files with uncommitted changes in the shared working tree."""
    if not os.path.isdir(repo):
        return set()
    try:
        out = subprocess.run(["git", "-C", repo, "status", "--porcelain"],
                             capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return set()
    files = set()
    for line in out.splitlines():
        if line[:1] in ("R", "C"):
            files.add(line.split(" -> ")[-1].strip())
            continue
        path = line[3:].strip().strip('"')
        if path:
            files.add(path)
    return files


def _frozen_blockers(owned, registry):
    """Owned files that a frozen registry claims.

    A missing registry declares no freezes; an unreadable one is a broken
    instrument and blocks, because reading it as empty is exactly how the guard
    would fail open.
    """
    if not owned or not os.path.isfile(registry):
        return []
    try:
        items = frozen.load_items(registry)
    except store.RegistryError as exc:
        return [f"FROZEN-REGISTRY-INVALID: {exc} — refusing to treat an unreadable freeze list as empty"]
    return [f"FROZEN-BLOCKED: {path} (owned by frozen item {item_id} — {area})"
            for path, item_id, area in frozen.blocked_files(items, owned)]


def _blockers(reg, lane_id, owned, repo, frozen_registry):
    """Every reason this lane may not touch ``owned`` right now."""
    problems = _frozen_blockers(owned, frozen_registry)
    for lane in reg.get("lanes", []):
        if lane["id"] == lane_id or lane.get("status") not in ACTIVE:
            continue
        overlap = sorted(set(owned) & set(lane.get("owned_files", [])))
        if overlap:
            problems.append(f"OWNED-CLASH: lane '{lane['id']}' (branch {lane.get('branch')}) "
                            f"already owns " + ", ".join(overlap))
    clash = sorted(set(owned) & _uncommitted_in(repo))
    if clash:
        problems.append("SHARED-TREE-BUSY: uncommitted changes in the shared repo to "
                        + ", ".join(clash) + " (another session owns that tree — use a worktree)")
    return problems


def _report_block(problems):
    for problem in problems:
        print(f"BLOCK: {problem}", file=sys.stderr)
    print(f"RESULT: BLOCK ({len(problems)} problem(s))")
    return 1


def cmd_check(args):
    reg = load_reg(_registry(args))
    owned = sorted(args.owned or [])
    problems = _blockers(reg, args.lane, owned, args.repo, _frozen_registry(args))
    if problems:
        return _report_block(problems)
    print(f"RESULT: CLEAR — lane '{args.lane}' may proceed ({len(owned)} owned file(s) free)")
    return 0


def cmd_start(args):
    if not args.owned:
        print("start requires at least one --owned file", file=sys.stderr)
        return 2
    registry = _registry(args)
    reg = load_reg(registry)
    for lane in reg.get("lanes", []):
        if lane["id"] == args.lane and lane.get("status") in ACTIVE:
            print(f"lane '{args.lane}' already active", file=sys.stderr)
            return 1
    owned = sorted(args.owned)
    problems = _blockers(reg, args.lane, owned, args.repo, _frozen_registry(args))
    if problems:
        return _report_block(problems)
    reg.setdefault("lanes", []).append({
        "id": args.lane,
        "branch": args.branch or "",
        "base": args.base or "",
        "worktree": args.worktree or "",
        "owner": args.owner or "",
        "owned_files": owned,
        "status": "active",
        "started": now(),
        "manifest": {"changed_files": [], "unowned_changed": [], "baseline_moves": [],
                     "reviewer": None, "signoff": "pending", "notes": ""},
    })
    save_reg(registry, reg)
    print(f"lane '{args.lane}' registered as active; {len(owned)} owned file(s)")
    return 0


def cmd_claim(args):
    registry = _registry(args)
    reg = load_reg(registry)
    matches = [lane for lane in reg.get("lanes", [])
               if lane["id"] == args.lane and lane.get("status") in ACTIVE]
    if len(matches) != 1:
        print(f"lane '{args.lane}' requires exactly one active record; found {len(matches)}",
              file=sys.stderr)
        return 1
    lane = matches[0]
    new_owned = sorted(set(args.owned or []) - set(lane.get("owned_files", [])))
    if not new_owned:
        print(f"lane '{args.lane}' already owns all requested files")
        return 0
    problems = _blockers(reg, args.lane, new_owned, args.repo, _frozen_registry(args))
    if problems:
        return _report_block(problems)
    lane["owned_files"] = sorted(set(lane.get("owned_files", [])) | set(new_owned))
    save_reg(registry, reg)
    print(f"lane '{args.lane}' claimed {len(new_owned)} owned file(s)")
    return 0


def cmd_list(args):
    reg = load_reg(_registry(args))
    active = [lane for lane in reg.get("lanes", []) if lane.get("status") in ACTIVE]
    if not active:
        print("no active lanes")
        return 0
    for lane in active:
        print(f"{lane['id']}  [{lane.get('status')}]  branch={lane.get('branch')}  "
              f"owner={lane.get('owner')}  owned={len(lane.get('owned_files', []))}")
        for path in lane.get("owned_files", []):
            print(f"    - {path}")
    return 0


def _blank_manifest():
    return {"changed_files": [], "unowned_changed": [], "baseline_moves": [],
            "reviewer": None, "signoff": "pending", "notes": ""}


def cmd_manifest(args):
    registry = _registry(args)
    reg = load_reg(registry)
    lane = lane_by_id(reg, args.lane)
    if not lane:
        print(f"no such lane '{args.lane}'", file=sys.stderr)
        return 1
    branch = lane.get("branch") or args.lane
    base = args.base or lane.get("base")
    if not base:
        print("no base branch — pass --base or start the lane with --base", file=sys.stderr)
        return 2
    repo = args.repo
    if not os.path.isdir(repo):
        print(f"repo '{repo}' not found — cannot diff", file=sys.stderr)
        return 1
    merge_base = _git(repo, "merge-base", base, branch)
    if merge_base.returncode != 0:
        print(f"no merge-base between {base} and {branch}", file=sys.stderr)
        return 1
    diff = _git(repo, "diff", "--name-status", merge_base.stdout.strip(), branch)
    changed, baseline = set(), []
    owned = set(lane.get("owned_files", []))
    for line in diff.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        path = parts[-1]
        changed.add(path)
        # A deletion or rename is a baseline move: it changes the ground other
        # lanes build on, so it needs a named reason from the reviewer.
        if status.startswith(("D", "R")):
            baseline.append(f"{status}\t{path}")
    unowned = sorted(changed - owned)
    manifest = lane.setdefault("manifest", _blank_manifest())
    manifest.update({
        "changed_files": sorted(changed),
        "unowned_changed": unowned,
        "baseline_moves": sorted(baseline),
    })
    save_reg(registry, reg)
    print(f"manifest for lane '{args.lane}' (vs {base}):")
    print(f"  changed: {len(changed)}  owned-unchanged: {len(owned - changed)}")
    if unowned:
        print("  !! UNOWNED CHANGED (drift — reviewer must approve):")
        for path in unowned:
            print(f"      - {path}")
    for move in baseline:
        print(f"  baseline-move: {move} (needs a named reason)")
    print(f"  reviewer-signoff: {manifest.get('signoff', 'pending')}")
    return 0


def cmd_signoff(args):
    registry = _registry(args)
    reg = load_reg(registry)
    lane = lane_by_id(reg, args.lane)
    if not lane:
        print(f"no such lane '{args.lane}'", file=sys.stderr)
        return 1
    manifest = lane.setdefault("manifest", _blank_manifest())
    manifest["reviewer"] = args.reviewer
    manifest["signoff"] = args.verdict
    if args.note:
        manifest["notes"] = args.note
    save_reg(registry, reg)
    print(f"lane '{args.lane}' reviewer-signoff: {args.verdict} by {args.reviewer}")
    return 0


def cmd_close(args):
    registry = _registry(args)
    reg = load_reg(registry)
    matches = [lane for lane in reg.get("lanes", []) if lane["id"] == args.lane]
    if args.only_active:
        matches = [lane for lane in matches if lane.get("status") in ACTIVE]
        label = "active record"
    else:
        label = "matching record"
    if len(matches) != 1:
        print(f"lane '{args.lane}' requires exactly one {label}; found {len(matches)}",
              file=sys.stderr)
        return 1
    lane = matches[0]
    lane["status"] = args.status or "merged"
    lane["closed"] = now()
    save_reg(registry, reg)
    print(f"lane '{args.lane}' closed ({lane['status']}); owned files freed")
    return 0


def add_parser(subparsers):
    parser = subparsers.add_parser("lanes", help="file-set ownership, shared-tree and worktree discipline")
    parser.add_argument("--registry", default=None,
                        help=f"lane registry (default: {DEFAULT_REGISTRY})")
    parser.add_argument("--frozen-registry", default=None,
                        help=f"frozen-paths registry (default: {DEFAULT_FROZEN})")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("check")
    p.add_argument("--lane", required=True)
    p.add_argument("--owned", action="append")
    p.add_argument("--repo", required=True)
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("start")
    p.add_argument("--lane", required=True)
    p.add_argument("--branch", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--worktree", default="")
    p.add_argument("--owner", default="")
    p.add_argument("--owned", action="append")
    p.add_argument("--repo", required=True)
    p.set_defaults(fn=cmd_start)

    p = sub.add_parser("claim")
    p.add_argument("--lane", required=True)
    p.add_argument("--owned", action="append", required=True)
    p.add_argument("--repo", required=True)
    p.set_defaults(fn=cmd_claim)

    p = sub.add_parser("list")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("manifest")
    p.add_argument("--lane", required=True)
    p.add_argument("--base", default=None, help="override the lane's recorded base branch")
    p.add_argument("--repo", required=True)
    p.set_defaults(fn=cmd_manifest)

    p = sub.add_parser("signoff")
    p.add_argument("--lane", required=True)
    p.add_argument("--reviewer", required=True)
    p.add_argument("--verdict", required=True, choices=["pass", "block"])
    p.add_argument("--note")
    p.set_defaults(fn=cmd_signoff)

    p = sub.add_parser("close")
    p.add_argument("--lane", required=True)
    p.add_argument("--only-active", action="store_true")
    p.add_argument("--status", choices=["merged", "closed"])
    p.set_defaults(fn=cmd_close)

    p = sub.add_parser("worktrees", help="read-only worktree audit")
    p.add_argument("--repo", required=True)
    p.add_argument("--json", action="store_true", help="print rows as JSON")
    p.add_argument("--out", help="also write the rows to this file (mode 0600)")
    p.set_defaults(fn=worktree.command)
    return parser
