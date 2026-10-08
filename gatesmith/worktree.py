"""Read-only worktree audit.

A report-only inventory of git worktrees: path, branch, HEAD, last-commit age,
clean/dirty, status counts, lane membership, and whether a process is using it.
Each worktree is classified active / candidate-stale-clean /
candidate-stale-dirty / unknown.

Two properties make it safe to run while work is in progress:

* it has no verb that mutates a worktree — no delete, prune, reset, or remove;
* ``unknown`` is never treated as safe to remove, and any probe failure is data
  (an ``unknown`` row), never an exception to the caller. A probe that cannot
  run must not read as "nothing here".
"""

import json
import os
import shutil
import time

from . import proc, store

ACTIVE_WINDOW_SEC = 48 * 3600   # newer than this -> active
STALE_WINDOW_SEC = 7 * 86400    # older than this with nothing else -> stale
DEFAULT_SCHEMA = "gatesmith-worktree-audit/v1"


def _git(repo, *argv):
    """Run git with an argv array — never a shell (via :func:`gatesmith.proc.run`).

    Only the pipe encoding is pinned: on a non-UTF-8 locale (Windows runners
    default to the system code page) git's output would otherwise decode as
    garbage or raise. Everything else — including the system config that
    decides line-ending normalization — must be exactly what the user's own
    git sees, or this tool would disagree with it about what is clean. On
    expiry the direct child is killed without draining its pipes.
    """
    return proc.run(["git", "-C", str(repo), *argv], timeout=30)


def _parse_status_counts(porcelain):
    """Count porcelain-v1 codes; ``X`` is staged, ``Y`` is unstaged."""
    counts = {}
    for line in porcelain.splitlines():
        if not line.strip():
            continue
        x, y = line[0], line[1]
        seen = set()
        if x == "?":
            seen.add("untracked")
        elif x == "!":
            seen.add("ignored")
        else:
            if x == "R" or y == "R":
                seen.add("renamed")
            elif x == "C" or y == "C":
                seen.add("copied")
            if x in ("M", "A", "D", "T"):
                seen.add({"M": "modified", "A": "added", "D": "deleted", "T": "typechange"}[x])
            if y in ("M", "D", "T"):
                seen.add({"M": "modified", "D": "deleted", "T": "typechange"}[y])
        for key in seen:
            counts[key] = counts.get(key, 0) + 1
    return counts


def _last_commit_age(repo, now_ts):
    """Seconds since the newest commit reachable here, or None if unreadable."""
    result = _git(repo, "log", "-1", "--format=%ct")
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return max(0, now_ts - int(result.stdout.strip()))
    except ValueError:
        return None


def _process_in_use(path):
    """Three-state probe: True / False / None (probe failure).

    A missing ``lsof`` or a non-zero exit means "could not tell", which must
    become ``unknown`` — not ``False``, which would let an in-use worktree look
    uninhabited and eligible for cleanup.
    """
    lsof = shutil.which("lsof") or "/usr/sbin/lsof"
    try:
        result = proc.run([lsof, "+D", str(path), "-Fn"], timeout=20)
    except Exception:
        return None
    if result.returncode == 0:
        return bool(result.stdout.strip())
    if result.returncode == 1 and not result.stderr.strip():
        # lsof ran cleanly and found nothing: a real negative, not a failure.
        return False
    return None


def classify(entry, now_ts=None):
    """active / candidate_stale_clean / candidate_stale_dirty / unknown.

    Any activity signal (lane registry, a process in the worktree, a recent
    commit) beats age. ``unknown`` is never safe to remove.
    """
    if entry.get("probe_failed"):
        return "unknown"
    if entry.get("in_lane_registry"):
        return "active"
    process_cwd = entry.get("process_cwd")
    if process_cwd is None:
        return "unknown"
    if process_cwd:
        return "active"
    age = entry.get("last_commit_age_sec")
    if age is None:
        return "unknown"
    if age < ACTIVE_WINDOW_SEC:
        return "active"
    if age >= STALE_WINDOW_SEC:
        return "candidate_stale_dirty" if not entry.get("clean") else "candidate_stale_clean"
    return "active"


def _lane_worktrees(lane_registry):
    """Worktree paths claimed by an active lane, or None if the registry is unreadable."""
    if not lane_registry:
        return set()
    from . import lanes  # local import: lanes imports this module for its worktrees verb
    try:
        data = store.load_json(lane_registry, {"lanes": []})
    except store.RegistryError:
        return None
    claimed = set()
    for lane in data.get("lanes", []):
        if lane.get("status") in lanes.ACTIVE and lane.get("worktree"):
            claimed.add(os.path.realpath(str(lane["worktree"])))
    return claimed


def _iter_worktrees(repo_root):
    """Enumerate worktrees from ``git worktree list --porcelain`` (read-only).

    Returns ``(paths, failed)``: a failed enumeration is flagged rather than
    disguised as a one-worktree census.
    """
    result = _git(repo_root, "worktree", "list", "--porcelain")
    if result.returncode != 0:
        return [str(repo_root)], True
    paths, current = [], {}
    for line in result.stdout.splitlines():
        if line.startswith("worktree "):
            current = {"path": line[len("worktree "):]}
        elif line.startswith("locked") or line.startswith("prunable"):
            current[line.split()[0]] = True
        elif not line.strip() and current:
            paths.append(current["path"])
            current = {}
    if current:
        paths.append(current["path"])
    return paths, False


def audit(repo_root, lane_registry=None, now_ts=None):
    """Inventory every worktree of ``repo_root``. Read-only; returns a list of rows."""
    if now_ts is None:
        now_ts = time.time()
    claimed = _lane_worktrees(lane_registry)
    registry_failed = claimed is None
    claimed = claimed or set()

    rows = []
    worktrees, enum_failed = _iter_worktrees(repo_root)
    for worktree in worktrees:
        real = os.path.realpath(worktree)
        entry = {"path": real, "probe_failed": bool(enum_failed or registry_failed)}
        head = _git(worktree, "rev-parse", "HEAD")
        if head.returncode != 0:
            entry["probe_failed"] = True
            entry.update({"branch": None, "head": None, "last_commit_age_sec": None,
                          "clean": False, "status_counts": {},
                          "in_lane_registry": real in claimed, "process_cwd": None})
            entry["classification"] = classify(entry, now_ts)
            rows.append(entry)
            continue
        entry["head"] = head.stdout.strip()
        branch_result = _git(worktree, "rev-parse", "--abbrev-ref", "HEAD")
        branch = branch_result.stdout.strip() if branch_result.returncode == 0 else None
        entry["branch"] = None if branch in (None, "", "HEAD") else branch
        entry["detached"] = branch == "HEAD"
        status = _git(worktree, "status", "--porcelain", "--untracked-files=normal")
        if status.returncode != 0:
            entry["probe_failed"] = True
            entry.update({"last_commit_age_sec": None, "clean": False, "status_counts": {},
                          "in_lane_registry": real in claimed, "process_cwd": None})
            entry["classification"] = classify(entry, now_ts)
            rows.append(entry)
            continue
        entry["status_counts"] = _parse_status_counts(status.stdout)
        entry["clean"] = not status.stdout.strip()
        entry["last_commit_age_sec"] = _last_commit_age(worktree, now_ts)
        entry["in_lane_registry"] = real in claimed
        entry["process_cwd"] = _process_in_use(real)
        entry["classification"] = classify(entry, now_ts)
        rows.append(entry)
    return rows


def write_report(path, payload, schema=DEFAULT_SCHEMA):
    """Write the audit payload as JSON at mode 0600 and return the path."""
    body = dict(payload)
    body.setdefault("schema", schema)
    body.setdefault("generated_at_utc", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    data = json.dumps(body, indent=1, sort_keys=True, ensure_ascii=False).encode("utf-8")
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(handle, data)
    finally:
        os.close(handle)
    os.chmod(path, 0o600)
    return path


def command(args):
    """Entry point for ``gatesmith lanes worktrees``."""
    lane_registry = getattr(args, "registry", None)
    rows = audit(args.repo, lane_registry=lane_registry)
    if args.out:
        write_report(args.out, {"rows": rows})
        print(f"report written to {args.out} (0600)")
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    if not rows:
        print("no worktrees")
        return 0
    for row in rows:
        age = row.get("last_commit_age_sec")
        age_s = "?" if age is None else f"{age // 3600}h"
        print(f"{row['path']}  [{row['classification']}]  branch={row.get('branch')}  "
              f"head={(row.get('head') or '')[:10]}  age={age_s}  "
              f"clean={row.get('clean')}  lane={row.get('in_lane_registry')}")
    return 0
