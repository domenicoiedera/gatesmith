"""The one bounded subprocess runner.

``subprocess.run(..., timeout=T)`` is not a bounded call on Windows. Two
mechanisms break it, and both were measured on real Windows CI rather than
argued from the source:

* On expiry CPython kills only the DIRECT child (``TerminateProcess``) and then
  calls ``communicate()`` with no timeout, which blocks until the stdout pipe
  reaches EOF. A grandchild that inherited the write end keeps the caller
  blocked — indefinitely if it never exits (``subprocess.py``, Windows branch,
  ~552-559).
* Windows' ``communicate()`` implements the timeout with READER THREADS. When a
  grandchild holds the pipe, the call outlives its own timeout: with a 0.5 s
  bound it returned at **5.02 s** (second Windows CI run, four jobs, 5.03-5.05 s
  — the exact span of the shim's sleep). An emulation of the first mechanism on
  POSIX returns in 0.50 s, so emulation alone did not catch this; the platform
  did.

``git`` on Windows spawns such children (diff/textconv drivers, hooks,
credential and ``git-remote-*`` helpers), so a hung git could exceed the tool's
declared bound.

:func:`run` therefore does not delegate its bound to ``communicate``. It drains
the pipes on a daemon thread and enforces the deadline itself with a bounded
thread join, which is honoured on every platform. On expiry it kills the whole
process TREE (``taskkill /F /T`` on Windows, ``kill`` elsewhere) so nothing keeps
the pipe open, and raises :class:`subprocess.TimeoutExpired`. Callers map that to
exit 2 (G10).

Case split, stated precisely because it is not symmetric across platforms: when
the deadline passes because a STRANDED DESCENDANT is holding the pipe while the
command itself has already finished, the tree kill releases the pipe and the real
result is returned rather than a false timeout — on Windows, where ``taskkill
/T`` reaches the descendant. On POSIX the descendant is not reachable without
process-group control, so that case reports a timeout; the command itself is
dead and only an orphan survives (the same orphan ``subprocess.run`` leaves).

The encoding is pinned to UTF-8 with ``errors="replace"`` so non-ASCII output
does not depend on the host code page. Stdlib only; ``shell=False``, always.
"""

import os
import subprocess
import threading

GRACE = 1.0      # seconds to let the reader finish after a tree kill
REAP = 5.0       # seconds to wait for the direct child after a tree kill


def _kill_tree(process):
    """Kill the child AND its descendants.

    ``TerminateProcess``/``SIGKILL`` reaches only the direct child; a grandchild
    that inherited our pipe keeps it open, which is what makes a "bounded" wait
    unbounded on Windows. Best-effort: a failure here must never mask the
    timeout we are about to report.
    """
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True, shell=False, timeout=10,
                encoding="utf-8", errors="replace",
            )
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        process.kill()
    except OSError:
        pass


def run(argv, *, timeout=None, cwd=None, env=None, text=True, stdin=None):
    """Run ``argv`` (argv array — never a shell) under a real wall-clock bound.

    Returns a ``subprocess.CompletedProcess``-shaped result with ``.returncode``,
    ``.stdout`` and ``.stderr`` so call sites stay readable. On expiry the whole
    process tree is killed and :class:`subprocess.TimeoutExpired` is raised.
    """
    process = subprocess.Popen(
        argv,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env,
        shell=False,
        encoding="utf-8" if text else None,
        errors="replace" if text else None,
    )
    box = {}
    moved = threading.Event()

    def _drain():
        try:
            box["out"], box["err"] = process.communicate()
        except BaseException as exc:            # pragma: no cover - defensive
            box["exc"] = exc
        finally:
            moved.set()

    reader = threading.Thread(target=_drain, name="gatesmith-proc-reader",
                              daemon=True)
    reader.start()
    moved.wait(timeout)                         # OUR bound, honoured everywhere

    if not moved.is_set():
        # The deadline passed with the drain unfinished. Distinguish the two
        # cases BEFORE killing, because the kill makes them look alike:
        child_still_running = process.poll() is None
        _kill_tree(process)
        try:
            process.wait(timeout=REAP)
        except subprocess.TimeoutExpired:
            pass
        if child_still_running or not moved.wait(GRACE):
            raise subprocess.TimeoutExpired(argv, timeout or 0)
        # The child had ALREADY finished and only a stray descendant held the
        # pipe: the tree kill released it, so report the real result instead of
        # a false timeout.
        if "exc" in box:
            raise subprocess.TimeoutExpired(argv, timeout or 0)

    if "exc" in box:
        raise box["exc"]
    return subprocess.CompletedProcess(process.args, process.returncode,
                                       box.get("out"), box.get("err"))