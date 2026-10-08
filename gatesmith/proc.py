"""The one bounded subprocess runner.

``subprocess.run(..., timeout=T)`` is not a bounded call on Windows. On expiry
CPython kills only the DIRECT child (``TerminateProcess``) and then calls
``communicate()`` **with no timeout**, which blocks until the stdout pipe
reaches EOF; a grandchild that inherited the write end keeps the caller blocked
— indefinitely if it never exits (``subprocess.py``, Windows branch, ~552-559:
``process.kill()`` then ``exc.stdout, exc.stderr = process.communicate()``).
``git`` on Windows spawns such children (diff/textconv drivers, hooks,
credential and ``git-remote-*`` helpers), so a hung git could hang the tool past
its declared bound. The old shape, emulated on POSIX, returned at **5.02 s** for
a 0.50 s timeout.

:func:`run` kills the direct child on expiry, reaps it, and returns AT ONCE by
raising :class:`subprocess.TimeoutExpired` — it never drains the pipes of a
timed-out child, because a timed-out child's output is never used. Callers map
``TimeoutExpired`` to exit 2 (G10). The encoding is pinned to UTF-8 with
``errors="replace"`` so non-ASCII output does not depend on the host code page.
"""

import subprocess


def run(argv, *, timeout=None, cwd=None, env=None, text=True, stdin=None):
    """Run ``argv`` (argv array — never a shell) under a real wall-clock bound.

    Returns a ``subprocess.CompletedProcess``-shaped result with ``.returncode``,
    ``.stdout`` and ``.stderr`` so call sites stay readable. On expiry the direct
    child is killed and reaped and :class:`subprocess.TimeoutExpired` is raised;
    the pipes of the timed-out child are NOT drained (see the module docstring).
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
    try:
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()      # the DIRECT child only (TerminateProcess / SIGKILL)
        process.wait()      # reap it so it does not linger as a zombie
        # Do NOT call communicate() again: a grandchild that inherited the stdout
        # pipe keeps that drain blocked past the timeout (the H1 hole). We never
        # use a timed-out child's output, so close the pipes and return at once.
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        raise
    return subprocess.CompletedProcess(process.args, process.returncode, out, err)
