"""Command-line entry point.

``gatesmith <gate> <verb> [flags]``. Every gate is fail-closed: a non-zero exit
means the action is not cleared. A registry that exists but cannot be parsed is
a hard error (exit 2), never a silent empty result.

The top-level ``gatesmith judge`` verb (v0.3.0) is the one NON-gate: it asks a
typed-decision classifier (bring-your-own endpoint) about the current registry
or a named review and prints a verdict table. It is informational by
construction — exit 0 whatever the classifier answers, 2 only when the
registry or the invocation itself is unreadable (usage) — because an
uncalibrated classifier must never decide anything (see docs/judge.md).
"""

import argparse
import subprocess
import sys

from . import __version__, config, evidence, frozen, lanes, review, store

GATES = (review, evidence, lanes, frozen)


class _NoAbbrevParser(argparse.ArgumentParser):
    """An ArgumentParser that refuses option prefixes (G4).

    ``argparse`` otherwise accepts any unambiguous prefix, so ``--allow-u`` would
    silently enable the DANGER flag ``--allow-unsealed``. Because
    ``add_subparsers`` defaults ``parser_class`` to ``type(self)``, using this
    class for the root parser makes every gate and sub-verb parser inherit the
    rule — a danger flag is never reachable by a typo.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)


def _add_judge_parser(subparsers):
    """The `gatesmith judge` verb — advisory classifier, exit 0 informational.

    It hangs off the root (not under a gate) because it belongs to no gate's
    decision: it records a SECOND opinion beside the gate's, and the taxonomy
    it ships with is the informational one (0 readable / 2 unreadable).
    """
    parser = subparsers.add_parser(
        "judge", help="ask the configured decision classifier about the "
                      "current registry/change — ADVISORY, exit 0 either way")
    parser.add_argument("--registry", default=None,
                        help=f"review registry to classify (default: "
                             f"{review.DEFAULT_REGISTRY})")
    parser.add_argument("--id", default=None,
                        help="classify one named review instead of the whole registry")
    parser.add_argument("--json", action="store_true",
                        help="also print the raw typed answers as one JSON object "
                             "(the audit receipt carries the same answers)")
    parser.set_defaults(fn=review.cmd_judge)
    return parser


def build_parser():
    parser = _NoAbbrevParser(
        prog="gatesmith",
        description="Fail-closed verification gates for AI coding agents.")
    parser.add_argument("--version", action="version", version=f"gatesmith {__version__}")
    parser.add_argument("--config", help="path to a gatesmith.yaml of shared defaults")
    sub = parser.add_subparsers(dest="gate", required=True)
    for gate in GATES:
        gate.add_parser(sub)
    _add_judge_parser(sub)
    return parser


def _force_utf8_output():
    """Emit UTF-8 whatever the platform's default encoding is.

    Windows defaults stdout to the ANSI code page (cp1252 in CI), so the ``·``
    and ``—`` separators our lines use were written as cp1252 bytes: the SAME
    command produced different bytes per platform, and every consumer reading
    UTF-8 (a pipe, a log, a test harness) saw U+FFFD. The output is the tool's
    property, not the host's. ``errors="replace"`` keeps a hostile path from
    aborting the run; streams that cannot be reconfigured (in-process callers,
    a captured StringIO) are left alone.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def main(argv=None):
    _force_utf8_output()
    args = build_parser().parse_args(argv)
    args._config = config.load(args.config) if args.config else {}
    try:
        return args.fn(args)
    except review.UsageError as exc:
        print(f"gatesmith: usage error — {exc}", file=sys.stderr)
        return 2
    except store.RegistryError as exc:
        print(f"gatesmith: unreadable registry — {exc}", file=sys.stderr)
        return 2
    except subprocess.TimeoutExpired as exc:
        # G10: a bounded subprocess (git in evidence/lanes, ssh-keygen in seal)
        # that did not answer is an unreadable instrument — a hard error (2),
        # never a traceback and never exit 1, which a caller reads as "blocked".
        # `TimeoutExpired` is a `SubprocessError`, NOT an `OSError`, so the
        # handler below never saw it.
        print(f"gatesmith: timed out — {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"gatesmith: I/O error — {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
