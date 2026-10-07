"""Command-line entry point.

``gatesmith <gate> <verb> [flags]``. Every gate is fail-closed: a non-zero exit
means the action is not cleared. A registry that exists but cannot be parsed is
a hard error (exit 2), never a silent empty result.
"""

import argparse
import sys

from . import __version__, config, evidence, frozen, lanes, review, store

GATES = (review, evidence, lanes, frozen)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="gatesmith",
        description="Fail-closed verification gates for AI coding agents.")
    parser.add_argument("--version", action="version", version=f"gatesmith {__version__}")
    parser.add_argument("--config", help="path to a gatesmith.yaml of shared defaults")
    sub = parser.add_subparsers(dest="gate", required=True)
    for gate in GATES:
        gate.add_parser(sub)
    return parser


def main(argv=None):
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
    except OSError as exc:
        print(f"gatesmith: I/O error — {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
