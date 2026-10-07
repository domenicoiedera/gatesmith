"""Frozen paths as code.

A frozen registry declares files — or directory prefixes — that only their
owner may change. The guard answers exactly one question: does this change-set
touch a frozen path? It is meant to be called both by the ``frozen`` command
and in-process by the lane guard, so it never shells out.

The registry is JSON::

    {"items": [
       {"id": "F1", "area": "payment capture", "owned_files": ["src/payments", "src/tax.ts"]}
    ]}

``owned_files`` entries are matched simply and readably: a trailing ``/`` means
"this directory and everything under it"; otherwise an entry matches itself and
anything beneath it.

Exit codes: 0 clear, 1 blocked, 2 registry unreadable.
"""

from . import config, store

DEFAULT_REGISTRY = "./FROZEN-registry.json"


def load_items(path):
    """Return the registry's item list (``[]`` when the file is absent).

    A registry that exists but is not a JSON object, or whose ``items`` is not
    a JSON list, is a broken instrument: it raises :class:`store.RegistryError`
    (the caller exits 2) rather than reading as an empty, clear result.
    """
    data = store.load_json(path, {"items": []})
    items = data.get("items", [])
    if items is None:
        items = []
    if not isinstance(items, list):
        raise store.RegistryError(
            f"{path}: 'items' must be a JSON list, got {type(items).__name__}")
    return items


def match(owned_globs, path):
    """True if ``path`` is covered by any owned-files entry."""
    candidate = path.strip()
    for glob in owned_globs:
        glob = str(glob).strip()
        if not glob:
            continue
        if glob.endswith("/"):
            if candidate.startswith(glob):
                return True
        else:
            if candidate == glob or candidate.startswith(glob + "/"):
                return True
    return False


def blocked_files(items, paths):
    """Return ``(path, id, area)`` for every path owned by a frozen item."""
    hits = []
    for path in paths:
        for item in items:
            if match(item.get("owned_files", []), path):
                hits.append((path, item.get("id"), item.get("area")))
    return hits


def cmd_check(args):
    registry = config.get(args, "frozen", "registry", DEFAULT_REGISTRY)
    changed = list(args.paths or [])
    if args.file_list:
        with open(args.file_list, encoding="utf-8") as fh:
            changed += [line.strip() for line in fh if line.strip()]
    if not changed:
        print("CLEAR — no files given, nothing to check.")
        return 0
    items = load_items(registry)
    hits = blocked_files(items, changed)
    if hits:
        print("FROZEN-BLOCKED — these files are owned by frozen items:")
        for path, item_id, area in hits:
            print(f"  {path}  ->  {item_id} ({area})")
        print("STOP. Only the owner lifts a freeze: get approval for this specific change, "
              "or re-plan around the frozen path(s).")
        return 1
    print(f"CLEAR — none of the {len(changed)} planned change(s) touch a frozen file.")
    return 0


def add_parser(subparsers):
    parser = subparsers.add_parser("frozen", help="check a change-set against a frozen-paths registry")
    parser.add_argument("--registry", default=None,
                        help=f"frozen-paths registry (default: {DEFAULT_REGISTRY})")
    sub = parser.add_subparsers(dest="cmd", required=True)

    check = sub.add_parser("check", help="fail when a planned path is frozen")
    check.add_argument("paths", nargs="*", help="files planned to change")
    check.add_argument("--file-list", help="file holding one path per line")
    check.set_defaults(fn=cmd_check)
    return parser
