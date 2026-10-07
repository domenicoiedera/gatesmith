"""Optional shared defaults read from a ``gatesmith.yaml``.

The parsed subset is deliberately tiny — flat two-level maps, scalars, inline
``[a, b]`` lists and dash lists — because gatesmith ships zero dependencies and
a full YAML parser would be the first import. Teams use it to stop repeating
paths on every command; a CLI flag always wins, and an absent or malformed
config degrades to the built-in defaults rather than failing the run.

    review:
      registry: .gatesmith/review-registry.json
    evidence:
      registry: .gatesmith/frozen-registry.json
      markers_file: .gatesmith/markers.txt
    lanes:
      registry: .gatesmith/lane-registry.json
      frozen_registry: .gatesmith/frozen-registry.json
"""

import os
import re

_INLINE_LIST = re.compile(r"^\[(.*)\]$")


def _scalar(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    if text.lower() in ("true", "false"):
        return text.lower() == "true"
    return text


def _strip_comment(line):
    """Drop a ``#`` comment, but not one inside a quoted value."""
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def load(path):
    """Parse ``path`` into ``{section: {key: value}}``; missing file -> ``{}``."""
    if not path or not os.path.isfile(path):
        return {}
    cfg = {}
    section = None
    last_key = None
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = _strip_comment(raw)
            if not line.strip():
                continue
            if line[:1].isspace():
                if section is None:
                    continue
                body = line.strip()
                if body.startswith("- ") and last_key is not None:
                    current = cfg[section].get(last_key)
                    if isinstance(current, list):
                        current.append(_scalar(body[2:]))
                    continue
                key, _, val = body.partition(":")
                key = key.strip()
                val = val.strip()
                if val == "":
                    cfg[section][key] = []
                elif _INLINE_LIST.match(val):
                    inner = _INLINE_LIST.match(val).group(1)
                    cfg[section][key] = [_scalar(p) for p in inner.split(",") if p.strip()]
                else:
                    cfg[section][key] = _scalar(val)
                last_key = key
            else:
                key, _, _ = line.partition(":")
                section = key.strip()
                cfg.setdefault(section, {})
                last_key = None
    return cfg


def get(args, section, key, default=None):
    """Resolve a setting: explicit CLI value, then config, then ``default``."""
    value = getattr(args, key, None)
    if value is not None:
        return value
    cfg = getattr(args, "_config", None) or {}
    return cfg.get(section, {}).get(key, default)
