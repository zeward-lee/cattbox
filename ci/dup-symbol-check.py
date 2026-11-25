#!/usr/bin/env python3
"""Layered merge guard, layer 1: duplicate symbols / duplicate l10n keys.

After a `git merge` that reports no conflict, a patch of ours and a freshly
released upstream implementation can both land, producing duplicate
declarations the compiler reports one at a time (2026-11-25 incident: two
"requestLocalNetworkPermission" branches in a Kotlin `when`, two Dart methods
of the same name, three l10n files each carrying the same key twice).

This script scans the four shapes we have actually been bitten by and prints
*every* hit in one pass:

  1. lib/l10n/l10n.dart                  duplicate `String get <name>`
  2. lib/l10n/intl/messages_*.dart       duplicate `"<key>": MessageLookupByLibrary`
  3. arb/*.arb                           duplicate JSON keys (json would silently
                                         drop them, so parse with a pairs hook)
  4. android/**/*.kt                     duplicate `fun` (same name + params) and
                                         duplicate `when` branch labels

Read-only. Exit 1 when anything is duplicated, 0 otherwise.
Pure standard library, Python 3.9+. Runs from any cwd.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

# --------------------------------------------------------------------------
# repo root discovery
# --------------------------------------------------------------------------


def find_repo_root(start: Path) -> Path:
    """Walk up from *start* until a directory containing .git is found."""
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    # Not a git checkout (e.g. a scratch copy): fall back to the script's
    # parent directory, which is what the caller most likely meant.
    return start


# --------------------------------------------------------------------------
# JSON with duplicate keys preserved
# --------------------------------------------------------------------------


class JsonObject(list):
    """A JSON object kept as its raw (key, value) pair list.

    `object_pairs_hook` is only invoked for objects, so plain Python lists in
    the resulting tree are JSON arrays. Wrapping pairs in this subclass is how
    we tell the two apart when walking the tree.
    """

    def keys_seen(self) -> List[str]:
        return [pair[0] for pair in self]


def load_json_preserving_duplicates(text: str):
    return json.loads(text, object_pairs_hook=JsonObject)


def walk_json(node, prefix: str = "") -> Iterable[Tuple[str, str]]:
    """Yield (json-path, duplicated-key) for every repeated key in *node*."""
    if isinstance(node, JsonObject):
        names = node.keys_seen()
        counts = Counter(names)
        for name in counts:
            if counts[name] > 1:
                yield (prefix or "<root>", name)
        for name, value in node:
            child = "%s.%s" % (prefix, name) if prefix else name
            yield from walk_json(value, child)
    elif isinstance(node, list):
        # A JSON array: its elements may be objects with duplicate keys.
        for index, item in enumerate(node):
            yield from walk_json(item, "%s[%d]" % (prefix, index))


def arb_key_lines(path: Path) -> Dict[str, List[int]]:
    """Map each quoted key to the line numbers where it appears.

    json gives us correctness (duplicate detection) but no positions, so the
    line numbers are recovered with a light scan of the raw text.
    """
    pattern = re.compile(r'^\s*"((?:[^"\\]|\\.)*)"\s*:')
    found: Dict[str, List[int]] = {}
    for lineno, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        match = pattern.match(line)
        if match:
            found.setdefault(match.group(1), []).append(lineno)
    return found


# --------------------------------------------------------------------------
# Kotlin helpers
# --------------------------------------------------------------------------


FUN_RE = re.compile(
    r"^\s{4}(?:override\s+|private\s+|suspend\s+)*fun\s+(\w+)\s*\(([^)]*)\)",
    re.MULTILINE,
)
WHEN_LABEL_RE = re.compile(r'^\s{12}"([^"]+)"\s*->', re.MULTILINE)


def split_top_level(text: str, separator: str = ",") -> List[str]:
    """Split on *separator* only at bracket depth 0."""
    parts: List[str] = []
    buf: List[str] = []
    depth = 0
    for char in text:
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        if char == separator and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(char)
    parts.append("".join(buf))
    return parts


def normalize_params(raw: str) -> str:
    """Normalize a Kotlin parameter list to a comparable signature.

    Kotlin overloads are keyed by parameter *types*, so keep only the type part
    of each parameter (`name: Type` -> `Type`) and collapse whitespace.
    """
    types: List[str] = []
    for param in split_top_level(raw):
        param = " ".join(param.split())
        if not param:
            continue
        segments = split_top_level(param, ":")
        if len(segments) > 1:
            param = segments[-1].strip()
        types.append(param)
    return ", ".join(types)


def add_hit(hits: List[Tuple[str, int, str, str]], path: Path, line: int,
            category: str, symbol: str, root: Path) -> None:
    rel = path.relative_to(root).as_posix()
    hits.append((rel, line, category, symbol))


# --------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------


def check_l10n_getters(root: Path, hits) -> None:
    path = root / "lib" / "l10n" / "l10n.dart"
    if not path.is_file():
        return
    pattern = re.compile(r"^\s*String get (\w+)")
    occurrences: Dict[str, List[int]] = {}
    for lineno, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        match = pattern.match(line)
        if match:
            occurrences.setdefault(match.group(1), []).append(lineno)
    for name, lines in occurrences.items():
        if len(lines) > 1:
            for lineno in lines:
                add_hit(hits, path, lineno, "l10n-getter", name, root)


def check_message_maps(root: Path, hits) -> None:
    pattern = re.compile(r'^\s*"([A-Za-z0-9_]+)": MessageLookupByLibrary')
    for path in sorted((root / "lib" / "l10n" / "intl").glob("messages_*.dart")):
        occurrences: Dict[str, List[int]] = {}
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            match = pattern.match(line)
            if match:
                occurrences.setdefault(match.group(1), []).append(lineno)
        for name, lines in occurrences.items():
            if len(lines) > 1:
                for lineno in lines:
                    add_hit(hits, path, lineno, "l10n-message-key", name, root)


def check_arb_files(root: Path, hits) -> None:
    for path in sorted((root / "arb").glob("*.arb")):
        try:
            document = load_json_preserving_duplicates(
                path.read_text(encoding="utf-8", errors="replace")
            )
        except ValueError as exc:
            print("warning: %s is not valid JSON: %s" % (path, exc), file=sys.stderr)
            continue
        key_lines = arb_key_lines(path)
        for json_path, name in walk_json(document):
            lines = key_lines.get(name, [0])
            for lineno in lines:
                symbol = name if json_path == "<root>" else "%s.%s" % (json_path, name)
                add_hit(hits, path, lineno, "arb-key", symbol, root)


def check_kotlin(root: Path, hits) -> None:
    for path in sorted((root / "android").rglob("*.kt")):
        text = path.read_text(encoding="utf-8", errors="replace")

        functions: Dict[Tuple[str, str], List[int]] = {}
        for match in FUN_RE.finditer(text):
            lineno = text.count("\n", 0, match.start()) + 1
            key = (match.group(1), normalize_params(match.group(2)))
            functions.setdefault(key, []).append(lineno)
        for (name, params), lines in functions.items():
            if len(lines) > 1:
                symbol = "%s(%s)" % (name, params) if params else "%s()" % name
                for lineno in lines:
                    add_hit(hits, path, lineno, "kt-fun", symbol, root)

        labels: Dict[str, List[int]] = OrderedDict()
        for match in WHEN_LABEL_RE.finditer(text):
            lineno = text.count("\n", 0, match.start()) + 1
            labels.setdefault(match.group(1), []).append(lineno)
        for label, lines in labels.items():
            if len(lines) > 1:
                for lineno in lines:
                    add_hit(hits, path, lineno, "kt-when-branch", '"%s"' % label, root)


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    root = find_repo_root(script_dir)

    hits: List[Tuple[str, int, str, str]] = []
    check_l10n_getters(root, hits)
    check_message_maps(root, hits)
    check_arb_files(root, hits)
    check_kotlin(root, hits)

    if not hits:
        print("dup-symbol-check: OK (0 duplicates)")
        return 0

    hits.sort(key=lambda item: (item[0], item[1], item[2], item[3]))
    groups: Dict[Tuple[str, str, str], List[int]] = OrderedDict()
    for rel, lineno, category, symbol in hits:
        groups.setdefault((rel, category, symbol), []).append(lineno)

    print("dup-symbol-check: FAIL (%d duplicate group(s), %d occurrence(s))"
          % (len(groups), len(hits)))
    print()
    current_file = None
    for (rel, category, symbol), lines in groups.items():
        if rel != current_file:
            print("== %s" % rel)
            current_file = rel
        print("  %s:%s: %s: %s"
              % (rel, ",".join(str(n) for n in lines), category, symbol))
    print()
    print("Fix: keep one side (upstream by default), remove our duplicate, "
          "then re-run this check.")
    return 1


if __name__ == "__main__":
    sys.exit(main())