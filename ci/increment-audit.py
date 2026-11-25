#!/usr/bin/env python3
"""Layered merge guard, layer 2: private-increment audit.

Run this *after* the merge commit exists (i.e. from the auto-sync workflow right
before `git push`). Two independent questions are answered:

  * Informational: did upstream touch any file where one of our private
    increments lives? (`git diff --name-only HEAD^1 HEAD^2` vs the file globs
    in ci/private-increments.json). Never blocks.
  * Hard: did upstream already ship a symbol that is equivalent to one of our
    increments? If yes, the house rule is "upstream wins, delete our patch",
    so this exits 1 and prints where the equivalent symbol lives upstream.

`exempt: true` entries are the private-protocol layer (upstream can never have
them): they take part in the file-overlap notice but are never symbol-checked.

Usage:
    python3 ci/increment-audit.py --upstream-tag v1.20.1

Exit codes: 0 clean, 1 equivalent implementation found upstream, 2 cannot run
(tag missing / git failure).

Standard library only, Python 3.9+.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

EXIT_OK = 0
EXIT_EQUIVALENT = 1
EXIT_CANNOT_RUN = 2


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def find_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return start


def git(root: Path, *args: str) -> subprocess.CompletedProcess:
    """Run git and return the completed process (stdout/stderr captured)."""
    return subprocess.run(
        ["git", *args],
        cwd=str(root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def git_ok(root: Path, *args: str) -> str:
    proc = git(root, *args)
    if proc.returncode != 0:
        raise RuntimeError(
            "git %s failed (rc=%d): %s"
            % (" ".join(args), proc.returncode, proc.stderr.strip())
        )
    return proc.stdout


def glob_match(path: str, pattern: str) -> bool:
    """Repo-relative glob match; `*` and `**` both span directories."""
    if fnmatch.fnmatchcase(path, pattern):
        return True
    # `dir/**` should also match the directory itself being renamed/deleted.
    if pattern.endswith("/**") and path.startswith(pattern[:-3]):
        return True
    return False


def resolve_merge_sides(root: Path, tag: str) -> Tuple[str, str, str]:
    """Return (base, head, mode) describing "what upstream changed this time"."""
    line = git_ok(root, "rev-list", "--parents", "-n", "1", "HEAD").strip()
    fields = line.split()
    if len(fields) == 3:
        return fields[1], fields[2], "merge (HEAD^1..HEAD^2)"

    # HEAD is not a merge commit (manual run on a normal history): reuse the
    # parents of the most recent merge commit, which is the same change set the
    # workflow would have audited.
    merge_line = git(root, "rev-list", "--merges", "-n", "1", "HEAD").stdout.strip()
    if merge_line:
        parent_proc = git(root, "rev-list", "--parents", "-n", "1", merge_line)
        merge_fields = parent_proc.stdout.strip().split()
        if parent_proc.returncode == 0 and len(merge_fields) == 3:
            return (
                merge_fields[1],
                merge_fields[2],
                "fallback (last merge %s: HEAD^1..HEAD^2)"
                % merge_line[:12],
            )

    # No merge anywhere: compare the release against its parent commit.
    parent = git(root, "rev-parse", "--verify", "--quiet", "%s^" % tag)
    if parent.returncode != 0 or not parent.stdout.strip():
        raise RuntimeError(
            "HEAD is not a merge commit and %s has no parent; cannot derive an "
            "upstream change set" % tag
        )
    return (
        parent.stdout.strip(),
        tag,
        "fallback (%s^..%s, no merge commit in history)" % (tag, tag),
    )


def parse_grep_hits(output: str, rev: str) -> List[str]:
    """Turn `git grep` output into `path:line: text` strings."""
    prefix = rev + ":"
    hits: List[str] = []
    for raw in output.splitlines():
        line = raw[len(prefix):] if raw.startswith(prefix) else raw
        hits.append(line.strip())
    return hits


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------


def load_config(path: Path) -> List[Dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    increments = data.get("increments")
    if not isinstance(increments, list):
        raise ValueError("%s has no `increments` list" % path)
    return increments


def audit(root: Path, config_path: Path, tag: str) -> int:
    increments = load_config(config_path)

    tag_commit = git(root, "rev-parse", "--verify", "--quiet", "%s^{commit}" % tag)
    if tag_commit.returncode != 0 or not tag_commit.stdout.strip():
        print(
            "increment-audit: cannot resolve upstream tag %r in this clone "
            "(fetch tags first, e.g. `git fetch --tags upstream --force`)" % tag,
            file=sys.stderr,
        )
        return EXIT_CANNOT_RUN

    try:
        base, head, mode = resolve_merge_sides(root, tag)
        changed_output = git_ok(root, "diff", "--name-only", base, head)
    except RuntimeError as exc:
        print("increment-audit: %s" % exc, file=sys.stderr)
        return EXIT_CANNOT_RUN

    changed = [line.strip() for line in changed_output.splitlines() if line.strip()]
    changed_set = set(changed)

    print("## 增量审计（上游 tag %s）" % tag)
    print()
    print("上游改动基线: `%s..%s` (%s, %d 个文件)"
          % (base[:12], head[:12], mode, len(changed)))
    print()

    overlaps: List[Tuple[str, List[str]]] = []
    equivalents: List[str] = []
    skipped_exempt: List[str] = []
    errors: List[str] = []

    for entry in increments:
        entry_id = str(entry.get("id", "<unnamed>"))
        exempt = bool(entry.get("exempt", False))
        block = bool(entry.get("block", True))

        touched: List[str] = []
        for path in changed:
            if any(glob_match(path, pattern) for pattern in entry.get("files", [])):
                touched.append(path)
        if touched:
            overlaps.append((entry_id, touched))

        if exempt:
            skipped_exempt.append(entry_id)
            continue
        if not block:
            continue

        patterns = [p for p in entry.get("symbols", []) if p]
        if not patterns:
            continue
        scope = entry.get("scope") or ["."]

        for pattern in patterns:
            proc = git(root, "grep", "-n", "-E", "-e", pattern, tag, "--", *scope)
            if proc.returncode not in (0, 1):
                errors.append(
                    "git grep for %r (%s) failed: %s"
                    % (pattern, entry_id, proc.stderr.strip())
                )
                continue
            if proc.returncode == 0:
                for hit in parse_grep_hits(proc.stdout, tag):
                    equivalents.append(
                        "上游已出现 `%s`（%s），按『上游优先删增量』规则应删掉我们的 `%s`（%s）"
                        % (pattern, hit, entry_id, entry.get("desc", ""))
                    )

    print("### 重叠提示（不 block）")
    print()
    if overlaps:
        print("上游本次改动触及我们的增量落点，需人工复核：")
        print()
        for entry_id, files in overlaps:
            print("- `%s`" % entry_id)
            for path in files:
                print("  - `%s`" % path)
    else:
        print("上游本次改动未触及任何增量落点。")
    print()

    if skipped_exempt:
        print("已跳过判定（exempt，私有协议层）: %s"
              % ", ".join("`%s`" % item for item in skipped_exempt))
        print()

    if errors:
        for message in errors:
            print("increment-audit: ERROR: %s" % message, file=sys.stderr)
        return EXIT_CANNOT_RUN

    if equivalents:
        print("### 上游已实现等价能力（必须删我们的增量）")
        print()
        for line in equivalents:
            print("- %s" % line)
        print()
        print("按规则默认动作：删我们的补丁（若确认上游实现语义不同，请人工判断后再放行）。")
        print()
        print("increment-audit: FAIL (重叠 %d 项、等价 %d 项)"
              % (len(overlaps), len(equivalents)))
        return EXIT_EQUIVALENT

    print("increment-audit: OK (重叠 %d 项、等价 0 项)" % len(overlaps))
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit our private increments against a merged upstream tag."
    )
    parser.add_argument("--upstream-tag", required=True,
                        help="upstream release tag that was merged, e.g. v1.20.1")
    parser.add_argument("--config", default=None,
                        help="path to private-increments.json (default: next to this script)")
    args = parser.parse_args(argv)

    script_dir = Path(__file__).resolve().parent
    root = find_repo_root(script_dir)
    config_path = Path(args.config) if args.config else script_dir / "private-increments.json"

    if not config_path.is_file():
        print("increment-audit: config not found: %s" % config_path, file=sys.stderr)
        return EXIT_CANNOT_RUN

    try:
        return audit(root, config_path, args.upstream_tag)
    except (ValueError, RuntimeError) as exc:
        print("increment-audit: %s" % exc, file=sys.stderr)
        return EXIT_CANNOT_RUN
    except subprocess.SubprocessError as exc:
        print("increment-audit: git invocation failed: %s" % exc, file=sys.stderr)
        return EXIT_CANNOT_RUN


if __name__ == "__main__":
    sys.exit(main())