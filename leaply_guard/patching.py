"""Apply model-written unified diffs, tolerant of wrong line numbers (hunks are located by content)."""
from __future__ import annotations

import difflib
import re


class PatchError(ValueError):
    pass


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")


def split_file_diffs(diff: str) -> dict[str, str]:
    """{path: diff text} for a multi-file unified diff."""
    files: dict[str, list[str]] = {}
    current = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:].split("\t")[0].strip()
            path = re.sub(r"^[ab]/", "", path)
            current = path
            files.setdefault(current, [])
            continue
        if line.startswith("--- ") or line.startswith("diff --git") or line.startswith("index "):
            continue
        if current is not None:
            files[current].append(line)
    return {k: "\n".join(v) for k, v in files.items()}


def _hunks(diff: str) -> list[list[str]]:
    hunks, cur = [], None
    for line in diff.splitlines():
        if _HUNK.match(line) or line.startswith("@@"):
            cur = []
            hunks.append(cur)
        elif cur is not None and (line[:1] in (" ", "+", "-") or line == ""):
            if line.startswith("\\ No newline"):
                continue
            cur.append(line if line else " ")
    return [h for h in hunks if h]


def _find(lines: list[str], block: list[str], start: int) -> int:
    norm = [l.rstrip() for l in block]
    n = len(block)
    for strict in (True, False):
        for i in list(range(start, len(lines) - n + 1)) + list(range(0, min(start, len(lines) - n + 1))):
            window = lines[i:i + n]
            if strict and [l.rstrip() for l in window] == norm:
                return i
            if not strict and [l.strip() for l in window] == [l.strip() for l in block]:
                return i
    return -1


def apply_unified_diff(original: str, diff: str) -> str:
    lines = original.splitlines()
    pos = 0
    hunks = _hunks(diff)
    if not hunks:
        raise PatchError("diff has no hunks")
    for h in hunks:
        old = [l[1:] for l in h if l[:1] in (" ", "-")]
        new = [l[1:] for l in h if l[:1] in (" ", "+")]
        if not old:
            raise PatchError("pure-insertion hunk without context")
        at = _find(lines, old, pos)
        if at < 0:
            raise PatchError(f"hunk context not found: {old[0][:80]!r}")
        # keep the original indentation when the match was whitespace-insensitive
        lines[at:at + len(old)] = new
        pos = at + len(new)
    return "\n".join(lines) + ("\n" if original.endswith("\n") or not original else "")


def make_diff(path: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{path}", tofile=f"b/{path}",
    ))


def diff_stats(diff: str) -> tuple[int, int]:
    add = sum(1 for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
    rem = sum(1 for l in diff.splitlines() if l.startswith("-") and not l.startswith("---"))
    return add, rem
