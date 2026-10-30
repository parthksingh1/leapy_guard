"""Devpost readiness checklist: python scripts/check_submission.py (exit code 1 if anything fails)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from leaply_guard.submission import checklist, fill_in_items  # noqa: E402


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    items = checklist(ROOT)
    print("Leaply Guard: submission checklist\n")
    for name, ok, note in items:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({note})" if note and not ok else ""))
    todo = fill_in_items(ROOT)
    if todo:
        print(f"\n{len(todo)} [fill in] items need your own words:")
        for t in todo:
            print("  - " + t)
    failed = [n for n, ok, _ in items if not ok]
    print(f"\n{len(items) - len(failed)}/{len(items)} checks pass." + ("" if not failed else " Fix the FAIL items before submitting."))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
