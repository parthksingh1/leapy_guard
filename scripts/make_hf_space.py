"""Prepare a Hugging Face Space commit: README.md with the Space header, on branch hf-space.

Usage (from the repo root, with a clean working tree):
    python scripts/make_hf_space.py
    git push space hf-space:main --force
    git checkout master
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADER = """---
title: Leaply Guard
emoji: 🛡️
colorFrom: green
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: Upgrade vulnerable deps across breaking versions, proven by tests
---

"""


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def main() -> int:
    if git("status", "--porcelain").strip():
        print("working tree not clean: commit first", file=sys.stderr)
        return 1
    git("checkout", "-B", "hf-space")
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    if not text.startswith("---"):
        readme.write_text(HEADER + text, encoding="utf-8", newline="\n")
        git("add", "README.md")
        git("-c", "user.name=Leaply Guard", "-c", "user.email=leaply-guard@users.noreply.github.com",
            "commit", "-m", "Hugging Face Space config")
    print("branch hf-space ready. Now run:\n  git push space hf-space:main --force\n  git checkout master")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
