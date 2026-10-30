"""Guardrails on every agent edit: scope, protected files, diff size, and secrets."""
from __future__ import annotations

import re
from pathlib import PurePosixPath

PROTECTED = [
    re.compile(p, re.I) for p in (
        r"(^|/)\.env(\..*)?$", r"(^|/)\.github/", r"(^|/)\.gitlab-ci", r"(^|/)\.circleci/",
        r"(^|/)(poetry|uv|Pipfile|package-lock|yarn|pnpm-lock)\.(lock|json|yaml)$", r"(^|/)Pipfile\.lock$",
        r"(^|/)\.git/", r"(^|/)id_(rsa|ed25519|ecdsa)", r"\.(pem|key|p12|pfx)$", r"(^|/)secrets?\b",
    )
]

SECRET_PATTERNS = {
    "AWS access key": r"AKIA[0-9A-Z]{16}",
    "GitHub token": r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}",
    "OpenAI-style key": r"sk-[A-Za-z0-9_-]{32,}",
    "Slack token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
    "Tavily key": r"tvly-[A-Za-z0-9-]{20,}",
    "Private key block": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "Google API key": r"AIza[0-9A-Za-z_-]{35}",
    "Generic credential": r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{24,}['\"]",
}


def check_path(path: str, allowed_tests: set[str]) -> str | None:
    """Return a violation message, or None if the agent may edit this path."""
    p = PurePosixPath(path.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts or path.startswith("~"):
        return f"{path}: outside the target repository"
    for pat in PROTECTED:
        if pat.search(p.as_posix()):
            return f"{path}: protected file (secrets, CI, lockfiles)"
    is_test = any(part in ("tests", "test") for part in p.parts) or p.name.startswith("test_") or p.name.endswith("_test.py")
    if is_test and p.as_posix() not in allowed_tests:
        return f"{path}: test file unrelated to the migration (tests prove the change; they are not rewritten to pass)"
    return None


def scan_secrets(diff: str) -> list[dict]:
    found = []
    for i, line in enumerate(diff.splitlines(), 1):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for name, pat in SECRET_PATTERNS.items():
            if re.search(pat, line):
                found.append({"type": name, "line": i})
    return found


class Guardrails:
    def __init__(self, max_diff_lines: int, allowed_tests: set[str] | None = None):
        self.max_diff_lines = max_diff_lines
        self.allowed_tests = allowed_tests or set()
        self.violations: list[str] = []
        self.checks = 0

    def check_edit(self, path: str) -> str | None:
        self.checks += 1
        v = check_path(path, self.allowed_tests)
        if v:
            self.violations.append(v)
        return v

    def check_size(self, total_changed_lines: int) -> str | None:
        self.checks += 1
        if total_changed_lines > self.max_diff_lines:
            v = f"diff too large: {total_changed_lines} changed lines > limit {self.max_diff_lines}"
            self.violations.append(v)
            return v
        return None

    def summary(self, secrets: list[dict]) -> dict:
        return {
            "status": "passed" if not secrets else "failed",
            "checks": self.checks,
            "rejected_edits": self.violations,
            "secrets_found": secrets,
            "max_diff_lines": self.max_diff_lines,
        }
