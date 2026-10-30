"""Isolated workspace: a temp copy of the repo with its own virtualenv, where tests run."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from .events import EventBus

IGNORE = shutil.ignore_patterns(".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache", ".leaply", "*.pyc")


@dataclass
class TestResult:
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    duration: float = 0.0
    cases: list[dict] = field(default_factory=list)
    output: str = ""
    exit_code: int = -1

    @property
    def total(self) -> int:
        return self.passed + self.failed + self.errors

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and self.failed == 0 and self.errors == 0 and self.passed > 0

    def failures_text(self, limit: int = 8000) -> str:
        parts = [f"{c['name']}: {c['message']}\n{c['detail']}" for c in self.cases if c["status"] in ("failed", "error")]
        text = "\n\n".join(parts) or self.output
        return text[-limit:]

    def to_dict(self) -> dict:
        return {"passed": self.passed, "failed": self.failed, "errors": self.errors, "skipped": self.skipped,
                "total": self.total, "ok": self.ok, "duration": round(self.duration, 2),
                "cases": [{k: c[k] for k in ("name", "status", "message")} for c in self.cases]}


class Workspace:
    def __init__(self, source: Path, bus: EventBus, test_timeout: int = 300):
        self.source = source
        self.bus = bus
        self.test_timeout = test_timeout
        self.root = Path(tempfile.mkdtemp(prefix="leaply-"))
        self.repo = self.root / "repo"
        shutil.copytree(source, self.repo, ignore=IGNORE)
        self.venv = self.root / "venv"
        self.uv = shutil.which("uv")
        self.commands: list[dict] = []

    # -- commands -------------------------------------------------------------
    def run(self, cmd: list[str], step: str, timeout: int = 600, cwd: Path | None = None) -> subprocess.CompletedProcess:
        started = time.time()
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
        for secret in ("NEBIUS_API_KEY", "TAVILY_API_KEY", "GITHUB_TOKEN"):
            env.pop(secret, None)  # the code under test never sees our keys
        try:
            proc = subprocess.run(cmd, cwd=cwd or self.repo, capture_output=True, text=True, timeout=timeout, env=env,
                                  encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired as exc:
            proc = subprocess.CompletedProcess(cmd, 124, exc.stdout or "", f"timed out after {timeout}s")
        rec = {"cmd": " ".join(str(c) for c in cmd).replace(str(self.root), "<ws>"), "exit": proc.returncode,
               "seconds": round(time.time() - started, 2), "step": step}
        self.commands.append(rec)
        self.bus.emit("command", actor="sandbox", **rec)
        return proc

    @property
    def python(self) -> Path:
        sub = "Scripts/python.exe" if os.name == "nt" else "bin/python"
        return self.venv / sub

    def create_venv(self, step: str) -> None:
        if self.venv.exists():
            shutil.rmtree(self.venv, ignore_errors=True)
        if self.uv:
            self.run([self.uv, "venv", "-q", "-p", f"{sys.version_info.major}.{sys.version_info.minor}", str(self.venv)], step)
        else:
            self.run([sys.executable, "-m", "venv", str(self.venv)], step)

    def install(self, step: str) -> bool:
        reqs = [p for p in sorted(self.repo.glob("requirements*.txt"))]
        args: list[str] = []
        for r in reqs:
            args += ["-r", str(r)]
        if (self.repo / "pyproject.toml").exists() and not reqs:
            args += ["-e", str(self.repo)]
        args += ["pytest"]
        if self.uv:
            proc = self.run([self.uv, "pip", "install", "-q", "-p", str(self.python), *args], step)
        else:
            proc = self.run([str(self.python), "-m", "pip", "install", "-q", *args], step)
        if proc.returncode != 0:
            self.bus.emit("log", step=step, actor="sandbox", level="error", message=(proc.stderr or proc.stdout)[-1500:])
        return proc.returncode == 0

    def installed_version(self, package: str, step: str) -> str | None:
        proc = self.run([str(self.python), "-c", f"import importlib.metadata as m; print(m.version({package!r}))"], step)
        return proc.stdout.strip() or None

    def run_tests(self, step: str, extra: list[str] | None = None) -> TestResult:
        report = self.root / "junit.xml"
        report.unlink(missing_ok=True)
        cmd = [str(self.python), "-m", "pytest", "-q", "-p", "no:cacheprovider", "--tb=short",
               f"--junitxml={report}", *(extra or [])]
        started = time.time()
        proc = self.run(cmd, step, timeout=self.test_timeout)
        res = TestResult(output=((proc.stdout or "") + "\n" + (proc.stderr or ""))[-20000:], exit_code=proc.returncode,
                         duration=time.time() - started)
        if report.exists():
            try:
                for case in ET.parse(report).getroot().iter("testcase"):
                    name = f"{case.get('classname', '')}::{case.get('name')}".replace("tests.", "tests/", 1)
                    status, message, detail = "passed", "", ""
                    for tag in ("failure", "error", "skipped"):
                        el = case.find(tag)
                        if el is not None:
                            status = {"failure": "failed", "error": "error", "skipped": "skipped"}[tag]
                            message = (el.get("message") or "")[:300]
                            detail = (el.text or "")[-3000:]
                            break
                    res.cases.append({"name": name, "status": status, "message": message, "detail": detail})
            except ET.ParseError:
                pass
        for c in res.cases:
            setattr(res, {"passed": "passed", "failed": "failed", "error": "errors", "skipped": "skipped"}[c["status"]],
                    getattr(res, {"passed": "passed", "failed": "failed", "error": "errors", "skipped": "skipped"}[c["status"]]) + 1)
        if not res.cases and proc.returncode != 0:
            res.errors = 1  # collection error: nothing ran
        return res

    # -- files ----------------------------------------------------------------
    def read(self, rel: str) -> str:
        return (self.repo / rel).read_text(encoding="utf-8")

    def write(self, rel: str, text: str) -> None:
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def bump_requirement(text: str, package: str, target: str) -> tuple[str, int]:
    """Deterministic version bump in requirements-style text. Returns (new_text, replacements)."""
    pat = re.compile(rf"^(\s*{re.escape(package)}\s*(?:\[[^\]]*\])?\s*)(==|>=|~=|<=)\s*[A-Za-z0-9.+!-]+(.*)$", re.I | re.M)
    return pat.subn(lambda m: f"{m.group(1)}=={target}{m.group(3) if not m.group(3).strip().startswith(',') else ''}", text)
