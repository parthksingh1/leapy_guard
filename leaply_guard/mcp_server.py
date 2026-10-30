"""Leaply Guard as an MCP server (stdio): scan_repo, triage, fix, get_report."""
from __future__ import annotations

import json
from pathlib import Path

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # 1.x
    from mcp.server.fastmcp import FastMCP

from .config import settings
from .events import EventBus
from .llm import LLM
from .pipeline import Pipeline, RunOptions, _new_run_id, resolve_repo
from .scan import Finding, scan_repo
from .triage import triage as run_triage

mcp = FastMCP("leaply-guard")
_findings: dict[str, tuple[str, Path, Finding]] = {}  # finding_id -> (repo spec, local path, finding)


def _summary(f: Finding) -> dict:
    return {
        "finding_id": f.id, "package": f.package.name, "version": f.package.version, "severity": f.severity,
        "advisories": [{"id": a.id, "cve": a.cve, "severity": a.severity, "fixed": a.fixed, "summary": a.summary} for a in f.advisories],
        "fixed_version": f.fixed_version, "latest_version": f.latest_version,
        "reachability": f.reachability.get("verdict"), "score": f.score,
    }


@mcp.tool(name="scan_repo")
def scan_repo_tool(path: str) -> str:
    """Scan a repository (local path or GitHub URL) for vulnerable pinned dependencies using OSV.dev.
    Returns findings with ids to pass to triage() and fix()."""
    local, _ = resolve_repo(path, EventBus("mcp"))
    deps, findings = scan_repo(local)
    for f in findings:
        _findings[f.id] = (path, local, f)
    return json.dumps({"dependencies": len(deps), "findings": [_summary(f) for f in findings]}, indent=1)


@mcp.tool()
def triage(finding_id: str) -> str:
    """Reachability triage with Nemotron 3 Nano: REACHABLE / POSSIBLY REACHABLE / NOT USED, with file:line evidence."""
    if finding_id not in _findings:
        return f"unknown finding_id {finding_id!r}; call scan_repo first"
    _, local, f = _findings[finding_id]
    result = run_triage(local, f, LLM(EventBus("mcp")) if settings.llm_enabled else None)
    return json.dumps(result, indent=1)


@mcp.tool()
def fix(finding_id: str, target_version: str | None = None) -> str:
    """Upgrade the vulnerable package, migrate the code (Ultra plans, Super edits), and prove it:
    tests before/after, a security regression test, and an OSV re-scan. Returns the run id and result card."""
    if finding_id not in _findings:
        return f"unknown finding_id {finding_id!r}; call scan_repo first"
    if not settings.llm_enabled:
        return "NEBIUS_API_KEY is not set on the MCP server"
    spec, _, f = _findings[finding_id]
    bus = EventBus(_new_run_id())
    result = Pipeline(RunOptions(repo=spec, package=f.package.name, target=target_version), bus).run()
    d = result.data
    from .report import result_card
    return json.dumps({
        "run_id": result.run_id, "status": result.status,
        "result": result_card(d) if "report_md" in d else d.get("error") or d.get("summary"),
        "confidence": d.get("confidence"), "report_path": d.get("delivery", {}).get("report_path"),
        "patch_path": d.get("delivery", {}).get("patch_path"),
    }, indent=1)


@mcp.tool()
def get_report(run_id: str) -> str:
    """The markdown report (PR body) for a finished run."""
    path = settings.runs_dir / run_id / "report.md"
    if not path.exists():
        return f"no report for run {run_id!r}"
    return path.read_text(encoding="utf-8")


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
