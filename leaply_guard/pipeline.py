"""The Leaply Guard pipeline: scan -> triage -> research -> baseline -> proof -> plan -> edit -> verify/fix -> rescan -> report."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import agents
from .config import Settings, settings as default_settings
from .events import EventBus
from .guardrails import Guardrails, scan_secrets
from .llm import LLM, LLMError
from .patching import PatchError, apply_unified_diff, diff_stats, make_diff, split_file_diffs
from .research import research as run_research
from .scan import Finding, scan_repo, vulns_for
from .triage import triage as run_triage
from .workspace import TestResult, Workspace, bump_requirement

PROOF_PATH = "tests/test_leaply_security_proof.py"
PROOFS_DIR = Path(__file__).parent / "proofs"
# vetted security tests for well-known advisories (used if the model-written test cannot be validated)
VETTED_PROOFS = {
    "GHSA-ffqj-6fqr-9h24": "pyjwt_cve_2022_29217.py", "CVE-2022-29217": "pyjwt_cve_2022_29217.py",
    "GHSA-8q59-q68h-6hv4": "pyyaml_cve_2020_14343.py", "CVE-2020-14343": "pyyaml_cve_2020_14343.py",
}


@dataclass
class RunOptions:
    repo: str
    package: str | None = None
    target: str | None = None
    branch: bool = False
    open_pr: bool = False
    keep_workspace: bool = False
    max_iterations: int | None = None
    max_diff_lines: int | None = None


@dataclass
class RunResult:
    run_id: str
    status: str = "running"  # success | needs_review | failed
    data: dict = field(default_factory=dict)


def _new_run_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]


def resolve_repo(spec: str, bus: EventBus) -> tuple[Path, str | None]:
    """Local path, or clone a GitHub URL into a temp dir. Returns (path, github 'owner/repo' or None)."""
    m = re.match(r"^(?:https?://github\.com/|git@github\.com:)([\w.-]+/[\w.-]+?)(?:\.git)?/?$", spec.strip())
    if m:
        dest = Path(tempfile.mkdtemp(prefix="leaply-src-")) / "repo"
        bus.emit("log", step="scan", message=f"cloning {m.group(1)}")
        proc = subprocess.run(["git", "clone", "--depth", "1", spec, str(dest)], capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed: {proc.stderr[-500:]}")
        return dest, m.group(1)
    path = Path(spec).expanduser().resolve()
    if not path.is_dir():
        raise FileNotFoundError(f"repository not found: {spec}")
    # a local checkout of a GitHub repo (e.g. inside GitHub Actions) can still get a pull request
    origin = subprocess.run(["git", "remote", "get-url", "origin"], cwd=path, capture_output=True, text=True)
    om = re.match(r"^(?:https?://(?:[^@/]+@)?github\.com/|git@github\.com:)([\w.-]+/[\w.-]+?)(?:\.git)?/?$", origin.stdout.strip())
    if origin.returncode == 0 and om and (path / ".git").exists():
        return path, om.group(1)
    return path, None


def pick_finding(findings: list[Finding], package: str | None) -> Finding | None:
    if package:
        return next((f for f in findings if f.package.name.lower() == package.lower()), None)
    return max(findings, key=lambda f: f.score) if findings else None


def _proof_status(res: TestResult) -> str:
    case = next((c for c in res.cases if "leaply_security_proof" in c["name"]), None)
    if case is None:
        return "error"
    return case["status"]


def _proof_is_valid_red(res: TestResult) -> bool:
    """A proof is only meaningful if it fails because the attack succeeded, not because it is broken."""
    case = next((c for c in res.cases if "leaply_security_proof" in c["name"]), None)
    if not case or case["status"] != "failed":
        return False
    bad = ("ImportError", "ModuleNotFoundError", "SyntaxError", "NameError", "AttributeError", "fixture")
    return not any(b in (case["message"] + case["detail"]) for b in bad)


class Pipeline:
    def __init__(self, opts: RunOptions, bus: EventBus | None = None, llm: LLM | None = None,
                 cfg: Settings | None = None):
        self.opts = opts
        self.cfg = cfg or default_settings
        self.run_id = bus.run_id if bus else _new_run_id()
        self.bus = bus or EventBus(self.run_id)
        self.llm = llm or LLM(self.bus, self.cfg)
        self.llm.bus = self.bus
        self.max_iter = opts.max_iterations or self.cfg.max_iterations
        # no test file is editable by an agent, including the security proof (it must not be "fixed" to pass)
        self.guard = Guardrails(opts.max_diff_lines or self.cfg.max_diff_lines, set())
        self.result = RunResult(self.run_id)
        self.files_changed: dict[str, str] = {}  # path -> original content
        self.ws: Workspace | None = None

    # -- helpers --------------------------------------------------------------
    def step(self, name: str, title: str, actor: str = "system", **kw):
        self.bus.emit("step_start", step=name, actor=actor, title=title, **kw)

    def done(self, name: str, actor: str = "system", status: str = "ok", **kw):
        self.bus.emit("step_end", step=name, actor=actor, status=status, **kw)

    def tests_event(self, step: str, label: str, res: TestResult, **kw):
        self.bus.emit("tests", step=step, actor="sandbox", label=label, **res.to_dict(), **kw)

    def current_diff(self) -> dict[str, str]:
        out = {}
        # dependency file first, source files next, the added security test last
        for path, before in sorted(self.files_changed.items(), key=lambda kv: kv[0] == PROOF_PATH):
            after = self.ws.read(path) if (self.ws.repo / path).exists() else ""
            d = make_diff(path, before, after)
            if d:
                out[path] = d
        return out

    def apply_agent_diff(self, path: str, diff_text: str, step: str, instructions: str, actor: str = "super") -> bool:
        """Apply a model diff to one file, behind guardrails; fall back to a full rewrite if the diff does not apply."""
        if self.guard.check_edit(path):
            self.bus.emit("guardrail", step=step, actor="system", status="rejected", path=path, reason=self.guard.violations[-1])
            return False
        if not (self.ws.repo / path).exists():
            self.bus.emit("guardrail", step=step, actor="system", status="rejected", path=path, reason=f"{path}: file does not exist")
            return False
        before = self.ws.read(path)
        per_file = split_file_diffs(diff_text)
        other = [p for p in per_file if p.replace("\\", "/") != path and p != "/dev/null"]
        for p in other:
            self.guard.violations.append(f"{p}: diff touched a file outside this edit")
            self.bus.emit("guardrail", step=step, actor="system", status="rejected", path=p,
                          reason="edit for one file tried to change another file")
        body = per_file.get(path) or next(iter(per_file.values()), diff_text)
        try:
            after = apply_unified_diff(before, body)
            how = "diff"
        except PatchError as exc:
            self.bus.emit("log", step=step, actor=actor, level="warn", message=f"{path}: diff did not apply ({exc}); asking for full file")
            after = agents.rewrite_file(self.llm, path, before, instructions, step)
            how = "rewrite"
        if after.strip() == before.strip():
            self.bus.emit("log", step=step, actor=actor, level="warn", message=f"{path}: no change produced")
            return False
        self.files_changed.setdefault(path, before)
        self.ws.write(path, after)
        add, rem = diff_stats(make_diff(path, before, after))
        self.bus.emit("file_changed", step=step, actor=actor, path=path, added=add, removed=rem, how=how,
                      diff=make_diff(path, before, after))
        return True

    # -- the run ----------------------------------------------------------------
    def run(self) -> RunResult:
        try:
            self._run()
        except Exception as exc:  # noqa: BLE001
            self.result.status = "failed"
            self.result.data["error"] = f"{type(exc).__name__}: {exc}"
            self.bus.emit("error", step="run", message=self.result.data["error"])
        finally:
            self.bus.done = True
            data = self.result.data
            data.setdefault("audit", {})
            data["audit"].update({
                "model_calls": self.llm.ledger.calls,
                "commands": self.ws.commands if self.ws else [],
                "files_changed": list(self.files_changed),
            })
            self.bus.emit("finished", step="run", status=self.result.status, result=_public(data))
            self.bus.save(self.cfg.runs_dir / f"{self.run_id}.json",
                          {"result": data, "status": self.result.status, "simulated": self.llm.simulated})
            if self.ws and not self.opts.keep_workspace:
                self.ws.cleanup()
        return self.result

    def _run(self):
        bus, opts, cfg = self.bus, self.opts, self.cfg
        data = self.result.data
        bus.emit("run_start", step="run", repo=opts.repo, models={r: s.model_id for r, s in cfg.models.items()},
                 limits={"max_iterations": self.max_iter, "max_diff_lines": self.guard.max_diff_lines,
                         "same_error_limit": cfg.same_error_limit})
        src, gh_repo = resolve_repo(opts.repo, bus)
        data["github_repo"] = gh_repo

        # 1. SCAN ------------------------------------------------------------------
        self.step("scan", "Scan dependencies (OSV.dev)", actor="osv")
        deps, findings = scan_repo(src)
        bus.emit("log", step="scan", actor="osv", message=f"{len(deps)} pinned dependencies, {len(findings)} vulnerable")

        # 2. TRIAGE --------------------------------------------------------------------
        self.step("triage", "Reachability triage", actor="nano")
        triage_llm = self.llm if cfg.llm_enabled else None
        for f in findings:
            run_triage(src, f, triage_llm)
        findings.sort(key=lambda f: -f.score)
        bus.emit("findings", step="scan", actor="osv", findings=[f.to_dict() for f in findings])
        self.done("scan", actor="osv", summary=f"{sum(len(f.advisories) for f in findings)} advisories in {len(findings)} packages")
        self.done("triage", actor="nano", summary=", ".join(f"{f.package.name}: {f.reachability['verdict']}" for f in findings))
        finding = pick_finding(findings, opts.package)
        if finding is None:
            self.result.status = "success"
            data["summary"] = "No known vulnerabilities in pinned dependencies." if not opts.package else f"{opts.package}: no known vulnerabilities."
            return
        if opts.target == "minimal":  # smallest jump that closes every advisory
            target = finding.fixed_version or finding.latest_version
        else:
            target = opts.target or finding.latest_version or finding.fixed_version
        data["finding"] = finding.to_dict()
        data["target"] = target
        primary = next((a for a in finding.advisories if a.id in VETTED_PROOFS or a.cve in VETTED_PROOFS), finding.advisories[0])
        bus.emit("selected", step="triage", actor="nano", package=finding.package.name, current=finding.package.version,
                 target=target, advisory=primary.id, cve=primary.cve, severity=finding.severity,
                 verdict=finding.reachability.get("verdict"))

        # 3. RESEARCH -----------------------------------------------------------------
        self.step("research", "Research advisory and migration guide", actor="tavily")
        research = run_research(finding, target, bus, api_key=cfg.tavily_api_key)
        data["sources"] = research["sources"]
        self.done("research", actor="tavily", summary=f"{len(research['sources'])} sources, {len(research['extracts'])} pages extracted")

        # 4. BASELINE ------------------------------------------------------------------
        self.step("baseline", "Baseline tests on the current version", actor="sandbox")
        self.ws = ws = Workspace(src, bus, cfg.test_timeout)
        ws.create_venv("baseline")
        if not ws.install("baseline"):
            raise RuntimeError("could not install the project's dependencies")
        baseline = ws.run_tests("baseline")
        self.tests_event("baseline", f"{finding.package.name} {finding.package.version}", baseline)
        data["tests_before"] = baseline.to_dict()
        self.done("baseline", actor="sandbox", summary=f"{baseline.passed}/{baseline.total} passing")

        snapshot = agents.repo_snapshot(ws.repo, cfg.max_repo_chars)

        # 5. SECURITY PROOF -----------------------------------------------------------
        self.step("proof", "Write security regression test", actor="ultra")
        proof = self._security_proof(finding, primary, research, snapshot)
        data["proof"] = proof
        self.done("proof", actor="ultra" if proof["source"] == "ultra" else "system",
                  summary=f"attack {'ACCEPTED' if proof['before'] == 'failed' else 'rejected'} on {finding.package.version}")

        # 6. BUMP ------------------------------------------------------------------------
        self.step("bump", f"Bump {finding.package.name} {finding.package.version} -> {target}", actor="system")
        dep_file = finding.package.file
        before_req = ws.read(dep_file)
        new_req, n = bump_requirement(before_req, finding.package.name, target)
        if n == 0:
            raise RuntimeError(f"could not find {finding.package.name} in {dep_file}")
        self.files_changed[dep_file] = before_req
        ws.write(dep_file, new_req)
        bus.emit("file_changed", step="bump", actor="system", path=dep_file, added=1, removed=1, how="deterministic",
                 diff=make_diff(dep_file, before_req, new_req))
        ws.create_venv("bump")
        if not ws.install("bump"):
            raise RuntimeError(f"could not install {finding.package.name}=={target}")
        installed = ws.installed_version(finding.package.name, "bump")
        broken = ws.run_tests("bump")
        self.tests_event("bump", f"{finding.package.name} {installed}, code unchanged", broken)
        data["tests_after_bump"] = broken.to_dict()
        self.done("bump", summary=f"{broken.failed + broken.errors} tests broken by the upgrade")

        # 7. PLAN ---------------------------------------------------------------------------
        self.step("plan", "Plan the migration (whole repo in context)", actor="ultra")
        plan = agents.plan_migration(self.llm, finding, target, snapshot, research, finding.reachability, broken.failures_text())
        plan["files"] = [f for f in plan.get("files", []) if isinstance(f, dict) and f.get("path")]
        data["plan"] = plan
        bus.emit("plan", step="plan", actor="ultra", plan=plan)
        self.done("plan", actor="ultra", summary=f"{len(plan['files'])} files, risk {plan.get('overall_risk', '?')}")

        # 8. EDIT ---------------------------------------------------------------------------
        self.step("edit", "Apply the plan file by file", actor="super")
        for item in plan["files"]:
            path = item["path"].replace("\\", "/").lstrip("./")
            if self.guard.check_edit(path):
                bus.emit("guardrail", step="edit", status="rejected", path=path, reason=self.guard.violations[-1])
                continue
            if not (ws.repo / path).exists():
                bus.emit("log", step="edit", level="warn", message=f"plan names {path}, which does not exist; skipped")
                continue
            instructions = "\n".join(item.get("changes", []))
            d = agents.edit_file(self.llm, path, ws.read(path), item, plan, finding, target)
            self.apply_agent_diff(path, d, "edit", instructions)
        self.done("edit", actor="super", summary=f"{len(self._agent_files())} source files changed")

        # 9. VERIFY + FIX LOOP ----------------------------------------------------------------
        result = self._verify_and_fix(finding, target)
        data["tests_after"] = result.to_dict()
        data["proof"]["after"] = _proof_status(result)

        # 10. RESCAN ----------------------------------------------------------------------------
        self.step("rescan", "Re-scan the upgraded dependency", actor="osv")
        remaining = vulns_for(finding.package.name, installed or target, finding.package.ecosystem)
        closed = [a.id for a in finding.advisories if a.id not in remaining and not set(a.aliases) & set(remaining)]
        audit = _pip_audit(ws)
        data["rescan"] = {"package": finding.package.name, "version": installed or target, "remaining": remaining,
                          "closed": closed, "pip_audit": audit}
        bus.emit("rescan", step="rescan", actor="osv", **data["rescan"])
        self.done("rescan", actor="osv", summary=f"{len(remaining)} known vulnerabilities for {finding.package.name} {installed or target}")

        # 11. EXPLAIN + REPORT ---------------------------------------------------------------------
        diffs = self.current_diff()
        data["diff"] = diffs
        total_lines = sum(sum(diff_stats(d)) for p, d in diffs.items() if p != PROOF_PATH)
        self.guard.check_size(total_lines)
        secrets = scan_secrets("\n".join(diffs.values()))
        data["guardrails"] = self.guard.summary(secrets)
        self.step("explain", "Explain each change for the reviewer", actor="nano")
        try:
            explained = agents.explain_changes(self.llm, diffs, finding, target)
        except LLMError as exc:
            explained = {"files": {}, "reviewer_summary": {"what_changed": f"(explanation unavailable: {exc})", "risk": plan.get("overall_risk", "medium"), "double_check": plan.get("risks", [])}}
        data["explanations"] = explained.get("files", {})
        data["reviewer_summary"] = explained.get("reviewer_summary", {})
        bus.emit("explanations", step="explain", actor="nano", files=data["explanations"], reviewer_summary=data["reviewer_summary"])
        self.done("explain", actor="nano")

        self.step("review", "Adversarial security review of the final diff", actor="ultra")
        try:
            review = agents.security_review(self.llm, diffs, finding, target)
            review["findings"] = [f for f in review.get("findings", []) if isinstance(f, dict)]
        except LLMError as exc:
            review = {"verdict": "unavailable", "findings": [], "summary": f"review failed: {exc}"}
        data["security_review"] = review
        bus.emit("security_review", step="review", actor="ultra", **review)
        high = [f for f in review["findings"] if f.get("severity") == "high"]
        self.done("review", actor="ultra", status="ok" if not high else "warn",
                  summary=f"{review.get('verdict')}: {len(review['findings'])} note(s), {len(high)} high")

        data["cost"] = self.llm.ledger.summary(cfg.models)
        data["confidence"] = confidence(data, self.max_iter)
        success = result.ok and data["proof"]["after"] == "passed" and not secrets and not high
        self.result.status = "success" if success else "needs_review"
        data["status"] = self.result.status

        from .report import build_report, deliver, sarif
        data["report_md"] = build_report(data, self.run_id)
        bus.emit("report", step="report", markdown=data["report_md"], sarif=sarif(data))
        delivery = deliver(self, data, src, gh_repo)
        data["delivery"] = delivery
        bus.emit("delivery", step="pr", actor="github", **delivery)
        bus.emit("cost", step="report", **data["cost"])

    # -- sub-steps ---------------------------------------------------------------------------
    def _security_proof(self, finding: Finding, primary, research: dict, snapshot: str) -> dict:
        ws, bus = self.ws, self.bus
        proof = {"advisory": primary.id, "cve": primary.cve, "source": None, "before": None, "after": None, "code": ""}
        candidates: list[tuple[str, str]] = []
        if self.cfg.llm_enabled:
            try:
                candidates.append(("ultra", agents.write_security_test(self.llm, finding, snapshot, research, primary.cve or primary.id)))
            except LLMError as exc:
                bus.emit("log", step="proof", actor="ultra", level="warn", message=f"security test generation failed: {exc}")
        vetted = VETTED_PROOFS.get(primary.id) or VETTED_PROOFS.get(primary.cve or "")
        if vetted:
            candidates.append(("vetted", (PROOFS_DIR / vetted).read_text(encoding="utf-8")))
        for source, code in candidates:
            ws.write(PROOF_PATH, code)
            res = ws.run_tests("proof", [PROOF_PATH])
            status = _proof_status(res)
            if _proof_is_valid_red(res):
                proof.update(source=source, before="failed", code=code)
                self.files_changed[PROOF_PATH] = ""  # new file: shipped in the PR as a regression test
                bus.emit("proof", step="proof", actor=source if source == "ultra" else "system", phase="before",
                         status="failed", source=source, code=code,
                         message=f"Attack accepted by {finding.package.name} {finding.package.version}: the test fails, as expected on vulnerable code")
                return proof
            bus.emit("log", step="proof", actor=source, level="warn",
                     message=f"{source} security test did not demonstrate the attack (status: {status}); discarded")
        (ws.repo / PROOF_PATH).unlink(missing_ok=True)
        proof.update(source="none", before="unavailable")
        bus.emit("proof", step="proof", phase="before", status="unavailable", source="none",
                 message="No validated security test for this advisory")
        return proof

    def _verify_and_fix(self, finding: Finding, target: str) -> TestResult:
        ws, bus, cfg = self.ws, self.bus, self.cfg
        signatures: dict[str, int] = {}
        tried: list[str] = []
        res = TestResult()
        for iteration in range(1, self.max_iter + 1):
            self.step("verify", f"Run tests (iteration {iteration})", actor="sandbox", iteration=iteration)
            res = ws.run_tests("verify")
            proof_status = _proof_status(res)
            self.tests_event("verify", f"iteration {iteration}", res, iteration=iteration, proof=proof_status)
            if (self.ws.repo / PROOF_PATH).exists():
                bus.emit("proof", step="verify", phase="after", status=proof_status, iteration=iteration)
            self.done("verify", actor="sandbox", summary=f"{res.passed}/{res.total} passing", iteration=iteration)
            self.result.data["iterations"] = iteration
            if res.ok:
                return res
            if iteration == self.max_iter:
                break
            self.step("fix", f"Triage and fix (iteration {iteration})", actor="nano", iteration=iteration)
            failures = res.failures_text()
            editable = self._source_files()
            try:
                tri = agents.triage_failure(self.llm, failures, editable, "fix")
            except LLMError as exc:
                tri = {"category": "other", "root_cause": str(exc), "files": self._agent_files(), "signature": failures[:120]}
            sig = re.sub(r"0x[0-9a-f]+|\d+", "#", str(tri.get("signature") or failures[:160]))[:160]
            signatures[sig] = signatures.get(sig, 0) + 1
            bus.emit("triage_failure", step="fix", actor="nano", iteration=iteration, **tri, repeats=signatures[sig])
            if signatures[sig] >= cfg.same_error_limit:
                bus.emit("handover", step="fix", reason=f"same error seen {signatures[sig]} times: {tri.get('root_cause')}", tried=tried)
                self.result.data["handover"] = {"reason": f"same error repeated {signatures[sig]} times", "error": tri.get("root_cause"), "tried": tried}
                self.done("fix", actor="nano", status="handover")
                return res
            targets = [p for p in tri.get("files", []) if p in editable] or self._agent_files()
            for path in targets[:4]:
                d = agents.fix_file(self.llm, path, ws.read(path), failures, tri, finding, target, "fix")
                if self.apply_agent_diff(path, d, "fix", f"Fix so the tests pass: {tri.get('root_cause')}"):
                    tried.append(f"iteration {iteration}: {path} ({tri.get('root_cause')})")
            self.done("fix", actor="super", summary=tri.get("root_cause", ""), iteration=iteration)
        if not res.ok:
            self.result.data.setdefault("handover", {"reason": f"tests still failing after {self.max_iter} iterations",
                                                     "error": res.failures_text(400), "tried": tried})
            bus.emit("handover", step="fix", reason=self.result.data["handover"]["reason"], tried=tried)
        return res

    def _agent_files(self) -> list[str]:
        dep = (self.result.data.get("finding") or {}).get("package", {}).get("file")
        return [p for p in self.files_changed if p not in (dep, PROOF_PATH)]

    def _source_files(self) -> list[str]:
        out = []
        for p in sorted(self.ws.repo.rglob("*.py")):
            rel = p.relative_to(self.ws.repo).as_posix()
            if not check_path_quiet(rel):
                out.append(rel)
        return out


def check_path_quiet(path: str) -> str | None:
    from .guardrails import check_path
    return check_path(path, set())


def _pip_audit(ws: Workspace) -> dict:
    exe = shutil.which("pip-audit")
    if not exe:
        return {"ran": False, "reason": "pip-audit not installed"}
    reqs = sorted(ws.repo.glob("requirements*.txt"))
    if not reqs:
        return {"ran": False, "reason": "no requirements file"}
    proc = ws.run([exe, "-r", str(reqs[0]), "-f", "json", "--progress-spinner", "off"], "rescan", timeout=300)
    try:
        report = json.loads(proc.stdout)
        deps = report.get("dependencies", report if isinstance(report, list) else [])
        vulns = sum(len(d.get("vulns", [])) for d in deps)
        return {"ran": True, "vulnerabilities": vulns}
    except (json.JSONDecodeError, AttributeError):
        return {"ran": False, "reason": "pip-audit output not parseable"}


def confidence(data: dict, max_iter: int) -> dict:
    after = data.get("tests_after", {})
    proof = data.get("proof", {})
    score, reasons = 0, []
    if after.get("ok"):
        score += 40
        reasons.append(f"all {after.get('total')} tests pass (+40)")
    else:
        reasons.append(f"{after.get('failed', 0) + after.get('errors', 0)} tests failing (+0)")
    if proof.get("after") == "passed" and proof.get("before") == "failed":
        score += 25
        reasons.append("security proof red -> green (+25)")
    it = data.get("iterations", max_iter)
    pts = max(0, 15 - 3 * (it - 1))
    score += pts
    reasons.append(f"{it} test iteration(s) (+{pts})")
    lines = sum(sum(diff_stats(d)) for p, d in data.get("diff", {}).items() if p != PROOF_PATH)
    pts = 10 if lines <= 40 else 5 if lines <= 150 else 0
    score += pts
    reasons.append(f"{lines} changed lines (+{pts})")
    if not data.get("rescan", {}).get("remaining"):
        score += 10
        reasons.append("0 known vulnerabilities remain (+10)")
    review = data.get("security_review", {})
    high = [f for f in review.get("findings", []) if f.get("severity") == "high"]
    if high:
        score -= 30
        reasons.append(f"security review raised {len(high)} high concern(s) (-30)")
    elif review.get("verdict") == "approve":
        reasons.append("security review approved (+0)")
    score = max(score, 0)
    level ="high" if score >= 85 else "medium" if score >= 60 else "low"
    return {"score": score, "level": level, "reasons": reasons,
            "needs_human_review": score < 60 or not after.get("ok") or "handover" in data}


def _public(data: dict) -> dict:
    """The run result without bulky fields, for the final event."""
    return {k: v for k, v in data.items() if k not in ("audit", "report_md")}
