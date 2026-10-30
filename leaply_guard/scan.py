"""Dependency scan against OSV.dev (free, no key): requirements.txt, pyproject.toml, package.json."""
from __future__ import annotations

import json
import math
import re
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path

import httpx

OSV = "https://api.osv.dev/v1"
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str  # PyPI | npm
    file: str
    line: int


@dataclass
class Advisory:
    id: str
    aliases: list[str]
    summary: str
    severity: str
    cvss_score: float | None
    fixed: str | None
    url: str
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_ransomware: bool = False

    @property
    def cve(self) -> str | None:
        return next((a for a in [self.id, *self.aliases] if a.startswith("CVE-")), None)


@dataclass
class Finding:
    id: str  # stable id, e.g. pypi:pyjwt
    package: Dependency
    advisories: list[Advisory]
    fixed_version: str | None  # lowest version that closes every advisory
    latest_version: str | None
    severity: str = "UNKNOWN"
    reachability: dict = field(default_factory=dict)
    score: float = 0.0
    epss: float = 0.0
    kev: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        for a, adv in zip(d["advisories"], self.advisories):
            a["cve"] = adv.cve
        return d


# --- dependency parsing ---------------------------------------------------------
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.+!-]+)")


def parse_dependencies(repo: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    for req in sorted(repo.glob("requirements*.txt")):
        for i, line in enumerate(req.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            m = _REQ.match(line.split("#", 1)[0])
            if m:
                deps.append(Dependency(m.group(1), m.group(2), "PyPI", req.name, i))
    pyproject = repo / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            text = pyproject.read_text(encoding="utf-8").splitlines()
            for spec in data.get("project", {}).get("dependencies", []):
                m = _REQ.match(spec)
                if m:
                    line = next((i for i, l in enumerate(text, 1) if spec in l), 0)
                    deps.append(Dependency(m.group(1), m.group(2), "PyPI", "pyproject.toml", line))
        except tomllib.TOMLDecodeError:
            pass
    pkg = repo / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            text = pkg.read_text(encoding="utf-8").splitlines()
            for section in ("dependencies", "devDependencies"):
                for name, ver in (data.get(section) or {}).items():
                    v = re.sub(r"^[\^~=v]+", "", str(ver))
                    if re.match(r"^\d+\.\d+", v):
                        line = next((i for i, l in enumerate(text, 1) if f'"{name}"' in l), 0)
                        deps.append(Dependency(name, v, "npm", "package.json", line))
        except json.JSONDecodeError:
            pass
    return deps


# --- CVSS 3.x base score --------------------------------------------------------
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0},
    "A": {"H": 0.56, "L": 0.22, "N": 0},
}


def cvss3_score(vector: str) -> float | None:
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        raw = min(1.08 * (impact + expl), 10) if changed else min(impact + expl, 10)
        return math.ceil(raw * 10 - 1e-9) / 10
    except (KeyError, ValueError, IndexError):
        return None


def _label(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MODERATE" if score >= 4 else "LOW"


def _vkey(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.+-]", v)[:4])


# --- OSV queries ----------------------------------------------------------------
def _advisory(vuln: dict, package: str) -> Advisory:
    score = None
    for s in vuln.get("severity") or []:
        if s.get("type", "").startswith("CVSS_V3"):
            score = cvss3_score(s["score"])
    label = (vuln.get("database_specific") or {}).get("severity") or _label(score)
    fixed = None
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != package.lower():
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for ev in rng.get("events", []):
                if "fixed" in ev and (fixed is None or _vkey(ev["fixed"]) > _vkey(fixed)):
                    fixed = ev["fixed"]
    refs = vuln.get("references") or []
    url = next((r["url"] for r in refs if r.get("type") == "ADVISORY"), f"https://osv.dev/vulnerability/{vuln['id']}")
    return Advisory(vuln["id"], vuln.get("aliases") or [], vuln.get("summary") or vuln.get("details", "")[:160],
                    label.upper(), score, fixed, url)


def latest_version(dep: Dependency, client: httpx.Client) -> str | None:
    try:
        if dep.ecosystem == "PyPI":
            return client.get(f"https://pypi.org/pypi/{dep.name}/json").json()["info"]["version"]
        return client.get(f"https://registry.npmjs.org/{dep.name}/latest").json()["version"]
    except Exception:
        return None


def query_osv(deps: list[Dependency], client: httpx.Client) -> list[list[str]]:
    body = {"queries": [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in deps]}
    res = client.post(f"{OSV}/querybatch", json=body).json().get("results", [])
    return [[v["id"] for v in (r.get("vulns") or [])] for r in res]


def scan_repo(repo: Path, timeout: float = 30) -> tuple[list[Dependency], list[Finding]]:
    deps = parse_dependencies(repo)
    if not deps:
        return deps, []
    findings: list[Finding] = []
    with httpx.Client(timeout=timeout, headers={"User-Agent": "leaply-guard"}, transport=httpx.HTTPTransport(retries=3)) as client:
        for dep, ids in zip(deps, query_osv(deps, client)):
            if not ids:
                continue
            details = [client.get(f"{OSV}/vulns/{i}").json() for i in ids]
            # collapse aliases (GHSA / PYSEC / CVE describe the same issue): keep one per group, prefer GHSA
            groups: dict[str, Advisory] = {}
            seen: dict[str, str] = {}
            for v in sorted(details, key=lambda v: (not v["id"].startswith("GHSA"), v["id"])):
                adv = _advisory(v, dep.name)
                keys = {adv.id, *adv.aliases}
                owner = next((seen[k] for k in keys if k in seen), None)
                if owner:
                    g = groups[owner]
                    if g.fixed is None or (adv.fixed and _vkey(adv.fixed) > _vkey(g.fixed)):
                        g.fixed = g.fixed or adv.fixed
                    if g.cvss_score is None:
                        g.cvss_score, g.severity = adv.cvss_score, adv.severity
                    for k in keys:
                        seen[k] = owner
                    continue
                groups[adv.id] = adv
                for k in keys:
                    seen[k] = adv.id
            advs = sorted(groups.values(), key=lambda a: (-SEVERITY_RANK.get(a.severity, 0), -(a.cvss_score or 0)))
            fixes = [a.fixed for a in advs if a.fixed]
            fixed_version = max(fixes, key=_vkey) if fixes else None
            sev = advs[0].severity if advs else "UNKNOWN"
            findings.append(Finding(
                id=f"{dep.ecosystem.lower()}:{dep.name.lower()}", package=dep, advisories=advs,
                fixed_version=fixed_version, latest_version=latest_version(dep, client), severity=sev,
            ))
    from .intel import enrich
    enrich(findings)
    return deps, findings


def vulns_for(name: str, version: str, ecosystem: str = "PyPI", timeout: float = 30) -> list[str]:
    """Ids still reported by OSV for an exact version (used to prove the fix closed the advisory)."""
    with httpx.Client(timeout=timeout, transport=httpx.HTTPTransport(retries=3)) as client:
        ids = query_osv([Dependency(name, version, ecosystem, "", 0)], client)[0]
    return ids
