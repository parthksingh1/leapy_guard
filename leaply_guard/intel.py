"""Exploit intelligence: FIRST EPSS (probability of exploitation) and CISA KEV (known exploited). Both free, no key."""
from __future__ import annotations

import time

import httpx

EPSS = "https://api.first.org/data/v1/epss"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_kev_cache: tuple[float, dict] | None = None


def kev_catalog(timeout: float = 30) -> dict[str, dict]:
    """CVE id -> KEV entry. Cached for 12 hours per process."""
    global _kev_cache
    if _kev_cache and time.time() - _kev_cache[0] < 43200:
        return _kev_cache[1]
    try:
        data = httpx.get(KEV, timeout=timeout, follow_redirects=True, headers={"User-Agent": "leaply-guard"}).json()
        cat = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    except Exception:
        cat = {}
    _kev_cache = (time.time(), cat)
    return cat


def epss_scores(cves: list[str], timeout: float = 20) -> dict[str, dict]:
    out: dict[str, dict] = {}
    cves = sorted(set(c for c in cves if c.startswith("CVE-")))
    for i in range(0, len(cves), 50):
        try:
            res = httpx.get(EPSS, params={"cve": ",".join(cves[i:i + 50])}, timeout=timeout).json()
            for row in res.get("data", []):
                out[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": row.get("date")}
        except Exception:
            continue
    return out


def enrich(findings) -> None:
    """Attach EPSS and KEV to every advisory, and the strongest signal to each finding."""
    cves = [a.cve for f in findings for a in f.advisories if a.cve]
    if not cves:
        return
    scores = epss_scores(cves)
    kev = kev_catalog()
    for f in findings:
        for a in f.advisories:
            s = scores.get(a.cve or "")
            a.epss = s["epss"] if s else None
            a.epss_percentile = s["percentile"] if s else None
            entry = kev.get(a.cve or "")
            a.kev = bool(entry)
            a.kev_ransomware = bool(entry and entry.get("knownRansomwareCampaignUse") == "Known")
        f.epss = max((a.epss or 0 for a in f.advisories), default=0.0)
        f.kev = any(a.kev for a in f.advisories)


def priority(severity_rank: int, reach_weight: float, epss: float, kev: bool) -> float:
    """Severity x reachability, boosted by exploit likelihood; a known-exploited CVE always jumps the queue."""
    score = severity_rank * reach_weight * (1 + 2 * min(epss, 1.0))
    if kev and reach_weight > 0.1:
        score += 5
    return round(score, 2)
