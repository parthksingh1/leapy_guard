"""Runtime research with Tavily: the security advisory and the official migration guide / changelog."""
from __future__ import annotations

import httpx

from .config import settings
from .events import EventBus
from .scan import Finding

TAVILY = "https://api.tavily.com"


def _post(path: str, body: dict, key: str, timeout: float = 40) -> dict:
    last = None
    for _ in range(3):
        try:
            r = httpx.post(f"{TAVILY}/{path}", json=body, timeout=timeout,
                           headers={"Authorization": f"Bearer {key}"})
            r.raise_for_status()
            return r.json()
        except httpx.HTTPError as exc:
            last = exc
    raise RuntimeError(f"Tavily {path} failed: {last}")


def research(finding: Finding, target: str, bus: EventBus, step: str = "research", api_key: str | None = None) -> dict:
    key = settings.tavily_api_key if api_key is None else api_key
    pkg = finding.package.name
    primary = finding.advisories[0] if finding.advisories else None
    cve = next((a.cve for a in finding.advisories if a.cve), None)
    queries = [
        f"{cve or (primary.id if primary else pkg)} {pkg} security advisory",
        f"{pkg} {finding.package.version.split('.')[0]}.x to {target.split('.')[0]}.0 migration guide breaking changes changelog",
    ]
    sources: list[dict] = []
    extracts: list[dict] = []

    if key:
        for q in queries:
            bus.emit("log", step=step, actor="tavily", message=f"search: {q}")
            res = _post("search", {"query": q, "max_results": 5, "search_depth": "advanced"}, key)
            for r in res.get("results", []):
                if r["url"] not in {s["url"] for s in sources}:
                    sources.append({"title": r.get("title", r["url"]), "url": r["url"], "snippet": (r.get("content") or "")[:300],
                                    "score": r.get("score"), "query": q, "via": "tavily"})
        top = sorted(sources, key=lambda s: -(s.get("score") or 0))[:5]
        if top:
            bus.emit("log", step=step, actor="tavily", message=f"extract: {len(top)} pages")
            res = _post("extract", {"urls": [s["url"] for s in top], "query": f"{pkg} breaking changes {target}",
                                    "chunks_per_source": 3, "format": "markdown"}, key, timeout=60)
            for r in res.get("results", []):
                extracts.append({"url": r["url"], "content": (r.get("raw_content") or "")[:12000]})
    else:
        bus.emit("log", step=step, actor="tavily", level="warn",
                 message="TAVILY_API_KEY not set: falling back to the OSV advisory references only")

    # the OSV advisories are always included as primary sources
    for a in finding.advisories[:5]:
        if a.url not in {s["url"] for s in sources}:
            sources.append({"title": f"{a.id} {a.cve or ''}: {a.summary}".strip(), "url": a.url, "snippet": a.summary,
                            "score": None, "query": "osv", "via": "osv"})
    bus.emit("sources", step=step, actor="tavily", sources=sources, extracted=[e["url"] for e in extracts])
    return {"sources": sources, "extracts": extracts}
