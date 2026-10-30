"""Standard exports: CycloneDX 1.5 SBOM (with vulnerabilities) and OpenVEX (reachability as VEX statements)."""
from __future__ import annotations

import time
import uuid

from . import __version__


def _purl(dep: dict) -> str:
    eco = {"PyPI": "pypi", "npm": "npm"}.get(dep["ecosystem"], dep["ecosystem"].lower())
    name = dep["name"].lower() if eco == "pypi" else dep["name"]
    return f"pkg:{eco}/{name}@{dep['version']}"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def cyclonedx(deps: list[dict], findings: list[dict], project: str = "project") -> dict:
    components = [{"type": "library", "bom-ref": _purl(d), "name": d["name"], "version": d["version"], "purl": _purl(d)}
                  for d in deps]
    vulns = []
    for f in findings:
        ref = _purl(f["package"])
        for a in f["advisories"]:
            v = {
                "bom-ref": f"{a['id']}@{ref}", "id": a.get("cve") or a["id"],
                "source": {"name": "OSV", "url": a["url"]},
                "references": [{"id": a["id"], "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{a['id']}"}}],
                "ratings": [{"severity": a["severity"].lower().replace("moderate", "medium"), "method": "CVSSv31",
                             **({"score": a["cvss_score"]} if a.get("cvss_score") else {})}],
                "description": a["summary"],
                "affects": [{"ref": ref}],
                "analysis": {"state": "exploitable" if f["reachability"].get("verdict") == "REACHABLE" else
                             "not_affected" if f["reachability"].get("verdict") == "NOT USED" else "in_triage",
                             "detail": f["reachability"].get("reasoning", "")[:500]},
            }
            if a.get("fixed"):
                v["recommendation"] = f"Upgrade {f['package']['name']} to {a['fixed']} or later."
            if a.get("epss") is not None:
                v["properties"] = [{"name": "epss", "value": str(a["epss"])}, {"name": "cisa-kev", "value": str(a.get("kev", False)).lower()}]
            vulns.append(v)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": _now(), "tools": [{"vendor": "Leaply Guard", "name": "leaply-guard", "version": __version__}],
                     "component": {"type": "application", "name": project, "bom-ref": project}},
        "components": components, "vulnerabilities": vulns,
    }


def openvex(findings: list[dict], author: str = "Leaply Guard") -> dict:
    """VEX: tell downstream scanners which advisories do not affect this product, and why."""
    statements = []
    for f in findings:
        verdict = f["reachability"].get("verdict")
        product = {"@id": _purl(f["package"])}
        for a in f["advisories"]:
            st = {"vulnerability": {"name": a.get("cve") or a["id"], "aliases": [a["id"]]}, "products": [product]}
            if verdict == "NOT USED":
                st.update(status="not_affected", justification="vulnerable_code_not_in_execute_path",
                          impact_statement=f["reachability"].get("reasoning", "")[:300])
            elif verdict == "REACHABLE":
                st.update(status="affected", action_statement=f"Upgrade to {f.get('fixed_version') or 'a fixed version'} (leaply-guard run --package {f['package']['name']}).")
            else:
                st.update(status="under_investigation")
            statements.append(st)
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"https://openvex.dev/docs/leaply-guard/{uuid.uuid4()}",
            "author": author, "timestamp": _now(), "version": 1, "statements": statements}
