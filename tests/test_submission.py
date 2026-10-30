"""Tests for the finish/submission helpers (fixture data below is a test input, not a result)."""
from pathlib import Path

from leaply_guard.submission import fill_slots, results_markdown, secret_scan, slot_values

ROOT = Path(__file__).resolve().parent.parent

RUN = {
    "run_id": "test-run",
    "events": [{"t": 0.0}, {"t": 125.4}],
    "result": {
        "status": "success", "target": "2.15.1", "iterations": 2,
        "finding": {"package": {"version": "1.7.1"}, "advisories": [{}, {}]},
        "tests_before": {"passed": 15, "total": 15}, "tests_after_bump": {"passed": 3, "total": 16, "failed": 13, "errors": 0},
        "tests_after": {"passed": 16, "total": 16},
        "proof": {"before": "failed", "after": "passed", "source": "ultra", "cve": "CVE-2022-29217"},
        "cost": {"rows": [{"role": "ultra", "model": "u", "calls": 2, "tokens_in": 1000, "tokens_out": 100, "cost_usd": 0.0013},
                          {"role": "super", "model": "s", "calls": 3, "tokens_in": 500, "tokens_out": 50, "cost_usd": 0.0002},
                          {"role": "nano", "model": "n", "calls": 4, "tokens_in": 400, "tokens_out": 40, "cost_usd": 0.00003}],
                 "total_cost_usd": 0.00153, "all_ultra_cost_usd": 0.0024, "routing_savings_pct": 36.2, "total_tokens": 2090},
        "confidence": {"score": 92}, "rescan": {"remaining": [], "closed": ["GHSA-x"], "package": "PyJWT", "version": "2.15.1"},
        "sources": [{"title": "t", "url": "https://example.com", "via": "tavily"}],
        "audit": {"model_calls": []}, "security_review": {"verdict": "approve", "summary": "ok"},
    },
}


def test_slot_values_and_results():
    v = slot_values(RUN)
    assert v["TESTS_AFTER"] == "16/16" and v["BROKEN_COUNT"] == "13" and v["RUN_TIME"] == "2m 05s"
    assert v["SAVINGS_PCT"] == "36" and v["ULTRA_TOKENS"] == "1,100"
    md = results_markdown(RUN)
    assert "16/16" in md and "36% saved" in md


def test_fill_slots_keeps_template(tmp_path):
    (tmp_path / "README.md").write_text("cost {{TOTAL_COST}} and {{UNKNOWN_SLOT}}\n", encoding="utf-8")
    unknown = fill_slots(tmp_path, {"TOTAL_COST": "$1.00"})
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == "cost $1.00 and {{UNKNOWN_SLOT}}\n"
    assert unknown == {"README.md": ["UNKNOWN_SLOT"]}
    fill_slots(tmp_path, {"TOTAL_COST": "$2.00"})  # a later run refills from the saved template
    assert "$2.00" in (tmp_path / "README.md").read_text(encoding="utf-8")


def test_repo_and_history_have_no_secrets():
    assert secret_scan(ROOT) == []
