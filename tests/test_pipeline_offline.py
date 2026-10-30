"""End-to-end pipeline test on the demo repo with scripted model answers (real OSV, real venvs, real pytest)."""
import dataclasses

import pytest

from leaply_guard.config import Settings
from leaply_guard.events import EventBus
from leaply_guard.pipeline import Pipeline, RunOptions

from scripted_llm import ScriptedLLM


@pytest.mark.slow
def test_pipeline_end_to_end_on_demo(tmp_path):
    cfg = dataclasses.replace(Settings(), nebius_api_key="test-key-not-used-xxxx", tavily_api_key="", github_token="",
                              runs_dir=tmp_path / "runs")
    bus = EventBus("test-run")
    llm = ScriptedLLM(bus, cfg)
    result = Pipeline(RunOptions(repo=str(cfg.demo_repo), package="PyJWT"), bus, llm, cfg).run()
    d = result.data
    assert result.status == "success", d.get("error") or d.get("handover")
    assert d["tests_before"]["ok"] and d["tests_before"]["passed"] == 15
    assert d["tests_after_bump"]["failed"] >= 10
    assert d["tests_after"]["ok"] and d["tests_after"]["passed"] == 16
    assert d["proof"] == {**d["proof"], "before": "failed", "after": "passed", "source": "vetted"}
    assert d["iterations"] == 2  # one fix iteration
    assert any("tests/test_tokens.py" in v for v in d["guardrails"]["rejected_edits"])
    assert d["guardrails"]["status"] == "passed"
    assert "GHSA-ffqj-6fqr-9h24" in d["rescan"]["closed"]
    assert d["finding"]["reachability"]["verdict"] == "REACHABLE"
    assert d["cost"]["routing_savings_pct"] > 0
    assert "CVE-2022-29217" in d["report_md"]
    kinds = {e["kind"] for e in bus.events}
    assert {"findings", "sources", "tests", "proof", "plan", "file_changed", "guardrail", "triage_failure", "finished"} <= kinds


@pytest.mark.slow
def test_pipeline_end_to_end_on_pyyaml_demo(tmp_path):
    cfg = dataclasses.replace(Settings(), nebius_api_key="test-key-not-used-xxxx", tavily_api_key="", github_token="",
                              runs_dir=tmp_path / "runs")
    bus = EventBus("test-yaml")
    llm = ScriptedLLM(bus, cfg, scenario="pyyaml")
    repo = cfg.demo_repo.parent / "yaml-config-service"
    result = Pipeline(RunOptions(repo=str(repo), package="PyYAML"), bus, llm, cfg).run()
    d = result.data
    assert result.status == "success", d.get("error") or d.get("handover")
    assert d["tests_before"]["passed"] == 11 and d["tests_before"]["ok"]
    assert d["tests_after_bump"]["failed"] >= 10
    assert d["tests_after"]["ok"] and d["tests_after"]["passed"] == 12
    assert d["proof"]["before"] == "failed" and d["proof"]["after"] == "passed" and d["proof"]["cve"] == "CVE-2020-14343"
    assert d["iterations"] == 2
    assert "tests/test_leaply_security_proof.py" in d["diff"]
