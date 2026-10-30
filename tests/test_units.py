from leaply_guard.guardrails import check_path, scan_secrets
from leaply_guard.llm import Ledger, extract_json
from leaply_guard.config import Settings
from leaply_guard.patching import apply_unified_diff, make_diff
from leaply_guard.scan import cvss3_score
from leaply_guard.workspace import bump_requirement


def test_cvss3_scores():
    assert cvss3_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N") == 7.4
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_score("garbage") is None


def test_diff_applies_with_wrong_line_numbers():
    before = "a\nb\nc\nd\ne\n"
    after = "a\nb\nC\nd\ne\n"
    diff = make_diff("x.py", before, after).replace("@@ -1,5 +1,5 @@", "@@ -40,5 +40,5 @@")
    assert apply_unified_diff(before, diff) == after


def test_guardrails():
    assert check_path("../etc/passwd", set())
    assert check_path(".env", set())
    assert check_path(".github/workflows/ci.yml", set())
    assert check_path("poetry.lock", set())
    assert check_path("tests/test_x.py", set())
    assert check_path("tests/test_x.py", {"tests/test_x.py"}) is None
    assert check_path("app/tokens.py", set()) is None


def test_secret_scan():
    diff = "+++ b/x\n+key = 'AKIAABCDEFGHIJKLMNOP'\n-old = 'AKIAABCDEFGHIJKLMNOP'\n+ok = 1\n"
    assert [f["type"] for f in scan_secrets(diff)] == ["AWS access key"]


def test_bump_requirement():
    text, n = bump_requirement("flask>=2\nPyJWT==1.7.1  # auth\n", "pyjwt", "2.15.1")
    assert n == 1 and "PyJWT==2.15.1  # auth" in text


def test_extract_json_with_reasoning():
    assert extract_json('<think>hmm {"no": 1}</think>Here:\n```json\n{"a": 1}\n```') == {"a": 1}


def test_routing_savings():
    models = Settings().models
    led = Ledger()
    led.add(models["ultra"], "plan", 10000, 1000, 1, "plan")
    led.add(models["nano"], "triage", 10000, 1000, 1, "fix")
    s = led.summary(models)
    assert s["all_ultra_cost_usd"] > s["total_cost_usd"]
    assert 0 < s["routing_savings_pct"] < 100


def test_security_proof_is_not_editable_by_agents():
    from leaply_guard.pipeline import PROOF_PATH, check_path_quiet
    assert check_path_quiet(PROOF_PATH)
