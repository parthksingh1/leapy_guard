"""leaply-guard finish: preflight -> live PyJWT run -> replay -> RESULTS.md -> fill docs -> secret scan + tests -> git commands."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from .config import ROOT, settings


class Stop(Exception):
    pass


def _h(title: str) -> None:
    print(f"\n\033[1m== {title} ==\033[0m")


def _set_env(key: str, value: str) -> None:
    """Add or update KEY=value in .env (only model ids are written here; never printed if secret)."""
    env = ROOT / ".env"
    lines = env.read_text(encoding="utf-8").splitlines() if env.exists() else []
    pat = re.compile(rf"^\s*#?\s*{re.escape(key)}=")
    for i, line in enumerate(lines):
        if pat.match(line):
            lines[i] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    env.write_text("\n".join(lines) + "\n", encoding="utf-8")


def preflight() -> None:
    _h("1/5 Preflight")
    if not settings.nebius_api_key:
        raise Stop("NEBIUS_API_KEY in .env is missing or still a placeholder. Paste the real key into .env and rerun.")
    if not settings.tavily_api_key:
        raise Stop("TAVILY_API_KEY in .env is missing or still a placeholder. Paste the real key into .env and rerun.")
    print("keys present (not shown)")
    from .events import EventBus
    from .llm import LLM

    llm = LLM(EventBus("preflight"))
    configured = {r: s.model_id for r, s in settings.models.items()}
    try:
        available = llm.list_models()
    except Exception as exc:
        raise Stop(f"Token Factory /models failed: {type(exc).__name__}: {str(exc)[:200]}. Check the key and NEBIUS_BASE_URL.")
    nemotron = [m for m in available if "nemotron" in m.lower()]
    print(f"{len(available)} models on Token Factory, {len(nemotron)} Nemotron")
    resolved = llm.resolve_models()
    for role, mid in resolved.items():
        if mid not in available:
            raise Stop(f"No Nemotron 3 {role} model found on Token Factory. Nemotron models: {nemotron}. Set MODEL_{role.upper()} in .env.")
        if mid != configured[role]:
            _set_env(f"MODEL_{role.upper()}", mid)
            print(f"MODEL_{role.upper()}: {configured[role]} -> {mid} (written to .env)")
        else:
            print(f"MODEL_{role.upper()}: {mid} ✓")
    for role in ("nano", "super", "ultra"):
        try:
            text = llm.chat(role, "ping", [{"role": "user", "content": "Reply with exactly: pong"}], max_tokens=1024)
        except Exception as exc:
            raise Stop(f"{role} ping failed: {str(exc)[:300]}")
        print(f"ping {role:5} -> {text.strip()[:40]!r}")


def live_run(package: str, repo: Path, replay_name: str) -> Path:
    _h(f"2/5 Live run: {package} ({repo.name})")
    from .cli import _print_event
    from .events import EventBus
    from .pipeline import Pipeline, RunOptions, _new_run_id

    bus = EventBus(_new_run_id())
    bus.subscribe(_print_event)
    result = Pipeline(RunOptions(repo=str(repo), package=package), bus).run()
    run_file = settings.runs_dir / f"{result.run_id}.json"
    if result.status != "success":
        reason = result.data.get("error") or (result.data.get("handover") or {}).get("reason") or "see the report"
        raise Stop(f"Live run ended with status '{result.status}': {reason}\nRun file: {run_file}\n"
                   "Rerun `leaply-guard finish` (model answers vary), or send the run file for a prompt fix.")
    settings.replays_dir.mkdir(exist_ok=True)
    shutil.copy(run_file, settings.replays_dir / f"{replay_name}.json")
    print(f"\nsaved replays/{replay_name}.json from live run {result.run_id}")
    return run_file


def write_results(run_file: Path) -> None:
    _h("3/5 Results and docs")
    from .submission import fill_in_items, fill_slots, results_markdown, slot_values

    run = json.loads(run_file.read_text(encoding="utf-8"))
    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "docs" / "RESULTS.md").write_text(results_markdown(run), encoding="utf-8", newline="\n")
    print("wrote docs/RESULTS.md")
    values = slot_values(run)
    unknown = fill_slots(ROOT, values)
    print("filled result slots in README.md, SUBMISSION.md, FEEDBACK.md, docs/DEVPOST_FORM.md, docs/VIDEO_RUNBOOK.md")
    for f, slots in unknown.items():
        print(f"  unknown slots left in {f}: {slots}")
    for k in ("TESTS_AFTER", "ITERATIONS", "TOTAL_COST", "SAVINGS_PCT", "RUN_TIME"):
        print(f"  {k} = {values[k]}")
    todo = fill_in_items(ROOT)
    if todo:
        print(f"\n{len(todo)} [fill in] items need your own words:")
        for t in todo:
            print("  - " + t)


def verify() -> None:
    _h("4/5 Secret scan and tests")
    from .submission import secret_scan

    problems = secret_scan(ROOT)
    if problems:
        raise Stop("secret scan found problems (nothing printed): " + "; ".join(problems))
    print("secret scan: clean (tracked files and git history)")
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"], cwd=ROOT,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    tail = (proc.stdout or proc.stderr).strip().splitlines()[-1:] or ["(no output)"]
    print("tests: " + tail[0])
    if proc.returncode != 0:
        raise Stop("test suite failed:\n" + (proc.stdout or "")[-2500:])


def git_commands() -> None:
    _h("5/5 Commit and publish")
    print("""git add -A
git commit -m "Add recorded live run, results and filled docs"
gh repo create leaply-guard --public --source . --remote origin --push     # first time
git push                                                                   # afterwards
python scripts/check_submission.py""")


def main(with_yaml: bool = False, skip_run: str | None = None) -> int:
    try:
        preflight()
        if skip_run:
            run_file = Path(skip_run)
            meta = json.loads(run_file.read_text(encoding="utf-8"))
            if meta.get("simulated") or meta.get("status") != "success":
                raise Stop(f"{run_file} is not a successful live run")
            settings.replays_dir.mkdir(exist_ok=True)
            shutil.copy(run_file, settings.replays_dir / "pyjwt-demo.json")
        else:
            run_file = live_run("PyJWT", settings.demo_repo, "pyjwt-demo")
            if with_yaml:
                try:
                    live_run("PyYAML", settings.demo_repo.parent / "yaml-config-service", "pyyaml-demo")
                except Stop as exc:
                    print(f"(PyYAML run skipped: {exc})")
        write_results(run_file)
        verify()
        git_commands()
    except Stop as exc:
        print(f"\n\033[91mSTOPPED:\033[0m {exc}")
        return 1
    print("\nDone. Open the UI with: leaply-guard serve   (it opens on the recorded live run)")
    return 0
