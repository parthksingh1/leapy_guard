"""leaply-guard command line."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from .config import settings

ACTOR = {"ultra": "\033[95mULTRA\033[0m", "super": "\033[94mSUPER\033[0m", "nano": "\033[92mNANO \033[0m",
         "tavily": "\033[93mTAVLY\033[0m", "osv": "\033[96mOSV  \033[0m", "sandbox": "\033[90mSBOX \033[0m",
         "system": "\033[90mSYS  \033[0m", "github": "\033[90mGH   \033[0m"}


def _print_event(e: dict) -> None:
    a = ACTOR.get(e["actor"], e["actor"])
    k = e["kind"]
    if k == "step_start":
        print(f"\n{a} ▶ {e['title']}")
    elif k == "step_end" and e.get("summary"):
        print(f"{a}   ✓ {e['summary']}")
    elif k == "model_call":
        print(f"{a}   · {e['purpose']}: {e['tokens_in']:,} in / {e['tokens_out']:,} out, {e['latency_s']}s, ${e['cost_usd']:.4f}")
    elif k == "tests":
        bar = "\033[92m" + "█" * e["passed"] + "\033[91m" + "█" * (e["failed"] + e["errors"]) + "\033[0m"
        print(f"{a}   tests [{e['label']}]: {bar} {e['passed']}/{e['total']}")
    elif k == "proof":
        print(f"{a}   security proof ({e.get('phase')}): {e['status']}" + (f" — {e['message']}" if e.get("message") else ""))
    elif k == "file_changed":
        print(f"{a}   edited {e['path']} (+{e['added']} −{e['removed']}, {e['how']})")
    elif k == "guardrail":
        print(f"{a}   guardrail rejected: {e['reason']}")
    elif k in ("log", "handover", "error"):
        print(f"{a}   {e.get('message') or e.get('reason')}")
    elif k == "triage_failure":
        print(f"{a}   failure triage: [{e.get('category')}] {e.get('root_cause')}")
    elif k == "selected":
        print(f"{a}   selected {e['package']} {e['current']} → {e['target']} ({e.get('cve') or e['advisory']}, {e['severity']}, {e['verdict']})")


def cmd_models(_args) -> int:
    from .llm import LLM

    llm = LLM()
    ids = llm.list_models()
    print("Nemotron models on Token Factory:")
    for m in ids:
        if "nemotron" in m.lower():
            print("  ", m)
    print("\nResolved:", json.dumps(llm.resolve_models(), indent=2))
    return 0


def cmd_ping(_args) -> int:
    from .events import EventBus
    from .llm import LLM

    llm = LLM(EventBus("ping"))
    llm.resolve_models()
    for role in ("nano", "super", "ultra"):
        text = llm.chat(role, "ping", [{"role": "user", "content": "Reply with exactly: pong"}], max_tokens=512)
        print(f"{role:5} {settings.models[role].model_id:45} -> {text.strip()[:60]!r}")
    print(json.dumps(llm.ledger.summary(settings.models), indent=2))
    return 0


def cmd_scan(args) -> int:
    from .events import EventBus
    from .llm import LLM
    from .pipeline import resolve_repo
    from .scan import scan_repo
    from .triage import triage

    bus = EventBus("scan")
    repo, _ = resolve_repo(args.repo, bus)
    deps, findings = scan_repo(repo)
    llm = LLM(bus) if settings.llm_enabled else None
    for f in findings:
        triage(repo, f, llm)
    findings.sort(key=lambda f: -f.score)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=1))
        return 0
    print(f"{len(deps)} pinned dependencies, {len(findings)} vulnerable\n")
    for f in findings:
        r = f.reachability
        print(f"{f.package.name} {f.package.version} [{f.severity}] {r['verdict']} (score {f.score}) → fixed in {f.fixed_version}, latest {f.latest_version}")
        for a in f.advisories:
            print(f"   {a.id:22} {a.cve or '':18} {a.severity:9} {a.summary[:70]}")
        for e in r.get("evidence", [])[:4]:
            print(f"   evidence {e['file']}:{e['line']} {e.get('why', '')[:80]}")
    return 0


def cmd_run(args) -> int:
    from .events import EventBus
    from .pipeline import Pipeline, RunOptions, _new_run_id

    if not settings.llm_enabled:
        print("NEBIUS_API_KEY is not set. Add it to .env (see .env.example).", file=sys.stderr)
        return 2
    bus = EventBus(_new_run_id())
    bus.subscribe(_print_event)
    opts = RunOptions(repo=args.repo, package=args.package, target=args.target, branch=args.branch,
                      open_pr=args.pr, keep_workspace=args.keep, max_iterations=args.max_iterations,
                      max_diff_lines=args.max_diff_lines)
    result = Pipeline(opts, bus).run()
    d = result.data
    print("\n" + "=" * 70)
    if "report_md" in d:
        from .report import result_card
        print(result_card(d))
        print(f"status: {result.status}   confidence: {d['confidence']['score']}/100")
        print(f"report: {d['delivery']['report_path']}")
        if d["delivery"].get("pr_url"):
            print(f"pull request: {d['delivery']['pr_url']}")
        elif d["delivery"].get("note"):
            print(d["delivery"]["note"])
    else:
        print(f"status: {result.status} {d.get('error') or d.get('summary', '')}")
    print(f"run log: {settings.runs_dir / (result.run_id + '.json')}")
    if args.save_replay and result.status == "success":
        settings.replays_dir.mkdir(exist_ok=True)
        dest = settings.replays_dir / f"{args.save_replay}.json"
        shutil.copy(settings.runs_dir / f"{result.run_id}.json", dest)
        print(f"replay saved: {dest}")
    return 0 if result.status == "success" else 1


def cmd_save_replay(args) -> int:
    src = settings.runs_dir / f"{args.run_id}.json"
    data = json.loads(src.read_text(encoding="utf-8"))
    if data.get("status") != "success":
        print("only successful live runs can be saved as replays", file=sys.stderr)
        return 1
    settings.replays_dir.mkdir(exist_ok=True)
    dest = settings.replays_dir / f"{args.name}.json"
    shutil.copy(src, dest)
    print(f"saved {dest}")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    uvicorn.run("leaply_guard.server:app", host=args.host, port=args.port, log_level="info")
    return 0


def cmd_mcp(_args) -> int:
    from .mcp_server import main

    main()
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(prog="leaply-guard", description="Upgrade vulnerable dependencies and prove it with your tests.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("models", help="list Nemotron models on Token Factory and resolve configured ids").set_defaults(fn=cmd_models)
    sub.add_parser("ping", help="call Ultra, Super and Nano once").set_defaults(fn=cmd_ping)

    s = sub.add_parser("scan", help="scan a repo for vulnerable dependencies and triage reachability")
    s.add_argument("--repo", default=str(settings.demo_repo))
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_scan)

    r = sub.add_parser("run", help="upgrade a vulnerable package and prove it with tests")
    r.add_argument("--repo", default=str(settings.demo_repo), help="local path or GitHub URL")
    r.add_argument("--package", help="package to upgrade (default: highest-risk finding)")
    r.add_argument("--target", help="target version (default: latest release)")
    r.add_argument("--branch", action="store_true", help="commit the change on a local branch")
    r.add_argument("--pr", action="store_true", help="open a GitHub pull request (needs GITHUB_TOKEN and a GitHub URL)")
    r.add_argument("--keep", action="store_true", help="keep the temp workspace")
    r.add_argument("--max-iterations", type=int)
    r.add_argument("--max-diff-lines", type=int)
    r.add_argument("--save-replay", metavar="NAME", help="save a successful run as replays/NAME.json for the web UI")
    r.set_defaults(fn=cmd_run)

    sr = sub.add_parser("save-replay", help="save a past successful run as a UI replay")
    sr.add_argument("run_id")
    sr.add_argument("--name", default="pyjwt-demo")
    sr.set_defaults(fn=cmd_save_replay)

    sv = sub.add_parser("serve", help="start the web UI")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(fn=cmd_serve)

    sub.add_parser("mcp", help="run the MCP server over stdio").set_defaults(fn=cmd_mcp)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
