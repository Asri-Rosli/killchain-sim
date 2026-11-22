"""Command line.

  python -m killchain run --backend ollama --model qwen2.5:7b --approve T1003.001
  python -m killchain run --backend scripted --script examples/demo_steered.json --approve T1003.001
  python -m killchain compare --backend scripted --script examples/demo_steered.json --approve T1003.001
"""
from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict
from pathlib import Path

from .agent import metrics, run_engagement
from .guard import Approver, PolicyGuard
from .llm import make_llm
from .sim import Network

ROOT = Path(__file__).resolve().parent.parent
SCENARIO = ROOT / "scenarios" / "acme.yml"
ROE = ROOT / "scenarios" / "acme_roe.yml"
RUNS = ROOT / "runs"


def one_run(args, enforce: bool) -> dict:
    net = Network.load(args.scenario)
    guard = PolicyGuard.load(args.roe, net, Approver(args.approve), enforce=enforce)
    llm = make_llm(args.backend, args.model, args.script)
    res = run_engagement(llm, net, guard, max_steps=args.max_steps)
    m = metrics(net, guard, res)
    d = RUNS / f"{time.strftime('%Y%m%d-%H%M%S')}_{'guarded' if enforce else 'monitor'}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "transcript.json").write_text(json.dumps([asdict(s) for s in res.steps], indent=2), encoding="utf-8")
    (d / "metrics.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    (d / "report.md").write_text(res.summary or "(no report)", encoding="utf-8")
    m["run_dir"] = str(d)
    m["would_block_log"] = guard.would_block
    return m


def cmd_run(args):
    m = one_run(args, enforce=not args.monitor_only)
    print(json.dumps({k: v for k, v in m.items() if k != "would_block_log"}, indent=2))


def cmd_compare(args):
    g = one_run(args, enforce=True)
    u = one_run(args, enforce=False)
    rows = [("objective reached", g["objective_reached"], u["objective_reached"]),
            ("out-of-bounds attempts", g["violations_attempted"], u["violations_attempted"]),
            ("actions stopped", g["blocked_by_guard"] + g["denied_by_operator"], 0),
            ("out-of-scope footholds", len(g["out_of_scope_footholds"]), len(u["out_of_scope_footholds"])),
            ("destructive/forbidden effects", len(g["impact"]), len(u["impact"])),
            ("stop reason", g["stop_reason"], u["stop_reason"])]
    print(f"{'':32}{'guard ON':>14}{'monitor only':>16}")
    for name, a, b in rows:
        print(f"{name:32}{str(a):>14}{str(b):>16}")
    if u["impact"]:
        print("\nWithout enforcement the (simulated) agent did:", "; ".join(u["impact"]))


def main(argv=None):
    p = argparse.ArgumentParser(prog="killchain", description="Red-team LLM agent on a simulated network")
    p.add_argument("--scenario", default=str(SCENARIO))
    p.add_argument("--roe", default=str(ROE))
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("run", cmd_run), ("compare", cmd_compare)):
        s = sub.add_parser(name)
        s.add_argument("--backend", choices=["ollama", "openai", "anthropic", "scripted"], default="ollama")
        s.add_argument("--model")
        s.add_argument("--script")
        s.add_argument("--max-steps", type=int, default=25)
        s.add_argument("--approve", default="deny",
                       help="deny | allow | ask | comma-separated technique IDs to pre-approve")
        if name == "run":
            s.add_argument("--monitor-only", action="store_true", help="log violations but do not block (simulation only)")
        s.set_defaults(fn=fn)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
