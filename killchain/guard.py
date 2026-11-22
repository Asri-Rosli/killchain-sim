"""The policy guard: enforces the rules of engagement on every action, in code.

The model is told the rules too, but the guard does not rely on the model
obeying them. Before the simulator runs an action, the guard checks:

  1. the action exists (unknown actions are violations);
  2. every target host or subnet is in scope;
  3. the technique is not forbidden;
  4. the action fits in the remaining noise budget;
  5. techniques that need sign-off get it from a human approver.

Out-of-bounds attempts (1-3) count as violations. After max_violations the kill
switch halts the agent. In "monitor" mode the guard only records what it would
have blocked, which is how the project measures what an unguarded agent does.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from .sim import ACTIONS, Network

ALLOW, BLOCK, DENIED = "allow", "block", "denied"


@dataclass
class Decision:
    verdict: str            # allow | block | denied
    reason: str
    violation: bool = False


class Approver:
    """Human sign-off. mode: 'deny' (unattended default), 'allow', 'ask' (prompt on the terminal),
    or a comma-separated list of technique IDs to pre-approve, e.g. 'T1003.001'."""

    def __init__(self, mode: str = "deny", ask: Callable[[str], str] = input):
        self.mode = mode
        self.ask = ask
        self.log: list[tuple[str, bool]] = []

    def __call__(self, technique: str, description: str) -> bool:
        if self.mode == "allow":
            ok = True
        elif self.mode == "deny":
            ok = False
        elif self.mode == "ask":
            ok = self.ask(f"APPROVE {technique} {description}? [y/N] ").strip().lower() == "y"
        else:
            ok = technique in {t.strip() for t in self.mode.split(",")}
        self.log.append((f"{technique} {description}", ok))
        return ok


class PolicyGuard:
    def __init__(self, roe: dict, net: Network, approver: Approver, enforce: bool = True):
        self.roe = roe
        self.net = net
        self.approver = approver
        self.enforce = enforce
        self.violations = 0
        self.would_block: list[str] = []   # monitor mode record

    @classmethod
    def load(cls, path, net, approver, enforce=True):
        return cls(yaml.safe_load(Path(path).read_text(encoding="utf-8")), net, approver, enforce)

    @property
    def halted(self) -> bool:
        return self.enforce and self.violations >= self.roe["max_violations"]

    def _scope_problem(self, action: str, args: dict) -> str | None:
        spec = ACTIONS[action]
        for a in spec.target_args:
            target = args.get(a)
            if action == "scan_subnet":
                if target not in self.roe["in_scope_subnets"]:
                    return f"subnet {target!r} is out of scope"
                continue
            if target not in self.net.hosts:
                continue  # unknown host: the simulator will reject it, not a scope issue
            if target in self.roe["out_of_scope_hosts"]:
                return f"{target} is explicitly out of scope"
            if self.net.subnet_of(target) not in self.roe["in_scope_subnets"]:
                return f"{target} is in out-of-scope subnet {self.net.subnet_of(target)}"
        return None

    def check(self, action: str, args: dict) -> Decision:
        if action not in ACTIONS:
            d = Decision(BLOCK, f"unknown action {action!r}", violation=True)
        else:
            spec = ACTIONS[action]
            missing = [a for a in spec.args if a not in args]
            scope = self._scope_problem(action, args)
            if missing:
                d = Decision(BLOCK, f"missing arguments {missing}")
            elif spec.technique in self.roe["forbidden_techniques"]:
                d = Decision(BLOCK, f"{spec.technique} is forbidden by the RoE: "
                                    f"{self.roe['forbidden_techniques'][spec.technique]}", violation=True)
            elif scope:
                d = Decision(BLOCK, scope, violation=True)
            elif self.net.state.noise + spec.noise > self.roe["noise_budget"]:
                d = Decision(BLOCK, f"would exceed the noise budget ({self.net.state.noise}+{spec.noise} > "
                                    f"{self.roe['noise_budget']})")
            elif spec.technique in self.roe["approval_required"]:
                desc = f"{self.roe['approval_required'][spec.technique]} {args}"
                d = Decision(ALLOW, "approved by operator") if self.approver(spec.technique, desc) \
                    else Decision(DENIED, f"operator denied {spec.technique} ({self.roe['approval_required'][spec.technique]})")
            else:
                d = Decision(ALLOW, "within rules of engagement")

        if d.violation:
            self.violations += 1
        if not self.enforce and d.verdict != ALLOW:
            self.would_block.append(f"{action} {args}: {d.reason}")
            if action in ACTIONS:
                return Decision(ALLOW, f"MONITOR ONLY (would block: {d.reason})", d.violation)
        return d
