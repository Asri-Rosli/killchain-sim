"""The simulated network and the actions an operator can take in it.

Nothing here touches a real system. Each action is a function that checks the
simulated state (what the attacker knows, where they have a foothold, which
credentials they hold) and updates it. Each action is labelled with its MITRE
ATT&CK technique, its Cyber Kill Chain stage and how much detection "noise" it makes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

KILL_CHAIN = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation",
              "Installation", "Command and Control", "Actions on Objectives"]


@dataclass(frozen=True)
class ActionSpec:
    technique: str
    technique_name: str
    stage: str
    noise: int
    args: tuple[str, ...]
    target_args: tuple[str, ...]  # args naming a host or subnet, checked against scope


ACTIONS: dict[str, ActionSpec] = {
    "scan_subnet": ActionSpec("T1046", "Network Service Discovery", "Reconnaissance", 3, ("subnet",), ("subnet",)),
    "enumerate_host": ActionSpec("T1046", "Network Service Discovery", "Reconnaissance", 1, ("host",), ("host",)),
    "exploit": ActionSpec("T1190", "Exploit Public-Facing Application", "Exploitation", 3, ("host", "vuln"), ("host",)),
    "escalate": ActionSpec("T1068", "Exploitation for Privilege Escalation", "Installation", 2, ("host", "vuln"), ("host",)),
    "dump_creds": ActionSpec("T1003.001", "OS Credential Dumping: LSASS Memory", "Actions on Objectives", 4, ("host",), ("host",)),
    "list_files": ActionSpec("T1083", "File and Directory Discovery", "Actions on Objectives", 1, ("host",), ("host",)),
    "read_file": ActionSpec("T1005", "Data from Local System", "Actions on Objectives", 1, ("host", "path"), ("host",)),
    "lateral_move": ActionSpec("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Actions on Objectives", 3,
                               ("src", "dst", "cred"), ("src", "dst")),
    "exfiltrate": ActionSpec("T1041", "Exfiltration Over C2 Channel", "Actions on Objectives", 5, ("host", "path"), ("host",)),
    "install_persistence": ActionSpec("T1053.005", "Scheduled Task", "Installation", 2, ("host",), ("host",)),
    "phish": ActionSpec("T1566", "Phishing", "Delivery", 2, ("target",), ()),
    "encrypt_files": ActionSpec("T1486", "Data Encrypted for Impact", "Actions on Objectives", 8, ("host",), ("host",)),
    "delete_backups": ActionSpec("T1490", "Inhibit System Recovery", "Actions on Objectives", 6, ("host",), ("host",)),
}


class ActionError(Exception):
    """The action is allowed but impossible in the current state (e.g. host unreachable)."""


@dataclass
class State:
    known_hosts: set[str] = field(default_factory=set)
    enumerated: set[str] = field(default_factory=set)
    footholds: dict[str, str] = field(default_factory=dict)   # host -> "user" | "admin"
    creds: set[str] = field(default_factory=set)
    noise: int = 0
    stages: list[str] = field(default_factory=list)
    objective_reached: bool = False
    impact: list[str] = field(default_factory=list)          # destructive effects (only possible without the guard)


class Network:
    def __init__(self, scenario: dict):
        self.name = scenario["name"]
        self.subnets = scenario["subnets"]
        self.hosts = scenario["hosts"]
        self.objective = scenario["objective"]
        self.state = State()

    @classmethod
    def load(cls, path: str | Path) -> "Network":
        return cls(yaml.safe_load(Path(path).read_text(encoding="utf-8")))

    # ---- helpers -----------------------------------------------------------
    def subnet_of(self, host: str) -> str:
        return self.hosts[host]["subnet"]

    def reachable_subnets(self) -> set[str]:
        out = set(self.subnets["internet"]["reaches"])
        for h in self.state.footholds:
            sn = self.subnet_of(h)
            out |= {sn, *self.subnets[sn]["reaches"]}
        return out

    def _need_host(self, host):
        if host not in self.hosts or host not in self.state.known_hosts:
            raise ActionError(f"unknown host {host!r}; scan a subnet first")

    def _need_reach(self, host):
        if self.subnet_of(host) not in self.reachable_subnets():
            raise ActionError(f"{host} is not reachable from your current footholds")

    def _need_foothold(self, host, level="user"):
        have = self.state.footholds.get(host)
        if have is None or (level == "admin" and have != "admin"):
            raise ActionError(f"you need {level} access on {host}")

    # ---- actions -------------------------------------------------------------
    def scan_subnet(self, subnet):
        if subnet not in self.subnets or subnet == "internet":
            raise ActionError(f"unknown subnet {subnet!r}")
        if subnet not in self.reachable_subnets():
            raise ActionError(f"subnet {subnet} is not reachable from your current footholds")
        found = [h for h, d in self.hosts.items() if d["subnet"] == subnet]
        self.state.known_hosts |= set(found)
        return f"{subnet} ({self.subnets[subnet]['cidr']}): " + ", ".join(
            f"{h} {self.hosts[h]['ip']}" for h in found)

    def enumerate_host(self, host):
        self._need_host(host)
        self._need_reach(host)
        self.state.enumerated.add(host)
        d = self.hosts[host]
        vulns = d.get("vulns", {})
        return (f"{host}: services {d['services']}; vulnerabilities "
                + (", ".join(f"{v} ({k})" for v, k in vulns.items()) if vulns else "none found"))

    def exploit(self, host, vuln):
        self._need_host(host)
        self._need_reach(host)
        if self.hosts[host].get("vulns", {}).get(vuln) != "remote":
            raise ActionError(f"{host} has no remotely exploitable vulnerability {vuln!r}")
        self.state.footholds.setdefault(host, "user")
        return f"Exploited {vuln} on {host}: user-level foothold."

    def escalate(self, host, vuln):
        self._need_foothold(host)
        if self.hosts[host].get("vulns", {}).get(vuln) != "privesc":
            raise ActionError(f"{host} has no privilege-escalation vulnerability {vuln!r}")
        self.state.footholds[host] = "admin"
        return f"Escalated to admin on {host}."

    def dump_creds(self, host):
        self._need_foothold(host, "admin")
        got = self.hosts[host].get("creds_cached", [])
        self.state.creds |= set(got)
        return f"Credentials recovered from {host}: {got or 'none'}"

    def list_files(self, host):
        self._need_foothold(host)
        files = list(self.hosts[host].get("files", {}))
        return f"{host}: " + (", ".join(files) if files else "no interesting files")

    def read_file(self, host, path):
        self._need_foothold(host)
        files = self.hosts[host].get("files", {})
        if path not in files:
            raise ActionError(f"no file {path!r} on {host}")
        if host == self.objective["host"] and path == self.objective["path"]:
            self.state.objective_reached = True
        return f"<untrusted_data>\n{files[path]}\n</untrusted_data>"

    def lateral_move(self, src, dst, cred):
        self._need_foothold(src)
        self._need_host(dst)
        sn = self.subnet_of(src)
        if self.subnet_of(dst) not in {sn, *self.subnets[sn]["reaches"]}:
            raise ActionError(f"{dst} is not reachable from {src}")
        if cred not in self.state.creds:
            raise ActionError(f"you do not hold credential {cred!r}")
        if cred not in self.hosts[dst].get("accepts", []):
            raise ActionError(f"{cred} is not valid on {dst}")
        self.state.footholds[dst] = "admin"
        return f"Logged in to {dst} from {src} as {cred}: admin access."

    def exfiltrate(self, host, path):
        self.read_file(host, path)
        self.state.impact.append(f"exfiltrated {host}:{path}")
        return f"(simulated) {path} copied off {host}."

    def install_persistence(self, host):
        self._need_foothold(host, "admin")
        self.state.impact.append(f"persistence on {host}")
        return f"(simulated) scheduled task installed on {host}."

    def phish(self, target):
        self.state.impact.append(f"phished {target}")
        return f"(simulated) phishing email sent to {target}."

    def encrypt_files(self, host):
        self._need_foothold(host, "admin")
        self.state.impact.append(f"encrypted {host}")
        return f"(simulated) files on {host} encrypted."

    def delete_backups(self, host):
        self._need_foothold(host, "admin")
        self.state.impact.append(f"deleted backups on {host}")
        return f"(simulated) backups on {host} deleted."

    def execute(self, action: str, args: dict) -> str:
        spec = ACTIONS[action]
        result = getattr(self, action)(**{k: args[k] for k in spec.args})
        self.state.noise += spec.noise
        if spec.stage not in self.state.stages:
            self.state.stages.append(spec.stage)
        return result

    def status(self) -> str:
        s = self.state
        return (f"Known hosts: {sorted(s.known_hosts) or 'none'}\n"
                f"Footholds: {s.footholds or 'none'}\nCredentials: {sorted(s.creds) or 'none'}\n"
                f"Reachable subnets: {sorted(self.reachable_subnets())}\nNoise used: {s.noise}")
