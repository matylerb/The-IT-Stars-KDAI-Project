"""
CSP response selector (Tyler).

Answers "what may we do about this incident?" by modelling response selection
as a CSP (X, D, C) and solving it with response.csp.BacktrackingSolver.

    X = {network, account, application} response slots, plus `severity`,
        a variable whose domain is fixed to the inferred severity. Making
        severity a variable turns C2 into a real binary constraint that
        forward checking propagates over.

    D(slot) = actions Ivan's knowledge graph links to the attack for that
              slot (knowledge.enrich -> "action_domains"), plus "none". If the
              graph knows no action for a slot, the domain is {"none"}: open
              world, nothing is invented.

    C1 unary   network != block_ip            when src_ip is allowlisted
    C2 binary  network = block_ip  ->  severity in {high, critical}
    C3 global  at least one slot != none      (goal test: always offer something)
    C4 unary   account != none                when a login succeeded after
                                              a brute-force burst

Output (ResponsePlan):
    recommended      the first solution found (MRV + LCV + preference order)
    allowed_actions  every action that appears in at least one solution;
                     these become the one-tap Telegram buttons
    removed          each action that appears in no solution, with the
                     constraint and reason that removed it

Input: an incident dict
    {"event": DetectionEvent.to_dict(),
     "severity": final severity (rule engine; the detector's until it lands),
     "trace": rule-engine proof trace,
     "knowledge": knowledge.enrich(event)}
make_incident() builds one from a DetectionEvent dict.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Union

from response.csp import CSP, BacktrackingSolver, Constraint, SearchStats

SLOTS = ("network", "account", "application")
SEVERITY_VAR = "severity"
NONE = "none"
SEVERITIES = ("low", "medium", "high", "critical")
BLOCKING_SEVERITIES = ("high", "critical")

Allowlist = List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]


# --- allowlist -----------------------------------------------------------------

def parse_allowlist(spec: Optional[Iterable[str] | str]) -> Allowlist:
    """Parse IPs / CIDR ranges, from a comma-separated string or an iterable."""
    if spec is None:
        return []
    items = spec.split(",") if isinstance(spec, str) else list(spec)
    nets = []
    for item in items:
        item = item.strip()
        if item:
            nets.append(ipaddress.ip_network(item, strict=False))
    return nets


def load_allowlist() -> Allowlist:
    """Allowlist from the ALLOWLIST environment variable, e.g. "10.0.0.1,192.168.1.0/24"."""
    return parse_allowlist(os.environ.get("ALLOWLIST", ""))


def is_allowlisted(ip: str, allowlist: Allowlist) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in allowlist)


# --- output --------------------------------------------------------------------

@dataclass
class RemovedAction:
    action: str
    slot: str
    constraint: Optional[str]
    reason: str


@dataclass
class ResponsePlan:
    status: str                                  # "ok" or "unsatisfiable"
    severity: str
    recommended: Dict[str, str]                  # slot -> action (may be "none")
    allowed_actions: List[str]                   # buttons, slot order then preference
    options: Dict[str, List[str]]                # slot -> values used by some solution
    removed: List[RemovedAction]
    required: List[RemovedAction]                # slots where "none" was ruled out
    initial_domains: Dict[str, List[str]]
    action_labels: Dict[str, str]
    provenance: Dict[str, List[str]]             # action -> graph triples that justify it
    constraints: List[dict]                      # id, kind, scope, reason
    solutions_count: int
    stats: SearchStats = field(repr=False, default_factory=SearchStats)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "severity": self.severity,
            "recommended": dict(self.recommended),
            "allowed_actions": list(self.allowed_actions),
            "options": {k: list(v) for k, v in self.options.items()},
            "removed": [vars(r) for r in self.removed],
            "required": [vars(r) for r in self.required],
            "initial_domains": {k: list(v) for k, v in self.initial_domains.items()},
            "action_labels": dict(self.action_labels),
            "provenance": {k: list(v) for k, v in self.provenance.items()},
            "constraints": list(self.constraints),
            "solutions_count": self.solutions_count,
            "search": {"nodes": self.stats.nodes, "backtracks": self.stats.backtracks},
        }

    def explanation_lines(self) -> List[str]:
        """Plain-text trace: constraint -> action, for console output and the template."""
        label = lambda a: self.action_labels.get(a, a)  # noqa: E731
        lines = []
        if self.status != "ok":
            lines.append("No combination of actions satisfies every safety rule. "
                         "No automatic action is offered; keep monitoring.")
        else:
            rec = [f"{s}: {label(a)}" for s, a in self.recommended.items() if a != NONE]
            lines.append("Recommended: " + "; ".join(rec))
            lines.append("Allowed: " + ", ".join(label(a) for a in self.allowed_actions))
        for r in self.required:
            lines.append(f"Required: an {r.slot} action ({r.constraint}: {r.reason})")
        for r in self.removed:
            lines.append(f"Not offered: {label(r.action)} "
                         f"({r.constraint or 'no valid combination'}: {r.reason})")
        return lines


# --- problem construction --------------------------------------------------------

def make_incident(event: dict, knowledge: Optional[dict] = None,
                  severity: Optional[str] = None, trace: Optional[list] = None) -> dict:
    """Assemble the selector's input from a DetectionEvent dict.

    `knowledge` defaults to Ivan's knowledge.enrich(event). `severity` and
    `trace` default to the detector's own until Cillian's rule engine is wired in.
    """
    if knowledge is None:
        from knowledge.enrich import enrich
        knowledge = enrich(event)
    return {
        "event": event,
        "severity": severity or event["severity"],
        "trace": trace if trace is not None else [],
        "knowledge": knowledge,
    }


def build_domains(action_domains: Dict[str, Sequence[dict]]):
    """Slot domains from the graph's action_domains, preserving the graph's order.

    `action_domains` is knowledge.enrich()["action_domains"]: slot -> list of
    {"id", "label", "slot", "mitigation", "path"}. Returns
    (domains, labels, provenance, ignored). Slots other than SLOTS, and actions
    whose own slot disagrees with the key they are listed under, are ignored
    and reported rather than guessed.
    """
    domains: Dict[str, List[str]] = {s: [] for s in SLOTS}
    labels: Dict[str, str] = {}
    provenance: Dict[str, List[str]] = {}
    ignored: List[str] = []
    for slot, actions in (action_domains or {}).items():
        for a in actions:
            aid = a["id"]
            if slot not in domains or a.get("slot", slot) != slot:
                ignored.append(aid)
                continue
            if aid not in domains[slot]:
                domains[slot].append(aid)
            labels.setdefault(aid, a.get("label", aid))
            provenance.setdefault(aid, list(a.get("path", [])))
    for s in SLOTS:
        domains[s].append(NONE)          # "do nothing on this layer" is always a value
    return domains, labels, provenance, ignored


def build_response_csp(incident: dict, allowlist: Allowlist):
    """Return (csp, labels, provenance) for one incident (see make_incident)."""
    event = incident["event"]
    severity = incident.get("severity") or event["severity"]
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity {severity!r}")
    src_ip = event["src_ip"]
    compromise = bool(event.get("possible_compromise"))

    knowledge = incident.get("knowledge") or {}
    domains, labels, provenance, _ = build_domains(knowledge.get("action_domains", {}))
    domains[SEVERITY_VAR] = [severity]
    allowlisted = is_allowlisted(src_ip, allowlist)

    constraints = [
        Constraint(
            "C1", ("network",),
            lambda net: not (allowlisted and net == "block_ip"),
            f"{src_ip} is on your allowlist, so it is never blocked" if allowlisted
            else f"allowlisted IPs are never blocked ({src_ip} is not on the allowlist)"),
        Constraint(
            "C2", ("network", SEVERITY_VAR),
            lambda net, sev: net != "block_ip" or sev in BLOCKING_SEVERITIES,
            f"blocking an IP is only offered at high or critical severity; "
            f"this incident is {severity}"),
        Constraint(
            "C3", SLOTS,
            lambda *acts: any(a != NONE for a in acts),
            "at least one protective action must be offered"),
        Constraint(
            "C4", ("account",),
            lambda acc: not (compromise and acc == NONE),
            "a login succeeded right after a password-guessing burst, "
            "so an account action is required" if compromise
            else "an account action is required only after a likely account takeover "
                 "(none detected here)"),
    ]
    csp = CSP(list(SLOTS) + [SEVERITY_VAR], domains, constraints)
    return csp, labels, provenance


def select_response(incident: dict, allowlist: Optional[Allowlist] = None) -> ResponsePlan:
    """Solve the response CSP for one incident."""
    if allowlist is None:
        allowlist = load_allowlist()
    csp, labels, provenance = build_response_csp(incident, allowlist)

    solver = BacktrackingSolver(csp)
    solutions = solver.solve(find_all=True)   # tiny space; enumerate to get every option
    severity = csp.domains[SEVERITY_VAR][0]

    options = {s: [v for v in csp.domains[s] if any(sol[s] == v for sol in solutions)]
               for s in SLOTS}
    allowed = [v for s in SLOTS for v in options[s] if v != NONE]

    first_prune = {}
    for p in solver.stats.prunes:
        first_prune.setdefault((p.variable, p.value), p)
    removed, required = [], []
    for s in SLOTS:
        for v in csp.domains[s]:
            if v in options[s]:
                continue
            p = first_prune.get((s, v))
            entry = RemovedAction(
                v, s,
                p.constraint if p else None,
                p.reason if p else "not part of any combination that satisfies every safety rule")
            # "none" ruled out means the slot is mandatory; that only makes sense
            # to report when the problem has solutions at all
            if v == NONE:
                if solutions:
                    required.append(entry)
            else:
                removed.append(entry)

    return ResponsePlan(
        status="ok" if solutions else "unsatisfiable",
        severity=severity,
        recommended={s: solutions[0][s] for s in SLOTS} if solutions else {},
        allowed_actions=allowed,
        options=options,
        removed=removed,
        required=required,
        initial_domains={s: list(csp.domains[s]) for s in SLOTS},
        action_labels=labels,
        provenance=provenance,
        constraints=[{"id": c.id, "kind": c.kind, "scope": list(c.scope), "reason": c.reason}
                     for c in csp.constraints],
        solutions_count=len(solutions),
        stats=solver.stats,
    )


# --- demo: python -m response.selector data/brute_force_logs.jsonl --allow 10.0.0.60

if __name__ == "__main__":
    import argparse

    from detection.detector import Detector

    ap = argparse.ArgumentParser(description="Run a recorded log through the detector and the response CSP.")
    ap.add_argument("log", help="JSONL access log, e.g. data/brute_force_logs.jsonl")
    ap.add_argument("--allow", default=os.environ.get("ALLOWLIST", ""),
                    help="comma-separated allowlisted IPs/CIDRs")
    args = ap.parse_args()

    det = Detector()
    allow = parse_allowlist(args.allow)
    with open(args.log) as f:
        for line in f:
            for ev in det.process_line(line):
                e = ev.to_dict()
                plan = select_response(make_incident(e), allow)
                print(f"\n== {e['attack_type']} from {e['src_ip']}  severity={plan.severity}"
                      f"  compromise={e['possible_compromise']}")
                for ln in plan.explanation_lines():
                    print("   " + ln)
                plural = "" if plan.solutions_count == 1 else "s"
                print(f"   ({plan.solutions_count} valid combination{plural}, "
                      f"{plan.stats.nodes} nodes, {plan.stats.backtracks} backtracks)")
