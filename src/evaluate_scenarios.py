"""
Scenario evaluation (Illya) — proposal §7.

evaluate.py measures the detector per request (recall / FPR / latency). This
runs the WHOLE pipeline — detector → knowledge graph → rule engine → CSP →
template advisor — once per recorded scenario and checks the properties the
proposal promises for explainability and safety:

  1. expected incident(s) and severity per scenario;
  2. every alert has a non-empty rule trace and a non-empty "why";
  3. every offered action has a graph proof (KnowledgeGraph.justify is not None);
  4. Block IP is never offered for an allowlisted IP, nor below high severity;
  5. benign traffic (locust) produces zero alerts.

It reuses the real modules, never a reimplementation, so a bug anywhere in the
pipeline shows up here. The LLM is stubbed out (template wording only), so no
network and no Groq key are needed; the "why" lines come from the graph and the
CSP regardless, which is exactly what we check.

Severity comes from Cillian's forward-chaining rule engine, exactly as the live
pipeline will use it:

    engine = RuleEngine.load("data/rules.json")
    severity, trace = engine.assess(event_dict, known_attacker)
    incident = make_incident(event_dict, knowledge=k, severity=severity, trace=trace)

The rule engine is a hard dependency: the scan-then-SQLi chain is only "critical"
because R2/R3 fire, and that is the headline result this evaluation exists to
show. Until the engine is merged, this script stops with a clear message instead
of a traceback.

Run it from the repository root:
    PYTHONPATH=src python -m evaluate_scenarios
    PYTHONPATH=src python -m evaluate_scenarios --json
"""
import argparse
import json
import sys

from advisor import advise
from detection.detector import Detector
from knowledge.enrich import enrich, get_graph
from response.selector import (
    make_incident, parse_allowlist, select_response, BLOCKING_SEVERITIES,
)

# No LLM: the template still produces what_happened / how_serious, and "why"
# is built from the graph + CSP either way. Keeps the eval offline and stable.
NO_LLM = lambda facts: None          # noqa: E731

BLOCK_IP = "block_ip"

# Each scenario: a recorded log, the incident(s) we expect (attack_type,
# severity) in order, an optional allowlist to apply, and whether any alert is
# expected at all. The chain scenario's "critical" needs the rule engine (R2/R3).
SCENARIOS = [
    {
        "name": "brute_force",
        "path": "data/brute_force_logs.jsonl",
        "expect": [("brute_force", "high"), ("brute_force", "critical")],
        "allowlist": "",
    },
    {
        "name": "dir_scan",
        "path": "data/dir_scan_logs.jsonl",
        "expect": [("dir_scan", "medium")],
        "allowlist": "",
    },
    {
        "name": "sqli",
        "path": "data/sqlmap_logs.jsonl",
        "expect": [("sqli", "high")],
        "allowlist": "",
    },
    {
        "name": "scan_then_sqli",
        "path": "data/scan_then_sqli_logs.jsonl",
        # dir_scan stays medium; the SQLi is lifted to critical by R2 (chain) + R3.
        "expect": [("dir_scan", "medium"), ("sqli", "critical")],
        "allowlist": "",
    },
    {
        "name": "benign",
        "path": "data/locust_logs.jsonl",
        "expect": [],                         # zero alerts
        "allowlist": "",
    },
    {
        "name": "brute_force_allowlisted",
        "path": "data/brute_force_logs.jsonl",
        "expect": [("brute_force", "high"), ("brute_force", "critical")],
        "allowlist": "10.0.0.60",             # the brute-force source: Block IP must never appear
    },
]


def load_engine(rules_path: str = "data/rules.json"):
    """Cillian's forward-chaining rule engine. A hard dependency of this eval.

    Returns a callable assess(event_dict, known_attacker) -> (severity, trace).
    """
    try:
        from detection.rule_engine import RuleEngine
    except ImportError as exc:
        raise SystemExit(
            "scenario evaluation needs Cillian's rule engine, which is not "
            "merged yet:\n"
            "  - src/detection/rule_engine.py (RuleEngine.load / .assess)\n"
            "  - data/rules.json\n"
            f"(import failed: {exc})\n"
            "The non-chain scenarios can only be checked once it lands; see "
            "TEAM_TODO.md, 'Cillian: rule engine'."
        )
    try:
        return RuleEngine.load(rules_path)
    except FileNotFoundError:
        raise SystemExit(
            f"scenario evaluation needs the rule base {rules_path}, which does "
            "not exist yet (Cillian). See TEAM_TODO.md."
        )


def run_scenario(scenario: dict, engine) -> dict:
    """Replay one scenario through the whole pipeline and check every property."""
    allowlist = parse_allowlist(scenario["allowlist"])
    allowlisted_run = bool(scenario["allowlist"])
    det = Detector()

    alerts = []            # (event_dict, plan, alert, trace) per detection
    for line in open(scenario["path"]):
        for ev in det.process_line(line):
            event = ev.to_dict()
            knowledge = enrich(event)
            severity, trace = engine.assess(event, knowledge["known_attacker"])
            incident = make_incident(event, knowledge=knowledge,
                                     severity=severity, trace=trace)
            plan = select_response(incident, allowlist)
            alert = advise(incident, plan, llm=NO_LLM)
            alerts.append((event, plan, alert, trace))

    checks = []            # (description, ok) pairs

    # (1) expected incidents and severities, in order.
    got = [(e["attack_type"], p.severity) for e, p, _, _ in alerts]
    checks.append((f"incidents {got} == expected {scenario['expect']}",
                   got == scenario["expect"]))

    # (5) benign => no alerts (expect == []) is covered by check (1); make it loud.
    if not scenario["expect"]:
        checks.append((f"no alerts on benign traffic (got {len(alerts)})",
                       len(alerts) == 0))

    graph = get_graph()
    for event, plan, alert, trace in alerts:
        tag = f"{event['attack_type']}/{plan.severity}"

        # (2) the rule engine fired (a severity trace) and the alert explains
        #     its actions (the graph/CSP "why these actions" lines).
        checks.append((f"[{tag}] rule trace non-empty", bool(trace)))
        checks.append((f"[{tag}] why non-empty", bool(alert.get("why"))))

        # (3) every offered action is backed by a graph proof path.
        for action in plan.allowed_actions:
            proof = graph.justify(event["attack_type"], action)
            checks.append((f"[{tag}] graph proof for '{action}'",
                           proof is not None))

        # (4a) Block IP only at high/critical severity.
        if BLOCK_IP in plan.allowed_actions:
            checks.append((f"[{tag}] Block IP only offered at high/critical",
                           plan.severity in BLOCKING_SEVERITIES))

        # (4b) Block IP never offered for an allowlisted IP.
        if allowlisted_run:
            checks.append((f"[{tag}] Block IP not offered for allowlisted "
                           f"{event['src_ip']}", BLOCK_IP not in plan.allowed_actions))

    passed = sum(1 for _, ok in checks if ok)
    return {
        "name": scenario["name"],
        "path": scenario["path"],
        "allowlist": scenario["allowlist"],
        "alerts": len(alerts),
        "incidents": got,
        "checks": checks,
        "passed": passed,
        "total": len(checks),
        "ok": passed == len(checks),
    }


def print_report(results: list) -> bool:
    all_ok = True
    print("Scenario evaluation (whole pipeline, template wording)")
    print("=" * 64)
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        allow = f"  allowlist={r['allowlist']}" if r["allowlist"] else ""
        print(f"\n{r['name']:24} [{mark}]  {r['passed']}/{r['total']} checks{allow}")
        print(f"  {r['path']}")
        print(f"  alerts: {r['alerts']}  incidents: {r['incidents']}")
        for desc, ok in r["checks"]:
            if not ok:
                print(f"    FAIL  {desc}")
        all_ok = all_ok and r["ok"]
    print("\n" + "=" * 64)
    print(f"OVERALL: {'PASS' if all_ok else 'FAIL'}  "
          f"({sum(r['passed'] for r in results)}/{sum(r['total'] for r in results)} checks)")
    return all_ok


def main():
    ap = argparse.ArgumentParser(description="Evaluate explainability and safety per scenario.")
    ap.add_argument("--rules", default="data/rules.json", help="rule base for the rule engine")
    ap.add_argument("--json", action="store_true", help="print raw JSON results only")
    args = ap.parse_args()

    engine = load_engine(args.rules)
    results = [run_scenario(s, engine) for s in SCENARIOS]

    if args.json:
        # Checks hold tuples; make them JSON-friendly.
        serialisable = []
        for r in results:
            r = dict(r)
            r["checks"] = [{"check": d, "ok": ok} for d, ok in r["checks"]]
            serialisable.append(r)
        print(json.dumps(serialisable, indent=2))
        all_ok = all(r["ok"] for r in results)
    else:
        all_ok = print_report(results)

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    sys.stdout.reconfigure(errors="replace")
    main()
