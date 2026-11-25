"""Tests for the CSP response selector (src/response/selector.py).

Incidents are built with response.kg_stub until Ivan's knowledge graph and
Cillian's rule engine are available; swap the builder then, the checks stay.
"""
import json
from pathlib import Path

from detection.detector import Detector
from response.csp import enumerate_solutions
from response.kg_stub import ACTIONS, stub_incident
from response.selector import (
    NONE, SLOTS, build_response_csp, is_allowlisted, parse_allowlist, select_response,
)

DATA = Path(__file__).resolve().parent.parent / "data"

ATTACKS = {
    "brute_force": "T1110.001",
    "sqli": "T1190",
    "xss": "T1189",
    "dir_scan": "T1595.003",
}


def make_event(attack_type="brute_force", severity="high", ip="10.0.0.60", compromise=False):
    return {
        "event_id": "0123456789abcdef",
        "attack_type": attack_type,
        "severity": severity,
        "confidence": 0.9,
        "src_ip": ip,
        "rule_ids": ["TEST-RULE"],
        "evidence": [],
        "possible_compromise": compromise,
        "owasp": "A07:2021-Identification and Authentication Failures",
        "mitre": ATTACKS[attack_type],
    }


def incident(**kw):
    return stub_incident(make_event(**kw))


def all_scenarios():
    """Every attack x severity x compromise x allowlisted combination."""
    for attack in ATTACKS:
        for sev in ("low", "medium", "high", "critical"):
            for comp in (False, True):
                for allowed in (False, True):
                    allow = parse_allowlist("10.0.0.60" if allowed else "")
                    yield incident(attack_type=attack, severity=sev, compromise=comp), allow


# --- safety constraints -----------------------------------------------------------

def test_c1_allowlisted_ip_is_never_blocked():
    for allow in ("10.0.0.60", "10.0.0.0/24", "192.168.1.1, 10.0.0.60"):
        plan = select_response(incident(severity="critical"), parse_allowlist(allow))
        assert "block_ip" not in plan.allowed_actions
        assert plan.recommended["network"] != "block_ip"
        assert any(r.action == "block_ip" and r.constraint == "C1" for r in plan.removed)


def test_c2_no_blocking_below_high():
    for sev in ("low", "medium"):
        plan = select_response(incident(attack_type="dir_scan", severity=sev), [])
        assert "block_ip" not in plan.allowed_actions
        assert any(r.action == "block_ip" and r.constraint == "C2" for r in plan.removed)


def test_blocking_offered_at_high_and_critical():
    for sev in ("high", "critical"):
        plan = select_response(incident(attack_type="sqli", severity=sev), [])
        assert "block_ip" in plan.allowed_actions
        assert not plan.removed


def test_c3_every_option_takes_some_action():
    for inc, allow in all_scenarios():
        csp, _, _ = build_response_csp(inc, allow)
        for sol in enumerate_solutions(csp):
            assert any(sol[s] != NONE for s in SLOTS)
        plan = select_response(inc, allow)
        if plan.status == "ok":
            assert any(a != NONE for a in plan.recommended.values())


def test_c4_compromise_requires_account_action():
    plan = select_response(incident(severity="critical", compromise=True), [])
    assert NONE not in plan.options["account"]
    assert plan.recommended["account"] != NONE
    assert [r.constraint for r in plan.required] == ["C4"]

    no_comp = select_response(incident(severity="high", compromise=False), [])
    assert NONE in no_comp.options["account"]
    assert no_comp.required == []


def test_rule_engine_severity_overrides_detector():
    # e.g. Cillian's R2/R3 escalate a scan to critical when it is part of a chain
    inc = incident(attack_type="dir_scan", severity="medium")
    assert "block_ip" not in select_response(inc, []).allowed_actions
    inc["severity"] = "critical"
    assert "block_ip" in select_response(inc, []).allowed_actions


# --- grounding in the knowledge graph -------------------------------------------------

def test_only_graph_actions_are_offered():
    for inc, allow in all_scenarios():
        graph_actions = {a["id"] for m in inc["mitigations"] for a in m["actions"]}
        plan = select_response(inc, allow)
        assert set(plan.allowed_actions) <= graph_actions
        for a in plan.allowed_actions:
            assert plan.provenance[a], f"{a} has no mitigation behind it"
            assert ACTIONS[a]["slot"] in plan.options and a in plan.options[ACTIONS[a]["slot"]]


def test_unknown_technique_has_nothing_to_offer():
    inc = incident()
    inc["mitigations"] = []       # open world: graph knows no mitigation
    plan = select_response(inc, [])
    assert plan.status == "unsatisfiable"
    assert plan.allowed_actions == [] and plan.recommended == {}
    assert "No combination" in plan.explanation_lines()[0]


def test_unsatisfiable_when_only_action_is_forbidden():
    inc = incident(severity="critical")
    inc["mitigations"] = [{"id": "block_source", "label": "Block",
                           "actions": [{"id": "block_ip", "slot": "network", "label": "Block"}]}]
    plan = select_response(inc, parse_allowlist("10.0.0.60"))
    assert plan.status == "unsatisfiable"
    assert [(r.action, r.constraint) for r in plan.removed] == [("block_ip", "C1")]


def test_actions_with_unknown_slot_are_ignored():
    inc = incident()
    inc["mitigations"].append({"id": "x", "actions": [{"id": "shutdown_server", "slot": "power"}]})
    plan = select_response(inc, [])
    assert "shutdown_server" not in plan.allowed_actions


def test_invalid_severity_rejected():
    inc = incident()
    inc["severity"] = "apocalyptic"
    try:
        select_response(inc, [])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# --- output is consistent with the CSP --------------------------------------------

def test_plan_matches_brute_force_enumeration():
    for inc, allow in all_scenarios():
        csp, _, _ = build_response_csp(inc, allow)
        sols = enumerate_solutions(csp)
        plan = select_response(inc, allow)
        assert plan.solutions_count == len(sols)
        expected = {sol[s] for sol in sols for s in SLOTS} - {NONE}
        assert set(plan.allowed_actions) == expected
        if sols:
            assert csp.is_solution({**plan.recommended, "severity": plan.severity})


def test_plan_is_json_serialisable():
    d = select_response(incident(severity="critical", compromise=True), []).to_dict()
    assert json.loads(json.dumps(d))["status"] == "ok"


# --- allowlist parsing --------------------------------------------------------------

def test_allowlist_parsing():
    nets = parse_allowlist(" 10.0.0.1 , ,192.168.0.0/16")
    assert is_allowlisted("10.0.0.1", nets)
    assert is_allowlisted("192.168.4.20", nets)
    assert not is_allowlisted("10.0.0.2", nets)
    assert not is_allowlisted("not-an-ip", nets)
    assert parse_allowlist(None) == [] and parse_allowlist("") == []


# --- real recorded attacks ------------------------------------------------------------

def plans_for(log_name, allow=""):
    det = Detector()
    out = []
    with open(DATA / log_name) as f:
        for line in f:
            for ev in det.process_line(line):
                out.append(select_response(stub_incident(ev.to_dict()), parse_allowlist(allow)))
    return out


def test_replayed_dir_scan_is_not_blocked():
    plans = plans_for("dir_scan_logs.jsonl")
    assert len(plans) == 1 and plans[0].severity == "medium"
    assert "block_ip" not in plans[0].allowed_actions


def test_replayed_brute_force_escalation():
    high, critical = plans_for("brute_force_logs.jsonl")
    assert high.severity == "high" and "block_ip" in high.allowed_actions
    assert critical.severity == "critical" and critical.recommended["account"] != NONE


def test_replayed_brute_force_from_allowlisted_ip():
    for plan in plans_for("brute_force_logs.jsonl", allow="10.0.0.60"):
        assert "block_ip" not in plan.allowed_actions
