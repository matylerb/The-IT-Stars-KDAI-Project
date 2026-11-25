"""End-to-end: a real DetectionEvent in, knowledge JSON out."""
import json
from datetime import datetime, timedelta, timezone

from detection.events import DetectionEvent
from knowledge.enrich import enrich, enrich_json
from knowledge.graph import KnowledgeGraph

T0 = datetime(2026, 11, 18, 0, 0, 0, tzinfo=timezone.utc)


def detection(attack_type, severity="high", ip="10.0.0.60"):
    """Build the event exactly like Cillian's detector does."""
    return DetectionEvent(attack_type=attack_type, severity=severity, confidence=0.9,
                          src_ip=ip, window_start=T0, window_end=T0 + timedelta(seconds=5),
                          request_count=10).to_dict()


def action_ids(result, slot):
    return [a["id"] for a in result["action_domains"][slot]]


def test_output_is_json_with_the_agreed_fields():
    out = json.loads(enrich_json(detection("sqli")))
    for key in ("event_id", "src_ip", "attack_type", "graph_status", "attack",
                "mitigations", "action_domains", "known_attacker"):
        assert key in out
    assert set(out["action_domains"]) == {"network", "account", "application"}


def test_proposal_example_brute_force_offers_block_rate_limit_reset():
    out = enrich(detection("brute_force", "critical"))
    assert out["attack"]["technique"]["id"] == "T1110.001"
    assert action_ids(out, "network") == ["rate_limit_login", "block_ip"]
    assert action_ids(out, "account") == ["reset_password"]


def test_known_attacker_is_reported():
    kg = KnowledgeGraph.load()
    kg.add("10.0.0.60", "type", "Attacker")
    kg.add("10.0.0.60", "confirmedAttackerOf", "brute_force")
    out = enrich(detection("sqli", ip="10.0.0.60"), kg)
    assert out["known_attacker"] == ["brute_force"]


def test_every_offered_action_is_grounded_in_the_graph():
    kg = KnowledgeGraph.load()
    for attack in ("sqli", "xss", "brute_force", "dir_scan"):
        out = enrich(detection(attack), kg)
        for actions in out["action_domains"].values():
            for a in actions:
                assert kg.justify(attack, a["id"]) is not None


def test_unknown_attack_suggests_nothing():
    out = enrich({"event_id": "x", "src_ip": "1.2.3.4", "attack_type": "ddos"})
    assert out["graph_status"].startswith("unknown")
    assert out["mitigations"] == []
