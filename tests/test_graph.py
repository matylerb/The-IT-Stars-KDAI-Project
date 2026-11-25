"""Tests for the security knowledge graph queries."""
import pytest

from knowledge.graph import KnowledgeGraph

kg = KnowledgeGraph.load()


def ids(items):
    return [i["id"] for i in items]


def slot_ids(domains, slot):
    return ids(domains[slot])


# ---------- describe ----------
def test_describe_brute_force():
    d = kg.describe("brute_force")
    assert d["known"] is True
    assert d["technique"]["id"] == "T1110.001"
    assert d["technique"]["parent"]["id"] == "T1110"
    assert d["weakness"]["id"] == "A07:2021"


def test_unknown_attack_is_unknown_not_invented():
    # open-world assumption: no facts -> "unknown"
    assert kg.describe("ddos") == {"id": "ddos", "known": False}
    assert kg.mitigations("ddos") == []
    assert all(v == [] for v in kg.actions("ddos").values())


# ---------- mitigations ----------
def test_inheritance_gives_sub_technique_the_parent_mitigations():
    # T1110.001 has no mitigatedBy of its own; they come from T1110 by rule K3
    found = {m["id"]: m for m in kg.mitigations("brute_force")}
    assert "credential_reset" in found
    assert found["credential_reset"]["rule"] == "K3"
    assert found["credential_reset"]["path"] == [
        "(brute_force, mapsTo, T1110.001)",
        "(T1110.001, subTechniqueOf, T1110)",
        "(T1110, mitigatedBy, credential_reset)",
    ]


def test_mitigation_found_by_two_rules_is_listed_once_with_shortest_path():
    # account_lockout is on T1110 (K3) and on A07:2021 (K4)
    found = kg.mitigations("brute_force")
    assert ids(found).count("account_lockout") == 1


def test_sql_specific_fix_only_for_sqli():
    assert "parameterised_queries" in ids(kg.mitigations("sqli"))
    assert "parameterised_queries" not in ids(kg.mitigations("xss"))


def test_every_attack_has_mitigations_with_sources():
    for t in kg.match(p="type", o="AttackPattern"):
        ms = kg.mitigations(t.s)
        assert len(ms) >= 3, t.s
        assert all(m["source"].startswith("https://") for m in ms)


# ---------- actions ----------
def test_brute_force_actions_per_slot():
    result = kg.actions("brute_force")
    assert slot_ids(result, "network") == ["rate_limit_login", "block_ip"]
    assert slot_ids(result, "account") == ["reset_password"]
    assert slot_ids(result, "application") == []


def test_actions_come_with_a_proof_path():
    block = kg.actions("dir_scan")["network"][0]
    assert block["id"] == "block_ip"
    assert block["path"] == [
        "(dir_scan, mapsTo, T1595.003)",
        "(T1595.003, subTechniqueOf, T1595)",
        "(T1595, mitigatedBy, network_filtering)",
        "(network_filtering, implementedBy, block_ip)",
    ]


def test_xss_gets_no_network_action_because_the_graph_has_none():
    result = kg.actions("xss")
    assert slot_ids(result, "network") == []
    assert slot_ids(result, "application") == ["notify_developer"]


def test_changing_knowledge_changes_recommendations():
    # the graph, not the code, decides: remove one fact and the action disappears
    g = KnowledgeGraph.load()
    assert "rate_limit_login" in slot_ids(g.actions("brute_force"), "network")
    g.remove("T1110", "mitigatedBy", "account_lockout")
    g.remove("A07:2021", "mitigatedBy", "account_lockout")
    assert "rate_limit_login" not in slot_ids(g.actions("brute_force"), "network")


# ---------- grounding check ----------
def test_justify_supported_action():
    path = kg.justify("sqli", "block_ip")
    assert path[-1] == "(network_filtering, implementedBy, block_ip)"


def test_justify_rejects_action_the_graph_does_not_support():
    assert kg.justify("xss", "block_ip") is None
    assert kg.justify("sqli", "reset_password") is None
    assert kg.justify("sqli", "shutdown_server") is None


def test_load_refuses_an_inconsistent_graph(tmp_path):
    (tmp_path / "ontology.csv").write_text("AttackPattern,type,Class\n")
    (tmp_path / "facts.csv").write_text("sqli,type,AttackPatern\n")      # typo
    with pytest.raises(ValueError):
        KnowledgeGraph.load(tmp_path)
