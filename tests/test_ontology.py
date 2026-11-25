"""Checks the real knowledge graph files against the ontology."""
from pathlib import Path

from detection.events import ATTACK_META
from knowledge.ontology import classes, properties, types_of, validate
from knowledge.triple_store import TripleStore

KG_DIR = Path(__file__).parent.parent / "data" / "kg"


def real_graph():
    s = TripleStore()
    s.load_csv(KG_DIR / "ontology.csv")
    s.load_csv(KG_DIR / "facts.csv")
    return s


def test_ontology_has_the_classes_and_properties_from_the_proposal():
    s = real_graph()
    assert {"AttackPattern", "Technique", "WeaknessCategory",
            "Mitigation", "ResponseAction"} <= classes(s)
    assert {"mapsTo", "classifiedAs", "mitigatedBy", "implementedBy"} <= properties(s)


def test_real_knowledge_graph_is_consistent():
    assert validate(real_graph()) == []


def test_every_detector_attack_type_is_in_the_graph():
    s = real_graph()
    for attack in ATTACK_META:
        assert "AttackPattern" in types_of(s, attack), attack


def test_graph_agrees_with_the_detector_mappings():
    # Cillian's DetectionEvent fills in mitre/owasp; the graph must say the same
    s = real_graph()
    for attack, meta in ATTACK_META.items():
        assert s.value(attack, "mapsTo") == meta["mitre"]
        assert meta["owasp"].startswith(s.value(attack, "classifiedAs"))


def test_every_mitigation_has_a_source():
    s = real_graph()
    for t in s.match(p="type", o="Mitigation"):
        assert (s.value(t.s, "source") or "").startswith("https://"), t.s


def test_every_action_fills_a_slot():
    s = real_graph()
    for t in s.match(p="type", o="ResponseAction"):
        assert s.value(t.s, "actsOn") in {"network", "account", "application"}, t.s


def test_typo_in_an_id_is_caught():
    s = real_graph()
    s.add("brute_force", "mapsTo", "T1110.01")          # typo, no such technique
    assert any("T1110.01" in e for e in validate(s))


def test_wrong_kind_of_link_is_caught():
    s = real_graph()
    s.add("block_ip", "mapsTo", "T1190")               # an action is not an attack
    assert any("subject should be" in e for e in validate(s))


def test_unknown_property_is_caught():
    s = real_graph()
    s.add("sqli", "fixedBy", "parameterised_queries")
    assert any("unknown property" in e for e in validate(s))
