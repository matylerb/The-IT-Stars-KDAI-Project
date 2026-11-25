"""Tests for turning feedback verdicts into knowledge-graph facts."""
from feedback.store import FeedbackStore
from knowledge.feedback_facts import known_attacks, learn_from_feedback
from knowledge.graph import KnowledgeGraph
from knowledge.ontology import validate


def event(event_id, attack_type="brute_force", ip="10.0.0.60"):
    return {"event_id": event_id, "attack_type": attack_type, "src_ip": ip,
            "rule_ids": ["BF-LOGIN-401"]}


def test_confirmed_alert_becomes_a_fact(tmp_path):
    store = FeedbackStore(str(tmp_path / "fb.jsonl"))
    store.record(event("e1"), verdict="confirmed")
    kg = KnowledgeGraph.load()

    added = learn_from_feedback(kg, store)

    assert ("10.0.0.60", "confirmedAttackerOf", "brute_force") in added
    assert known_attacks(kg, "10.0.0.60") == ["brute_force"]
    assert validate(kg) == []            # new facts still follow the ontology


def test_false_positive_and_dismissed_add_nothing(tmp_path):
    store = FeedbackStore(str(tmp_path / "fb.jsonl"))
    store.record(event("e1"), verdict="false_positive")
    store.record(event("e2", ip="10.0.0.99"), verdict="dismissed")
    kg = KnowledgeGraph.load()
    assert learn_from_feedback(kg, store) == []
    assert known_attacks(kg, "10.0.0.60") == []


def test_only_the_latest_verdict_counts(tmp_path):
    store = FeedbackStore(str(tmp_path / "fb.jsonl"))
    store.record(event("e1"), verdict="confirmed")
    store.record(event("e1"), verdict="false_positive")   # human changed their mind
    kg = KnowledgeGraph.load()
    assert learn_from_feedback(kg, store) == []


def test_running_twice_does_not_duplicate(tmp_path):
    store = FeedbackStore(str(tmp_path / "fb.jsonl"))
    store.record(event("e1"), verdict="confirmed")
    kg = KnowledgeGraph.load()
    learn_from_feedback(kg, store)
    assert learn_from_feedback(kg, store) == []


def test_unknown_attack_type_is_ignored(tmp_path):
    store = FeedbackStore(str(tmp_path / "fb.jsonl"))
    store.record(event("e1", attack_type="ddos"), verdict="confirmed")
    kg = KnowledgeGraph.load()
    assert learn_from_feedback(kg, store) == []


def test_empty_store_is_fine(tmp_path):
    kg = KnowledgeGraph.load()
    assert learn_from_feedback(kg, FeedbackStore(str(tmp_path / "none.jsonl"))) == []
