"""Detector + knowledge graph on the real labelled dataset."""
from knowledge.demo import detect_dataset, main
from knowledge.enrich import enrich
from knowledge.graph import KnowledgeGraph

kg = KnowledgeGraph.load()
results = [enrich(ev, kg) for ev in detect_dataset()]


def test_every_detected_attack_is_known_to_the_graph():
    assert {r["attack_type"] for r in results} == {"brute_force", "dir_scan", "sqli"}
    assert all(r["graph_status"] == "known" for r in results)


def test_every_alert_gets_at_least_one_action():
    for r in results:
        assert any(r["action_domains"].values()), r["attack_type"]


def test_demo_runs(capsys):
    main()
    out = capsys.readouterr().out
    assert "Proof path" in out
    assert "learned:" in out
