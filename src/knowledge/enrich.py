"""
One call for the pipeline: DetectionEvent dict in, knowledge JSON out.

    from knowledge.enrich import enrich, enrich_json
    kg_part = enrich(event.to_dict())        # dict
    text = enrich_json(event.to_dict())      # same, as a JSON string

Who uses what:
  - Cillian (fact builder / rules): "attack", "known_attacker"
  - Tyler (CSP): "action_domains" = the domain of each slot (add "none" yourself)
  - Tyler (LLM / grounding check): "mitigations" with "path" and "source";
    for any action the LLM mentions, KnowledgeGraph.justify() must not be None
"""
import json

from knowledge.feedback_facts import known_attacks
from knowledge.graph import KnowledgeGraph

_kg = None


def get_graph() -> KnowledgeGraph:
    """Load the graph once and reuse it (loading reads and checks the CSVs)."""
    global _kg
    if _kg is None:
        _kg = KnowledgeGraph.load()
    return _kg


def enrich(event: dict, kg: KnowledgeGraph = None) -> dict:
    kg = kg or get_graph()
    attack = event["attack_type"]
    description = kg.describe(attack)

    return {
        "event_id": event.get("event_id"),
        "src_ip": event.get("src_ip"),
        "attack_type": attack,
        "graph_status": "known" if description["known"] else
                        "unknown: the knowledge graph has no facts about this attack, "
                        "so nothing is suggested",
        "attack": description,
        "mitigations": kg.mitigations(attack),
        "action_domains": kg.actions(attack),
        "known_attacker": known_attacks(kg, event.get("src_ip")),
    }


def enrich_json(event: dict, kg: KnowledgeGraph = None) -> str:
    return json.dumps(enrich(event, kg))
