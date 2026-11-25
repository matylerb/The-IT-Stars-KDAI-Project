# Handoff: Ivan's knowledge graph

**For:** Tyler, Cillian (and Illya for the feedback link)
**From:** Ivan
**Status:** done and tested (`tests/test_triple_store.py`, `test_ontology.py`, `test_graph.py`, `test_feedback_facts.py`, `test_enrich.py`, `test_enrich_dataset.py`).

## Where it sits

```
detector -> DetectionEvent -> [knowledge graph] -> facts/rules (Cillian) -> CSP (Tyler) -> LLM -> Telegram
                                     ^                                                          |
                                     +------ confirmed attackers <----- feedback store <--------+
```

## What is in it

| Part | File | Lecture |
|---|---|---|
| Ontology: classes, properties, domain and range | `data/kg/ontology.csv` | 8 |
| Facts: 4 attacks, 6 ATT&CK techniques, 3 OWASP categories, 12 mitigations (each with a source), 4 response actions | `data/kg/facts.csv` | 8 |
| Triple store with pattern-matching queries (`?variables`, like SPARQL) | `src/knowledge/triple_store.py` | 8 |
| Consistency check of facts against the ontology | `src/knowledge/ontology.py` | 8 |
| Graph rules K1-K4, actions per CSP slot, proof paths, grounding check | `src/knowledge/graph.py` | 7, 8 |
| Confirmed verdicts -> new facts | `src/knowledge/feedback_facts.py` | 7 |
| One call for the pipeline | `src/knowledge/enrich.py` | |
| Presentation demo | `src/knowledge/demo.py` | |

All knowledge is in the two CSV files. To change what the system recommends, edit `facts.csv`, not the code. The tests check every change against the ontology.

## How the graph decides (not just a lookup)

Mitigations are not stored next to the attack. They are derived by four graph rules:

| Rule | Pattern |
|---|---|
| K1 | `(?a, mitigatedBy, ?m)` |
| K2 | `(?a, mapsTo, ?t) ∧ (?t, mitigatedBy, ?m)` |
| K3 | `(?a, mapsTo, ?t) ∧ (?t, subTechniqueOf, ?p) ∧ (?p, mitigatedBy, ?m)`: inheritance from the parent technique |
| K4 | `(?a, classifiedAs, ?w) ∧ (?w, mitigatedBy, ?m)` |

An action goes into a CSP domain if `(?m, implementedBy, ?action)` holds for one of those mitigations, and `(?action, actsOn, ?slot)` says which slot. Which actions are finally shown (allowlist, severity) is decided by the CSP, not here.

K3 is why the graph is more than a lookup table: `T1110.001` has no mitigations of its own, so it gets them from its parent `T1110` (like "a Dog is a Mammal" in Lecture 8). Every answer comes with the triples that prove it (`path`), and changing one line in `facts.csv` changes the recommendations.

Open-world assumption: no path means "unknown", and nothing is invented.

## How to use it

```python
from knowledge.enrich import enrich, enrich_json

kg_part = enrich(event.to_dict())        # dict
text = enrich_json(event.to_dict())      # JSON string
```

Lower-level, if you need it:

```python
from knowledge.graph import KnowledgeGraph
kg = KnowledgeGraph.load()                    # load once
kg.justify("sqli", "block_ip")                # proof path, or None if the graph does not support it
kg.query([("?a", "mapsTo", "?t")])            # any pattern query
```

### Tyler
- **CSP domains:** `kg_part["action_domains"]` has the keys `network`, `account`, `application`. Each one is a list of actions (`id`, `label`, `path`). Add `none` to each domain yourself.
- **Grounding check:** for every action the LLM or CSP outputs, `KnowledgeGraph.justify(attack_type, action_id)` must not be `None`.
- **LLM prompt:** use `attack.label`, `attack.description`, `technique`, `weakness`, and `mitigations[*].label/description/source`. Every item has a source URL.
- **Docker:** the graph reads `data/kg/*.csv`. If the agent image only copies `src/`, add `COPY data/kg/ /app/data/kg/` to the Dockerfile (with `src/` at `/app/src/`).
- **Startup:** call `learn_from_feedback(get_graph(), FeedbackStore())` once, so confirmed attackers from earlier runs are known (`from knowledge.feedback_facts import learn_from_feedback`, `from knowledge.enrich import get_graph`).

### Cillian
- `kg_part["attack"]["technique"]` and `["weakness"]` for facts like `technique(e1, T1110.001)`.
- `kg_part["known_attacker"]` lists the attack types a human already confirmed for this IP. It is empty if none. You can use it as a fact in your rules if you want.

## Output example (brute force, shortened)

```json
{
  "event_id": "48207b18-…",
  "src_ip": "10.0.0.60",
  "attack_type": "brute_force",
  "graph_status": "known",
  "attack": {
    "id": "brute_force", "known": true, "label": "Brute-force login",
    "description": "Many passwords were tried against the login page to guess one that works.",
    "technique": {"id": "T1110.001", "label": "Brute Force: Password Guessing", "source": "…",
                  "parent": {"id": "T1110", "label": "Brute Force", "source": "…"}},
    "weakness": {"id": "A07:2021", "label": "Identification and Authentication Failures", "source": "…"}
  },
  "mitigations": [
    {"id": "account_lockout", "label": "Limit failed logins", "description": "…",
     "source": "https://attack.mitre.org/mitigations/M1036/", "rule": "K3",
     "reason": "it is inherited from the parent ATT&CK technique",
     "path": ["(brute_force, mapsTo, T1110.001)", "(T1110.001, subTechniqueOf, T1110)",
              "(T1110, mitigatedBy, account_lockout)"]}
  ],
  "action_domains": {
    "network": [{"id": "rate_limit_login", "label": "Rate-limit logins", "slot": "network",
                 "mitigation": "account_lockout", "path": ["…", "(account_lockout, implementedBy, rate_limit_login)"]},
                {"id": "block_ip", "label": "Block IP", "slot": "network", "mitigation": "network_filtering", "path": ["…"]}],
    "account": [{"id": "reset_password", "label": "Reset password", "slot": "account",
                 "mitigation": "credential_reset", "path": ["…"]}],
    "application": []
  },
  "known_attacker": []
}
```

## Run

```bash
PYTHONPATH=src python -m knowledge.demo     # presentation demo (4 scenes)
PYTHONPATH=src python -m knowledge.graph    # summary of the graph
python -m pytest -q                         # all tests
```

## Limitations
- The knowledge is hand-built from MITRE ATT&CK and the OWASP cheat sheets, so it is small and may be incomplete (the knowledge acquisition bottleneck, Lecture 8).
- The ontology check only covers `type`, `domain` and `range`, not full description logic.
- Response actions are a deliberately small set (4) to keep the CSP simple.
