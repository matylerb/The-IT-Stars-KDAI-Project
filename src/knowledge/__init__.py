"""
Knowledge graph (Ivan).

Security knowledge stored as (subject, predicate, object) triples in CSV files:
  data/kg/ontology.csv  - the ontology: classes, properties, domain and range
  data/kg/facts.csv     - the facts: attacks, ATT&CK techniques, OWASP
                          categories, mitigations and response actions

Modules:
  triple_store.py   - loads triples and answers pattern-matching queries
  ontology.py       - checks the facts against the ontology
  graph.py          - security questions: what is this attack, what mitigates
                      it, which actions are allowed, and why (justification path)
  feedback_facts.py - turns confirmed alerts from the feedback store into facts
  enrich.py         - one call for the pipeline: DetectionEvent dict in, JSON out
"""
