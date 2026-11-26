# Report: Knowledge-Driven Cybersecurity Incident Advisor

*Outline: each section is written by the person named.*

## 1. Problem and formulation (everyone)
AIMA formulation: state, actions, transition model, goal test, knowledge representation, reasoning.

## 2. Knowledge graph (Ivan)
Ontology, triples, graph rules K1–K4, proof paths, open-world assumption. Why it is more than a lookup table.

## 3. Detection and rule engine (Cillian)
Detector rules and windows. Rule base R1–R4, forward chaining, conflict resolution (highest severity), explanation trace. Why each rule is justified.

## 4. Response selection, LLM and alerts (Tyler)
CSP (X, D, C), constraints C1–C4, backtracking with forward checking, MRV and LCV. LLM phrasing only, grounding check, template fallback. Telegram human in the loop, dry run. See src/response/README.md.

## 5. Environment, data, feedback and evaluation (Illya)
Docker environment, datasets and labelling, replay, feedback store, threshold tuning.

## 6. Evaluation results (Illya)
Detection metrics and the scenario table (proposal §7).

## 7. Changes since the proposal, with reasons (everyone)

## 8. Limitations and future work (everyone)

## 9. Use of generative AI tools
See the README.
