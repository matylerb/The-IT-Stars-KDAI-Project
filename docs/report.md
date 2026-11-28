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

**Environment.** The target is OWASP Juice Shop behind nginx, run locally with Docker Compose (`docker-compose.yml`, `nginx/nginx.conf`). nginx writes a one-line JSON access log — the single contract between the site and the agent. Because the detector, replay tool and evaluation all read the same record format, a replayed attack and a live attack are indistinguishable to the rest of the pipeline. Secrets live in `.env` (git-ignored); `.env.example` documents them.

**Data and labelling.** Attacks were recorded with our own scripts (`src/attacks/`) and sqlmap; benign traffic was generated with Locust. `src/dataset/label_logs.py` joins every line against `data/ground_truth.jsonl` by IP and timestamp window to produce `data/labelled_dataset.jsonl` (968 requests: 719 benign, 249 attack). Labelling is by ground-truth window, not by re-running the detector, so the evaluation never grades the detector against its own output.

**Chain scenario.** Rules R2/R3 require one IP to scan then inject. In the raw recordings the scan is from `10.0.0.70` and the SQLi from `10.0.0.80`, so the chain can never fire. `src/dataset/make_chain_scenario.py` rewrites the SQLi source IP to the scanner's and shifts its timestamps to start 60 s after the scan; payloads and inter-request gaps are unchanged. The script keeps the construction reproducible and reviewable.

**Replay.** `src/replay.py` plays a log back to stdout with original timing or instantly (`--speed 0`), driving the whole pipeline offline. It is the demo fallback if a live attack fails.

**Feedback and threshold tuning.** Every Telegram verdict is appended to `data/feedback.jsonl` as `(event_id, rule_ids, verdict)`. `src/feedback/tune_thresholds.py` counts false-positive verdicts per rule and nudges the relevant threshold one bounded step, logging every change. This is explicit knowledge revision — not retraining a model (Lecture 7) — and is deliberately bounded so a noisy feedback stream cannot blind the detector. Confirmed attackers become knowledge-graph facts (Ivan's side) and via rule R4 raise the severity of that IP's next incident.

## 6. Evaluation results (Illya)

**Detection metrics** (per request, 968-request labelled dataset, `PYTHONPATH=src python -m evaluate`):

| Measure | Result | Target | |
|---|---|---|---|
| Recall | 98.4% (245/249) | ≥ 90% | PASS |
| False-positive rate | 0.0% (0/719) | ≤ 5% | PASS |
| Max alert latency | 5.0 s | < 30 s | PASS |

Recall by type: brute_force 100% (17/17), dir_scan 100% (66/66), sqli 97.6% (162/166). The four missed SQLi requests are blind time-based payloads with no query-string signal; nginx does not log request bodies (scope limit, §8).

**Scenario evaluation** (`PYTHONPATH=src python -m evaluate_scenarios`). Each scenario is replayed through the full pipeline with the LLM stubbed out. Every alert is checked for: expected incident and severity; non-empty rule trace; a knowledge-graph proof for every offered action; and the two Block-IP safety rules.

| Scenario | Incidents | Alerts | Properties checked |
|---|---|---|---|
| brute_force | high → critical | 2 | severity, trace, graph proof, Block IP only ≥ high |
| dir_scan | medium | 1 | Block IP correctly **not** offered |
| sqli | high | 1 | severity, trace, graph proof |
| scan_then_sqli | medium → **critical** | 2 | R2+R3 lift SQLi to critical via chain |
| benign | — | **0** | no false alerts |
| brute_force + allowlist | high, critical | 2 | Block IP **never** offered for allowlisted IP |

The key row is `scan_then_sqli`: SQLi alone is *high*, but because the same IP scanned first, R2 derives `chain` and R3 raises it to *critical* — the knowledge chain changing the outcome end to end.

> The chain severity and scenario run depend on Cillian's rule engine (§3). Until that merges, `evaluate_scenarios` tests skip and the critical row is pending; detection metrics and chain-scenario construction are independent and verified now.

## 7. Changes since the proposal, with reasons (everyone)

## 8. Limitations and future work (everyone)

## 9. Use of generative AI tools
See the README.
