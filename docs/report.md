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

**Environment.** The target is OWASP Juice Shop behind nginx, run locally with
Docker Compose (`docker-compose.yml`, `nginx/nginx.conf`). nginx is configured
to write a one-line JSON access log, which is the single interface between the
live site and the agent: the agent either tails that file or reads replayed
lines on stdin. Keeping the contract to "one JSON object per request" means the
detector, the replay tool and the evaluation all consume exactly the same
records, so a replayed attack and a live attack are indistinguishable to the
rest of the pipeline. Secrets (Telegram and Groq keys, the allowlist) live in
`.env`, which is git-ignored; `.env.example` documents them.

**Data and labelling.** Attacks were recorded by running our own scripts
(`src/attacks/`) and sqlmap against the site, and benign traffic was generated
with Locust (`src/traffic/locust_benign.py`). `src/dataset/label_logs.py` joins
every recorded line against `data/ground_truth.jsonl` by source IP and
timestamp window and writes `data/labelled_dataset.jsonl` (968 requests: 719
benign, 249 attack). Labelling is by ground-truth window, not by re-running the
detector, so the evaluation never grades the detector against its own output.

**The scan-then-SQLi chain scenario.** The attack-chain rules R2/R3 only fire
when *one* IP first scans and then injects (`same_ip`, `before`). In the raw
recordings the scan is from `10.0.0.70` and the SQLi from `10.0.0.80`, so the
chain can never fire. `src/dataset/make_chain_scenario.py` builds
`data/scan_then_sqli_logs.jsonl` by reusing the real dir-scan lines and the real
sqlmap attacker lines, rewriting the SQLi source IP to the scanner's and
shifting its timestamps to start 60 s after the scan. Only the IP and the
absolute timestamps change — the sqlmap payloads, paths and inter-request gaps
are preserved — so the detector still recognises genuine SQLi, now attributed to
the same attacker as the scan, in the right order. Generating it from a script
rather than editing JSON by hand keeps it reproducible and reviewable.

**Replay.** `src/replay.py` plays a recorded log back to stdout with the
original timing (or instantly, `--speed 0`), which drives the whole pipeline
offline and is the demo's fallback if a live attack fails on the network.

**Feedback and threshold tuning.** Every human verdict from Telegram is appended
to `data/feedback.jsonl` by `src/feedback/store.py` as
`(event_id, rule_ids, verdict)`. `src/feedback/tune_thresholds.py` counts
false-positive verdicts per rule and, past a bounded limit, nudges the relevant
detector threshold one fixed step towards firing less, never past a hard ceiling,
logging every change for review. This is explicit knowledge revision by editing
data — not retraining a model (Lecture 7) — and it is deliberately bounded so a
noisy feedback stream cannot blind the detector. Confirmed attackers are the
other feedback path: they become knowledge-graph facts (Ivan's side) and, via
rule R4, raise the severity of that IP's next incident.

## 6. Evaluation results (Illya)

**Detection metrics** (per request, on the 968-request labelled dataset, from
`PYTHONPATH=src python -m evaluate`). The detector is scored against the
ground-truth labels, never its own output; latency is the span of the window
that produced each alert (see `src/evaluate.py` for why wall-clock latency is
meaningless in a replay).

| Measure | Result | Target | |
|---|---|---|---|
| Recall | 98.4% (245/249) | ≥ 90% | PASS |
| False-positive rate | 0.0% (0/719) | ≤ 5% | PASS |
| Max alert latency | 5.0 s | < 30 s | PASS |

Recall by attack type: brute_force 100% (17/17), dir_scan 100% (66/66),
sqli 97.6% (162/166). The four missed SQLi requests are blind time-based
payloads with no injectable characters in the query string; nginx does not log
request bodies, so there is no signal to catch them (a scope limit, §8).

**Scenario evaluation** (whole pipeline, from
`PYTHONPATH=src python -m evaluate_scenarios`). Each recorded scenario is
replayed through detector → knowledge graph → rule engine → CSP → template
advisor, and every alert is checked for: the expected incident and severity; a
non-empty rule trace and a non-empty "why these actions"; a knowledge-graph
proof (`justify` ≠ None) for every offered action; and the two Block-IP safety
rules. The LLM is stubbed out, so the run is offline and the "why" lines are
exactly the graph/CSP output under test.

| Scenario | Incidents (type, severity) | Alerts | Properties checked |
|---|---|---|---|
| brute_force | brute_force high, brute_force critical | 2 | severity, trace, graph proof per action, Block IP only ≥ high |
| dir_scan | dir_scan medium | 1 | Block IP correctly **not** offered (medium) |
| sqli | sqli high | 1 | severity, trace, graph proof per action |
| scan_then_sqli | dir_scan medium, **sqli critical** | 2 | chain rules R2+R3 lift SQLi to critical |
| benign (locust) | — | **0** | no alerts on benign traffic |
| brute_force + allowlist 10.0.0.60 | brute_force high, critical | 2 | Block IP **never** offered for an allowlisted IP |

The headline row is `scan_then_sqli`: the SQLi stage alone is *high*, but because
the same IP scanned first, R2 derives `chain` and R3 raises it to *critical* —
knowledge in the chain changing the outcome, shown end to end. The
`brute_force + allowlist` row demonstrates constraint C1, and `dir_scan` shows
C2 withholding Block IP below high severity.

> The scan-then-SQLi severity and the scenario run depend on the forward-chaining
> rule engine (§3). Where the engine is not yet integrated at the time of
> writing, the `evaluate_scenarios` tests skip and the critical severity on the
> chain row is pending that merge; the detector metrics above and the
> chain-scenario construction are independent of it and verified now.

## 7. Changes since the proposal, with reasons (everyone)

## 8. Limitations and future work (everyone)

## 9. Use of generative AI tools
See the README.
