# What's left before Monday 30 Nov, 10:00

Final commit is **Monday 10:00** (no commits after). Demo is 12:00–14:00. Individual reflections are due at 22:00.

This list checks the repo against three things: proposal v2, the assignment brief, and Bianca's feedback. Her feedback, in short:

1. **The graph must do more than a lookup.** The demo must show knowledge in the graph *changing* a recommendation.
2. **Don't add too many CSP categories or constraints.** Knowledge representation plus reasoning is the main value.
3. **Success depends on the severity and attack-chain rules.** A small, well-justified rule set beats a big one.

---

## Done: Tyler (CSP, LLM, grounding, Telegram, orchestrator)

- **Orchestrator** (`src/agent/main.py`): log → detector → graph → CSP → LLM → alert. It reads `.env` itself.
  ```
  python src/replay.py data/brute_force_logs.jsonl --speed 0 | python src/agent/main.py --stdin
  ```
- **Telegram** (`src/telegram_bot.py`): one button per CSP-approved action, plus "Ignore: normal traffic" and "Ignore: not sure".
  - Block IP is a dry run: it writes to `data/nginx_deny.dryrun.conf` and never touches nginx.
  - Every tap is saved in Illya's feedback store.
- **"Why these actions" in every alert:** built from the graph and the CSP, never by the LLM. For example:
  - `Rate-limit logins: Brute-force login → ATT&CK T1110.001 → part of T1110 → mitigated by Limit failed logins`
  - `Not offered: Block IP (C2: blocking an IP is only offered at high or critical severity; this incident is medium)`
  - `Known attacker: a person already confirmed 10.0.0.60 as an attacker (brute_force)`
- **Confirmed attackers go into the graph straight away.** Tapping an action button adds `(ip, confirmedAttackerOf, attack)` to Ivan's graph immediately, and it's also reloaded from `data/feedback.jsonl` at startup.
- **LLM:** Groq `openai/gpt-oss-120b` (the old llama model is gone). If the LLM fails, a template is used.
  - It is given facts only, never the attacker's raw requests.
  - The grounding check rejects any action, technique, OWASP id, IP or severity that isn't in the facts.
  - **When the rule engine lands, its trace replaces the detector's rule ids in what the LLM explains.**
- **Docker:** `docker compose build agent` works, and the container runs the pipeline. Secrets come from `.env` (see `.env.example`). Never commit `.env`.
- 185 tests pass: `python -m pytest -q`

---

## Cillian: rule engine (**most urgent**, Bianca's point 3)

Proposal §5 promises forward chaining over a rule base stored as data, with an explanation trace. Today severity is hard-coded in the detector, so this is the biggest gap against the rubric ("Application of AI techniques" and "Knowledge representation and reasoning" are worth 8 of the 15 marks).

**Keep it to these four rules**, each justified in one line in the report:

| Rule | IF | THEN | Why (for the report) |
|---|---|---|---|
| R1 | `attack(E, brute_force) ∧ success_after_fail(E)` | `severity(E, critical)` | a guessed password worked: the account is likely compromised |
| R2 | `attack(E1, dir_scan) ∧ attack(E2, sqli) ∧ same_ip(E1, E2) ∧ before(E1, E2)` | `chain(E2)` | reconnaissance followed by exploitation is a planned attack |
| R3 | `chain(E)` | `severity(E, critical)` | a multi-stage attack is worse than either stage alone |
| R4 | `confirmed_attacker(ip(E))` | `severity(E, high)` *(at least)* | a person already confirmed this IP is hostile (**fact comes from the knowledge graph**) |

Starting fact: the detector's own severity, `detected_severity(E, S) → severity(E, S)`. If several rules set a severity, **the highest wins** (proposal §5).

**What Tyler's code needs from you:**
```python
engine = RuleEngine.load("data/rules.json")       # rules as data, not code (Lecture 8)
severity, trace = engine.assess(event, known_attacker)
#   event          = DetectionEvent dict (ev.to_dict())
#   known_attacker = knowledge["known_attacker"], e.g. ["brute_force"] or []
#   severity       = "low" | "medium" | "high" | "critical"
#   trace          = list of plain-English strings, one per fired rule, e.g.
#                    "R1: a login succeeded right after a brute-force burst -> critical"
```
- The engine must **remember earlier events per IP**: R2 needs the earlier dir_scan.
- Run forward chaining until no new facts appear (fixed point), and record every rule that fired. That's the explanation facility (Lectures 7–8).
- Tests: each rule fires and doesn't fire, highest severity wins, the trace lists the fired rules, and nothing changes after the fixed point.
- **Update the README** once it's merged: the "Rule engine" row in the architecture table still says *being added*.
- **Tell Tyler when it's merged. He wires it into `handle()` in `src/agent/main.py`** (about 3 lines: `make_incident(event, knowledge=k, severity=severity, trace=trace)`). The CSP, the LLM and Telegram already accept `severity` and `trace`.

**Why R4 matters for the demo:** a dir_scan is medium, so the CSP's C2 rule hides Block IP. Once a human confirms that IP, the graph records it, R4 raises the next alert to high, and **Block IP appears**. That's Bianca's point 1 shown live: graph knowledge changes the recommendation.

---

## Illya: scenario data and evaluation (proposal §7) — **done**

1. ~~**Scan-then-injection replay**~~: done. `src/dataset/make_chain_scenario.py`
   builds `data/scan_then_sqli_logs.jsonl` — the real dir_scan lines then the
   real sqlmap lines rewritten to the scanner's IP (10.0.0.70) with timestamps
   shifted to follow the scan. The detector emits dir_scan then sqli from one
   IP, so R2/R3 can fire. Tested (`tests/test_evaluate_scenarios.py`).
2. ~~**Scenario evaluation**~~: done. `src/evaluate_scenarios.py`
   (`PYTHONPATH=src python -m evaluate_scenarios`) replays brute force, scan,
   SQLi, scan-then-SQLi, benign, and an allowlisted brute force through the
   whole pipeline and checks expected severity, a non-empty trace and `why`, a
   graph proof (`justify`) for every offered action, Block IP only at ≥ high and
   never for an allowlisted IP, and 0 alerts on benign. The results table is in
   `docs/report.md` §6, and §5 is written.
   - **Depends on Cillian's rule engine** for the chain's *critical* severity.
     The evaluator calls `RuleEngine.load("data/rules.json")` /
     `engine.assess(event, known_attacker)` exactly as specified below. Until it
     merges, `evaluate_scenarios` stops with a clear message and the three
     engine-dependent tests skip; the chain data and the detector metrics are
     verified now. Verified end-to-end against a temporary local stub of that
     interface. **Cillian: when you merge, re-run `python -m evaluate_scenarios`
     — the chain row should flip to `sqli critical` with no code change.**
3. ~~Root `requirements.txt`~~: done (Tyler).

---

## Ivan: knowledge graph (done)

- Your part matches the proposal: ontology, triples, K1–K4 including inheritance, proof paths, consistency check, and feedback facts.
- **For the demo and report, Bianca's point 1:** alerts now show your proof paths. The "→ part of T1110 →" step is your K3 inheritance rule. Be ready to explain why it's more than a lookup:
  - mitigations are **derived** by rules, not stored next to the attack;
  - editing one line of `facts.csv` changes the buttons with no code change;
  - confirmed attackers become new facts that (with R4) change severity and therefore the actions.
- A quick live demo idea: remove one `implementedBy` line, rerun, and the button disappears.

---

## Everyone

**Repo cleanup (done by Tyler):**
- Lecture slides and the assignment brief moved to `lectures/`.
- `proposal/proposal.md` is now proposal v2; the first proposal was removed.
- Removed `plan.md` (an old, unused plan) and `DETECTION_INTEGRATION_HANDOFF.md` (an internal handoff note). Both are still in the git history.
- Added root `requirements.txt`, `docs/report.md` (outline with owners), `presentation/` and `assets/`.
- [x] `README.md` rewritten with everything the brief asks for. **Check your own rows** in the architecture and contribution tables.

**Still to do:**
- [ ] `docs/report.md`: each person writes their own section in the outline, plus:
  - the AIMA formulation (state, actions, goal, knowledge representation, reasoning), since the brief asks for it explicitly;
  - the evaluation table;
  - limitations (proposal §3);
  - **changes since the proposal, with reasons:**
    - CSP constraint C4 (an account action is required when a login may be compromised);
    - severity as a CSP variable;
    - LCV and degree heuristics;
    - the LLM model switch;
    - rule R4.
- [ ] `presentation/`: slides (5–10 minutes): problem → AI techniques → design decisions → challenges → results.
- [ ] `assets/`: screenshots (Telegram alert, architecture diagram). Link a Telegram screenshot from the README's "Example output".
- [ ] **AI tool acknowledgement**, required by the brief's academic integrity section. The README has a table with one row per person: **fill in your own row honestly** (which tools, used for what). Tyler's row is done.

**Demo plan:** use replays, not live traffic, so it can't fail on the network. Run each from the repo root with Telegram on:

| # | Show | Proves |
|---|---|---|
| 1 | `brute_force_logs.jsonl` → 2 alerts; tap Reset password on the critical one | graph path, C4 forces an account action, human in the loop, dry run |
| 2 | `dir_scan_logs.jsonl` → medium, Block IP not offered; tap Notify developer | C2, CSP explanation |
| 3 | Ctrl+C, run `dir_scan_logs.jsonl` again → "Known attacker", R4 → high → **Block IP offered** | **graph knowledge changes the recommendation** (Bianca 1) |
| 4 | `scan_then_sqli_logs.jsonl` → R2 + R3 → critical | attack-chain rules (Bianca 3) |
| 5 | `locust_logs.jsonl` → no alerts | no alert fatigue |
| 6 | `ALLOWLIST=10.0.0.60`, brute force again → Block IP not offered | C1 safety |

Before step 1, delete `data/feedback.jsonl`, so the demo starts with no known attackers.

**Q&A: everyone must be able to explain their own code.** The brief says failing to explain submitted work can count as insufficient authorship. Questions to expect:
- Why a CSP and not if-statements?
- Why no AC-3?
- Why forward chaining, not backward?
- Why is the LLM only allowed to phrase?
- What stops the LLM inventing a mitigation?
- What happens if the graph has no facts about an attack (open world)?
- How do you know the severity rules are right?
