# CSP response selector

**Owner:** Tyler
**For:** Cillian (rule engine input), Ivan (graph contract), anyone wiring the agent
**Status:** built and tested (`tests/test_csp.py`, `tests/test_response_selector.py`). Domains come from Ivan's knowledge graph. Severity comes from the detector until Cillian's rule engine is wired in.

This module answers one question for each incident: **which response actions is it safe to offer the human?** It models that as a constraint satisfaction problem (Lecture 5) and solves it with backtracking search. Its output is the set of one-tap actions shown in the Telegram alert, plus a record of why every other action was not offered.

It decides **what may be offered**, never what is done. A human approves every action.

---

## 1. Where it sits

```
detector ─► DetectionEvent ─► knowledge graph (Ivan) ─► action domains + proof paths ─┐
                         └──► rule engine (Cillian) ──► severity + rule trace ─────────┤
                                                                                        ▼
                                                    [response selector: this module]
                                                                                        │
                                       ResponsePlan: allowed actions, recommendation, reasons
                                                                                        ▼
                                                              LLM phrasing ─► Telegram buttons
```

| File | Contents | Depends on |
|---|---|---|
| `csp.py` | A general CSP solver. It contains no security knowledge. | standard library only |
| `selector.py` | The security response problem built on `csp.py`, the allowlist, and the output type. | `csp.py`, `knowledge.enrich` |

The two files are deliberately separate: `csp.py` is the algorithm, `selector.py` is the problem. This follows the AIMA principle from Lecture 1 of separating the problem definition from the solution method. `csp.py` could solve any other CSP, and the tests use it on Lecture 5's dinner-party, map-colouring and room-allocation examples.

---

## 2. Problem formulation (X, D, C)

### Variables (X)

| Variable | Meaning |
|---|---|
| `network` | what to do about the source IP |
| `account` | what to do about user accounts |
| `application` | what to change in the web application |
| `severity` | the incident's final severity, with a **single-value domain** |

`severity` is a variable rather than a plain parameter so that C2 is a genuine binary constraint between two variables. That way forward checking propagates over it, exactly as in the Lecture 5 examples.

### Domains (D)

`D(slot)` contains the actions the knowledge graph links to this attack for that slot, followed by `none`.

The selector reads `knowledge["action_domains"]` from `knowledge.enrich(event)`. The graph derives these through its rules K1–K4: each action is reachable from the attack through `mitigatedBy` and `implementedBy` links, and assigned to a slot by `actsOn`. Every action therefore arrives with a proof path, which the selector keeps as `provenance`.

| Attack | `network` | `account` | `application` |
|---|---|---|---|
| `brute_force` | `rate_limit_login`, `block_ip`, `none` | `reset_password`, `none` | `none` |
| `sqli` | `block_ip`, `none` | `none` | `notify_developer`, `none` |
| `dir_scan` | `block_ip`, `none` | `none` | `notify_developer`, `none` |
| `xss` | `none` | `none` | `notify_developer`, `none` |

Two properties of the domains:
- **List order is preference order.** It follows the graph's order and is used to break ties when choosing values. `none` always comes last.
- **Open-world assumption (Lecture 8).** If the graph has no action for a slot, that slot's domain is just `{none}`. An attack the graph doesn't know at all, e.g. `ddos`, gets `{none}` everywhere and the problem is unsatisfiable. Nothing is ever invented.

### Constraints (C)

| Id | Arity | Scope | Constraint | Purpose |
|---|---|---|---|---|
| C1 | unary | `network` | `network ≠ block_ip` if `src_ip` is allowlisted | never lock out our own addresses |
| C2 | binary | `network`, `severity` | `network = block_ip → severity ∈ {high, critical}` | proportional response |
| C3 | ternary* | `network`, `account`, `application` | at least one slot ≠ `none` | the goal test: always offer something |
| C4 | unary | `account` | `account ≠ none` if `possible_compromise` | a likely account takeover must be acted on |

\* The proposal calls C3 a global constraint. It involves all three slots, which here means three variables, so the code reports its arity as `ternary`.

Each constraint carries a plain-English `reason` written for the incident at hand. For example, C1 reads "10.0.0.60 is on your allowlist, so it is never blocked" when the IP is allowlisted, and "allowlisted IPs are never blocked (10.0.0.60 is not on the allowlist)" when it isn't. These reasons go straight into the alert and the LLM prompt, so they never state anything false about the incident.

---

## 3. Algorithm (`csp.py`)

`BacktrackingSolver` implements the full Lecture 5 pipeline:

```
node consistency (unary constraints, before search)
   ↓
choose variable:  MRV (fewest remaining values), Degree breaks ties
   ↓
order values:     LCV (fewest neighbour values removed); ties keep graph order
   ↓
assign, then forward check: prune neighbours that are the last unassigned
variable of some constraint; an empty domain means backtrack immediately
   ↓
on backtrack: restore every value pruned by the abandoned assignment
```

| Step | Method | Notes |
|---|---|---|
| Node consistency | `_node_consistency` | Applies C1 and C4 before the search starts. |
| Variable ordering | `select_unassigned_variable` | `min` over (domain size, −unassigned degree). Remaining ties keep the declared order. |
| Value ordering | `order_domain_values`, `impact` | Impact = number of neighbour values ruled out. Uses a stable sort, so equal impact keeps the graph's preference order. |
| Inference | `_forward_check` | Classic forward checking for binary constraints. For C3 it acts once two of the three slots are assigned. |
| Restoration | `_restore` | Puts pruned values back in their original position. This is the restoration point from Lecture 5's MAC slide, and a dedicated test fails without it. |
| Search | `solve`, `_backtrack` | `find_all=True` enumerates every solution. |

**Why every solution is enumerated:** the buttons are the union of the actions used by any solution, so the selector needs all of them, not just the first. The space is tiny: with the current graph, at most 6 complete assignments (brute force: 3 × 2 × 1). `enumerate_solutions()` is the generate-and-test baseline ("naive search: try everything") that the tests compare against.

**Search behaviour on the recorded attacks:** 4–9 nodes and **0 backtracks**. Forward checking removes every dead end before the search walks into it.

**Complexity:** general finite-domain CSP satisfiability is NP-complete (Lecture 5). This instance has 4 variables with domains of at most 3 values, and its constraint graph is nearly a tree, so its cost is negligible. The CSP is used for its declarative, explainable constraints, not for speed. See §9.

---

## 4. Input

`select_response(incident, allowlist=None)` takes one incident dict. Build it with `make_incident()`:

```python
from response.selector import make_incident, select_response

incident = make_incident(event)               # event = DetectionEvent.to_dict()
# == {"event": event,
#     "severity": event["severity"],            # override with the rule engine's result
#     "trace": [],                              # rule engine proof trace
#     "knowledge": knowledge.enrich(event)}     # Ivan's graph

incident = make_incident(event, severity=final_sev, trace=rule_trace)   # once Cillian's engine is wired in
plan = select_response(incident)
```

| Field used | Source | Used for |
|---|---|---|
| `event.src_ip` | detector | C1 |
| `event.possible_compromise` | detector | C4 |
| `severity` (else `event.severity`) | rule engine (else detector) | C2, `severity` domain |
| `knowledge.action_domains` | knowledge graph | slot domains, labels, provenance |

**Allowlist:** if no allowlist is passed, it's read from the `ALLOWLIST` environment variable. This is a comma-separated list of IPs or CIDR ranges, e.g. `ALLOWLIST=10.0.0.1,192.168.1.0/24`. Use `parse_allowlist()` to build one in code. Invalid IP strings are never treated as allowlisted.

**Robustness:**
- Actions listed under an unknown slot, or under a slot that doesn't match their own `slot` field, are ignored.
- An unknown severity raises `ValueError`.
- A missing `knowledge` block behaves like an unknown attack and gives `unsatisfiable`.

---

## 5. Output: `ResponsePlan`

| Field | Meaning |
|---|---|
| `status` | `"ok"`, or `"unsatisfiable"` when no combination satisfies every constraint |
| `severity` | the severity the constraints were checked against |
| `recommended` | the first solution found (MRV + LCV + graph order): slot → action, may contain `none` |
| `allowed_actions` | every non-`none` action that appears in **at least one** solution. **These become the Telegram buttons.** |
| `options` | slot → the values used by some solution |
| `removed` | actions in the initial domain that appear in no solution, each with the constraint id and reason that removed it |
| `required` | slots where `none` was ruled out, i.e. an action is mandatory, with the constraint that forced it |
| `initial_domains` | slot domains before any pruning |
| `action_labels` | action id → human label from the graph |
| `provenance` | action id → the graph triples that justify it |
| `constraints` | id, arity, scope and incident-specific reason of every constraint |
| `solutions_count`, `stats` | number of solutions; search nodes and backtracks |

`plan.to_dict()` is JSON-ready. `plan.explanation_lines()` gives the plain-text trace used by the console output and, later, the template alert.

### Example: brute force followed by a successful login, from an allowlisted IP

Real output, from `data/brute_force_logs.jsonl` with `ALLOWLIST=10.0.0.60`, shortened:

```json
{
  "status": "ok",
  "severity": "critical",
  "recommended": {"network": "rate_limit_login", "account": "reset_password", "application": "none"},
  "allowed_actions": ["rate_limit_login", "reset_password"],
  "removed":  [{"action": "block_ip", "slot": "network", "constraint": "C1",
                "reason": "10.0.0.60 is on your allowlist, so it is never blocked"}],
  "required": [{"action": "none", "slot": "account", "constraint": "C4",
                "reason": "a login succeeded right after a password-guessing burst, so an account action is required"}],
  "initial_domains": {"network": ["rate_limit_login", "block_ip", "none"],
                      "account": ["reset_password", "none"], "application": ["none"]},
  "provenance": {"reset_password": ["(brute_force, mapsTo, T1110.001)",
                                    "(T1110.001, subTechniqueOf, T1110)",
                                    "(T1110, mitigatedBy, credential_reset)",
                                    "(credential_reset, implementedBy, reset_password)"]},
  "solutions_count": 2,
  "search": {"nodes": 5, "backtracks": 0}
}
```

The same plan as `explanation_lines()`:
```
Recommended: network: Rate-limit logins; account: Reset password
Allowed: Rate-limit logins, Reset password
Required: an account action (C4: a login succeeded right after a password-guessing burst, so an account action is required)
Not offered: Block IP (C1: 10.0.0.60 is on your allowlist, so it is never blocked)
```

This gives the full chain proposal §7 asks for: **evidence → rule → severity → constraint → action**. The detector supplies the evidence and rule ids, the rule engine the severity, and this module the constraint and action links, with the graph's proof path behind each action.

---

## 6. Results on the recorded attacks

| Replay | Severity | Buttons offered | Removed / required |
|---|---|---|---|
| `brute_force_logs.jsonl`, first event | high | Rate-limit logins, Block IP, Reset password | none |
| `brute_force_logs.jsonl`, escalation | critical | Rate-limit logins, Block IP, Reset password | account action required (C4) |
| `dir_scan_logs.jsonl` | medium | Notify developer | Block IP removed (C2); application action then required (C3) |
| `sqlmap_logs.jsonl` | high | Block IP, Notify developer | none |
| `brute_force_logs.jsonl`, allowlisted | high / critical | Rate-limit logins, Reset password | Block IP removed (C1) |
| `locust_logs.jsonl` (benign) | none | no incident | |

The directory scan shows constraint propagation working across constraints. Once C2 removes `block_ip`, the network and account slots can only be `none`, so forward checking on C3 removes `none` from the application slot and "Notify developer" becomes mandatory.

---

## 7. Running it

```powershell
$env:PYTHONPATH="src"
python -m response.selector data/brute_force_logs.jsonl
python -m response.selector data/brute_force_logs.jsonl --allow 10.0.0.60
python -m response.selector data/dir_scan_logs.jsonl
python -m pytest -q tests/test_csp.py tests/test_response_selector.py
```

The demo runs a recorded log through the real `Detector` and knowledge graph, then prints each incident's explanation lines and search statistics.

---

## 8. Tests

### `tests/test_csp.py`: the solver
- Lecture 5 examples: the dinner party (all constraint arities), a map-colouring triangle (6 solutions), and an unsatisfiable all-different problem with two values.
- MRV, Degree tie-break and LCV impact, each checked against the lecture's own worked numbers.
- Restoration of pruned values on backtrack. The problem is built so that the only solution needs a value pruned in an abandoned branch.
- **Soundness and completeness:** on 40 random CSPs, under all 8 on/off combinations of MRV, LCV and forward checking, the solver returns exactly the same set of solutions as generate-and-test.

### `tests/test_response_selector.py`: the security problem, using the real graph
- Each constraint: C1 (exact IP and CIDR ranges), C2 (low and medium), C3 (over every scenario), C4 (required, and unsatisfiable when the graph offers no account action).
- **Grounding:** across every attack × severity × compromise × allowlist combination, each offered action has a proof from `KnowledgeGraph.justify()`.
- **Consistency:** `allowed_actions` equals the union over brute-force enumeration, and `recommended` is a valid solution.
- Open world: an unknown attack and missing knowledge both give `unsatisfiable`, without crashing.
- Unknown or mismatched slots are ignored, and an invalid severity is rejected.
- Constraint reasons are true for the incident at hand.
- Real replays of the brute-force, directory-scan and sqlmap logs, including an allowlisted run.

---

## 9. Design decisions

| Decision | Reason |
|---|---|
| A CSP rather than if-statements | The constraints are declarative data with ids and reasons, every pruning is recorded and explainable, and adding a slot or constraint needs no change to the solver. |
| Severity as a single-valued variable | Turns "block only at high severity" into a real binary constraint that forward checking propagates over, instead of a hidden `if`. |
| `none` in every domain | Doing nothing on one layer is a legitimate choice. C3 stops all three slots being `none`. |
| Enumerate all solutions | The buttons are the union of the actions used by any solution. The space has at most 6 assignments with the current graph. |
| Recommendation = first solution found | It's deterministic and follows MRV, LCV and the graph's preference order. Changing the order of lines in `data/kg/facts.csv` changes the recommendation without code changes. |
| Unsatisfiable is a valid result | The alert still goes out, saying "no safe automatic action, keep monitoring", with only the Ignore options. |
| Domains come only from the graph | The selector can't offer an action the graph doesn't support (open-world assumption). |

## 10. Limitations

- **Hard constraints only.** Every constraint is all-or-nothing. A ranking such as "prefer blocking at critical" would need soft or weighted constraints (a constraint optimisation problem). The recommendation is the first solution, not an optimal one.
- **Brittle thresholds (Lecture 8).** C2 switches at the medium/high boundary. A medium incident one rule short of high gets no blocking option.
- **Severity is the detector's** until the rule engine is integrated, so chain escalation (R2/R3) isn't yet reflected.
- **Small action set.** The graph currently has 4 actions, so most slots have one or two values. The CSP's strengths show more as the graph grows.
- **Explainable is not the same as correct (Lecture 8).** The trace explains faithfully what the constraints did, but if a constraint or a graph fact is wrong, the explanation is just as clear and just as wrong.
