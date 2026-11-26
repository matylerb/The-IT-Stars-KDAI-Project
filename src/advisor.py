"""
LLM advisor (Tyler): turns an incident and its CSP plan into a plain-English alert.

The LLM only phrases the alert (Lecture 8, hybrid AI). It is given the facts and
the approved actions, nothing else, and its answer is checked against those
facts. If there is no API key, the call fails, or the check finds a problem,
a simple template built from the same facts is used instead.

The attacker's requests (evidence) are never sent to the LLM, so text hidden
in them cannot instruct it.

    from advisor import advise
    alert = advise(incident, plan)   # {"what_happened", "how_serious", "actions", "why", "source"}

Demo, from the repo root:  PYTHONPATH=src python src/advisor.py data/brute_force_logs.jsonl
"""
import json
import os
import re
import urllib.request

from knowledge.enrich import get_graph

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-oss-120b"

PROMPT = """You write security alerts for a small business owner who is not a security expert.
Use ONLY the facts below. Do not add attack techniques, IP addresses, severity levels or actions that are not in the facts.
State the severity exactly as given. Nothing has been done yet: a person will decide.
Reply with JSON only, in this shape:
{"what_happened": "...", "how_serious": "...", "actions": {"<action id>": "<one short sentence>"}}
what_happened: one or two plain sentences, including the source IP and how many requests.
how_serious: one or two sentences that give the severity and explain why, using "why" from the facts.
The actions must be exactly the action ids in the facts; say what each one would do.

Facts:
"""


def build_facts(incident, plan):
    """The only information the alert may use."""
    event = incident["event"]
    knowledge = incident["knowledge"]
    attack = knowledge.get("attack", {})
    why = [str(step) for step in incident.get("trace") or []]   # rule engine's proof trace
    if not why:                                                  # no rule engine: detector's rules
        why = list(event["rule_ids"])
        if event.get("possible_compromise"):
            why.append("a login succeeded right after the failed attempts")
    if knowledge.get("known_attacker"):
        why.append(known_attacker_text(event["src_ip"], knowledge["known_attacker"]))
    return {
        "attack": attack.get("label", event["attack_type"]),
        "description": attack.get("description"),
        "source_ip": event["src_ip"],
        "request_count": event["request_count"],
        "severity": plan.severity,
        "why": why,
        "technique": (attack.get("technique") or {}).get("id"),
        "owasp": (attack.get("weakness") or {}).get("id"),
        "actions": {a: plan.action_labels[a] for a in plan.allowed_actions},
        "not_offered": [r.reason for r in plan.removed],
    }


def known_attacker_text(ip, attacks):
    return f"a person already confirmed {ip} as an attacker ({', '.join(attacks)})"


# --- "Why these actions": built from the graph and the CSP, never by the LLM ----

HOP = {"mapsTo": "ATT&CK", "classifiedAs": "OWASP", "subTechniqueOf": "part of",
       "mitigatedBy": "mitigated by"}


def graph_path(path, label):
    """Graph triples -> 'Brute-force login → ATT&CK T1110.001 → part of T1110 → mitigated by Limit failed logins'."""
    triples = [t.strip("()").split(", ", 2) for t in path]
    parts = [label(triples[0][0])]
    for _, relation, obj in triples:
        if relation == "implementedBy":          # the action itself, already named
            continue
        parts.append(f"{HOP.get(relation, relation)} {label(obj) if relation == 'mitigatedBy' else obj}")
    return " → ".join(parts)


def why_lines(incident, plan, label=None):
    """Why each action is offered (graph path) or not (CSP constraint). Always shown."""
    label = label or get_graph().label
    lines = []
    for action in plan.allowed_actions:
        if plan.provenance.get(action):
            lines.append(f"{label(action)}: {graph_path(plan.provenance[action], label)}")
    for r in plan.required:
        lines.append(f"Must include an {r.slot} action ({r.constraint}: {r.reason})")
    for r in plan.removed:
        lines.append(f"Not offered: {label(r.action)} ({r.constraint or 'no valid combination'}: {r.reason})")
    if plan.status != "ok":
        lines.append(plan.explanation_lines()[0])
    known = incident["knowledge"].get("known_attacker")
    if known:
        lines.append("Known attacker: " + known_attacker_text(incident["event"]["src_ip"], known))
    return lines


def ask_llm(facts):
    """Ask Groq to phrase the facts. Returns the reply text, or None if unavailable."""
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        return None
    body = json.dumps({
        "model": os.environ.get("LLM_MODEL") or DEFAULT_MODEL,   # empty counts as unset
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "user", "content": PROMPT + json.dumps(facts, indent=2)}],
    }).encode()
    req = urllib.request.Request(GROQ_URL, data=body, headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "User-Agent": "kdai-incident-advisor",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.load(resp)["choices"][0]["message"]["content"]
    except Exception:          # no network, timeout, bad key, odd reply: use the template
        return None


def check(answer, facts):
    """Grounding check: list of problems with the LLM's answer (empty = OK)."""
    if not isinstance(answer, dict):
        return ["answer is not a JSON object"]
    problems = []
    if not isinstance(answer.get("actions"), dict) or set(answer["actions"]) != set(facts["actions"]):
        problems.append("actions are not exactly the approved actions")
    text, allowed = json.dumps(answer), json.dumps(facts)
    patterns = (r"\bT\d{4}(?:\.\d{3})?\b",            # ATT&CK technique
                r"\bA\d{2}:20\d{2}\b",                 # OWASP category
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b")        # IP address
    for pattern in patterns:
        for found in re.findall(pattern, text):
            if found not in allowed:
                problems.append(f"{found} is not in the facts")
    if facts["severity"] not in str(answer.get("how_serious", "")).lower():
        problems.append(f"does not state the severity ({facts['severity']})")
    return problems


def template(facts):
    """Fallback alert built only from the facts."""
    serious = f"Severity: {facts['severity']}. Why: {', '.join(facts['why'])}."
    if facts["technique"]:
        serious += f" This matches MITRE ATT&CK {facts['technique']} and OWASP {facts['owasp']}."
    if not facts["actions"]:
        serious += " No safe automatic action is available, so keep monitoring."
    return {
        "what_happened": f"{facts['attack']} from {facts['source_ip']} "
                         f"({facts['request_count']} requests). {facts['description'] or ''}".strip(),
        "how_serious": serious,
        "actions": dict(facts["actions"]),
    }


def advise(incident, plan, llm=ask_llm):
    """Alert for one incident: the LLM's wording if it passes the check, else the template.
    "why" is always added from the graph and the CSP, whoever wrote the rest."""
    facts = build_facts(incident, plan)
    why = why_lines(incident, plan)
    reply = llm(facts)
    if reply:
        try:
            answer = json.loads(reply)
        except ValueError:
            answer = None
        if not check(answer, facts):
            return {**answer, "why": why, "source": "llm"}
    return {**template(facts), "why": why, "source": "template"}


if __name__ == "__main__":
    import sys

    from detection.detector import Detector
    from response.selector import make_incident, select_response

    det = Detector()
    for line in open(sys.argv[1]):
        for ev in det.process_line(line):
            incident = make_incident(ev.to_dict())
            alert = advise(incident, select_response(incident))
            print(json.dumps(alert, indent=2))
