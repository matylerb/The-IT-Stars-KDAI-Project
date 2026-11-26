"""
LLM advisor (Tyler): turns an incident and its CSP plan into a plain-English alert.

The LLM only phrases the alert (Lecture 8, hybrid AI). It is given the facts and
the approved actions, nothing else, and its answer is checked against those
facts. If there is no API key, the call fails, or the check finds a problem,
a simple template built from the same facts is used instead.

The attacker's requests (evidence) are never sent to the LLM, so text hidden
in them cannot instruct it.

    from advisor import advise
    alert = advise(incident, plan)   # {"what_happened", "how_serious", "actions", "source"}

Demo, from the repo root:  PYTHONPATH=src python src/advisor.py data/brute_force_logs.jsonl
"""
import json
import os
import re
import urllib.request

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = os.environ.get("LLM_MODEL", "llama-3.3-70b-versatile")

PROMPT = """You write security alerts for a small business owner who is not a security expert.
Use ONLY the facts below. Do not add attack techniques, IP addresses, severity levels or actions that are not in the facts.
State the severity exactly as given. Nothing has been done yet: a person will decide.
Reply with JSON only, in this shape:
{"what_happened": "...", "how_serious": "...", "actions": {"<action id>": "<one short sentence>"}}
The actions must be exactly the action ids in the facts.

Facts:
"""


def build_facts(incident, plan):
    """The only information the alert may use."""
    event = incident["event"]
    attack = incident["knowledge"].get("attack", {})
    why = list(event["rule_ids"])
    if event.get("possible_compromise"):
        why.append("a login succeeded right after the failed attempts")
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


def ask_llm(facts):
    """Ask Groq to phrase the facts. Returns the reply text, or None if unavailable."""
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        return None
    body = json.dumps({
        "model": MODEL,
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
    for reason in facts["not_offered"]:
        serious += f" Not offered: {reason}."
    if not facts["actions"]:
        serious += " No safe automatic action is available, so keep monitoring."
    return {
        "what_happened": f"{facts['attack']} from {facts['source_ip']} "
                         f"({facts['request_count']} requests). {facts['description'] or ''}".strip(),
        "how_serious": serious,
        "actions": dict(facts["actions"]),
    }


def advise(incident, plan, llm=ask_llm):
    """Alert for one incident: the LLM's wording if it passes the check, else the template."""
    facts = build_facts(incident, plan)
    reply = llm(facts)
    if reply:
        try:
            answer = json.loads(reply)
        except ValueError:
            answer = None
        if not check(answer, facts):
            return {**answer, "source": "llm"}
    return {**template(facts), "source": "template"}


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
