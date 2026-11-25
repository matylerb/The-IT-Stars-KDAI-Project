"""
TEMPORARY stand-in for Ivan's knowledge graph and Cillian's rule engine.

Delete this module once `kg` and the rule engine exist. It only exists so the
CSP response selector can be built and tested against the agreed incident
contract before those components land. Nothing here is used at runtime once
the real components are wired in.

It mirrors the triples the graph is expected to hold:
    (technique, mitigatedBy, mitigation)
    (mitigation, implementedBy, action)
    (action, actsOn, slot)
"""
from __future__ import annotations

ACTIONS = {
    "block_ip":                 {"slot": "network",     "label": "Block this IP address"},
    "rate_limit_ip":            {"slot": "network",     "label": "Slow down requests from this IP"},
    "reset_password":           {"slot": "account",     "label": "Reset the targeted account's password"},
    "lock_account":             {"slot": "account",     "label": "Temporarily lock the targeted account"},
    "rate_limit_login":         {"slot": "application", "label": "Limit login attempts on the login page"},
    "restrict_sensitive_paths": {"slot": "application", "label": "Hide sensitive files and folders"},
    "review_input_validation":  {"slot": "application", "label": "Fix input checking on the affected page"},
}

MITIGATIONS = {
    "block_source":         {"label": "Block or throttle the source", "actions": ["block_ip", "rate_limit_ip"]},
    "account_lockout":      {"label": "Account lockout",              "actions": ["rate_limit_login", "lock_account"]},
    "credential_reset":     {"label": "Credential reset",             "actions": ["reset_password"]},
    "input_validation":     {"label": "Input validation",             "actions": ["review_input_validation"]},
    "hide_sensitive_paths": {"label": "Restrict sensitive paths",     "actions": ["restrict_sensitive_paths"]},
}

TECHNIQUES = {
    "T1110.001": {"label": "Brute Force: Password Guessing",
                  "mitigatedBy": ["block_source", "account_lockout", "credential_reset"]},
    "T1190":     {"label": "Exploit Public-Facing Application",
                  "mitigatedBy": ["block_source", "input_validation"]},
    "T1189":     {"label": "Drive-by Compromise",
                  "mitigatedBy": ["block_source", "input_validation"]},
    "T1595.003": {"label": "Active Scanning: Wordlist Scanning",
                  "mitigatedBy": ["block_source", "hide_sensitive_paths"]},
}


def mitigations_for(technique_id: str) -> list:
    """Mitigations in the incident-contract shape, actions carrying their slot."""
    tech = TECHNIQUES.get(technique_id)
    if tech is None:
        return []          # open world: unknown, not "no mitigation exists"
    out = []
    for mid in tech["mitigatedBy"]:
        m = MITIGATIONS[mid]
        out.append({
            "id": mid,
            "label": m["label"],
            "actions": [{"id": a, **ACTIONS[a]} for a in m["actions"]],
        })
    return out


def stub_incident(event: dict) -> dict:
    """Build an incident (agreed contract) from a DetectionEvent dict.

    Severity is the detector's own; the trace is a one-line placeholder until
    the rule engine provides the real proof trace.
    """
    tech_id = event.get("mitre")
    owasp = event.get("owasp") or ""
    weakness_id, _, weakness_label = owasp.partition("-")
    return {
        "event": event,
        "severity": event["severity"],
        "trace": [{"rule": "DETECTOR", "if": list(event.get("rule_ids", [])),
                   "then": f"severity({event['event_id'][:8]}, {event['severity']})"}],
        "technique": {"id": tech_id, "label": TECHNIQUES.get(tech_id, {}).get("label", "")},
        "weakness": {"id": weakness_id, "label": weakness_label},
        "mitigations": mitigations_for(tech_id),
    }
