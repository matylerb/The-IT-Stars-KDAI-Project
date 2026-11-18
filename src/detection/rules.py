"""
Stateless detection rules (SQL injection and XSS).
 
Each rule is a regex with a weight (how suspicious a match is on its own).
Weights for one request are combined with noisy-OR:
    confidence = 1 - (1 - w1) * (1 - w2) * ...
so one weak signal stays below the threshold but several together cross it.
"""
import math
import re
from typing import NamedTuple, Optional
 
from detection.features import query_values
 
# --- SQL injection rules (run on decoded query VALUES) ---
SQLI_RULES = {
    "SQLI-UNION":       (re.compile(r"(?i)\bunion\b[\s\S]{0,40}\bselect\b"), 0.9),
    "SQLI-STACKED":     (re.compile(r"(?i);\s*(?:select|drop|insert|update|delete|exec)\b"), 0.9),
    "SQLI-TIME":        (re.compile(r"(?i)\b(?:sleep|benchmark|pg_sleep|randomblob|waitfor\s+delay)\s*\("), 0.9),
    "SQLI-META":        (re.compile(r"(?i)\b(?:sqlite_master|information_schema|sys\.tables)\b"), 0.95),
    "SQLI-DML":         (re.compile(r"(?i)\b(?:select|insert|update|delete|drop)\b[\s\S]{0,60}\b(?:from|into|table|set)\b"), 0.8),
    "SQLI-QUOTE-KW":    (re.compile(r"(?i)['\"]\)*\s*(?:and|or|union|select|order|having)\b"), 0.7),
    "SQLI-TAUTOLOGY":   (re.compile(r"(?i)\b(?:and|or)\b\s*\(*\s*['\"]?\w+['\"]?\s*=\s*['\"]?\w+"), 0.6),
    "SQLI-ORDER-BY":    (re.compile(r"(?i)\border\s+by\s+\d+"), 0.7),
    "SQLI-CASE-WHEN":   (re.compile(r"(?i)\bcase\s+when\b"), 0.7),
    "SQLI-FUNC":        (re.compile(r"(?i)\b(?:char|hex|cast|substr|substring|unicode|length)\s*\("), 0.5),
    "SQLI-COMMENT":     (re.compile(r"(?:--|/\*|\*/)"), 0.4),
    "SQLI-QUOTE-PAREN": (re.compile(r"['\"]\s*\)"), 0.4),
}
 
# --- XSS rules (query values only: request bodies are not logged) ---
XSS_RULES = {
    "XSS-SCRIPT":  (re.compile(r"(?i)<\s*/?\s*script\b"), 0.9),
    "XSS-HANDLER": (re.compile(r"(?i)\bon(?:error|load|mouseover|focus|click)\s*="), 0.8),
    "XSS-JS-URI":  (re.compile(r"(?i)javascript\s*:"), 0.8),
    "XSS-TAG":     (re.compile(r"(?i)<\s*(?:iframe|img|svg|body|object|embed)\b"), 0.6),
}
 
INJECTION_CHARS = re.compile(r"['\"()<>]")
TOOL_UA = re.compile(r"(?i)sqlmap|nikto|nmap|gobuster|dirbuster|wfuzz|hydra|masscan")
 
DEFAULT_THRESHOLD = 0.7
# Supporting signals: they add confidence but don't say WHICH injection it is.
GENERIC_RULES = {"SQLI-CHAR-DENSITY", "SQLI-SERVER-ERROR", "TOOL-UA"}
 
 
class RuleHit(NamedTuple):
    attack_type: str      # "sqli" or "xss"
    confidence: float
    rule_ids: list
 
 
def _noisy_or(weights) -> float:
    return 1 - math.prod(1 - w for w in weights)
 
 
def _match(text: str, rules: dict) -> list:
    return [(rid, w) for rid, (rx, w) in rules.items() if rx.search(text)]
 
 
def check_request(rec: dict, threshold: float = DEFAULT_THRESHOLD,
                  use_tool_ua: bool = False) -> Optional[RuleHit]:
    """Return a RuleHit if this single request looks like SQLi or XSS, else None."""
    values = query_values(rec.get("query", ""))
    if not values:
        return None
 
    sqli = _match(values, SQLI_RULES)
    if len(INJECTION_CHARS.findall(values)) >= 4:
        sqli.append(("SQLI-CHAR-DENSITY", 0.5))
    if rec.get("status", 0) >= 500:
        sqli.append(("SQLI-SERVER-ERROR", 0.5))
    if use_tool_ua and TOOL_UA.search(rec.get("user_agent", "")):
        sqli.append(("TOOL-UA", 0.95))
    xss = _match(values, XSS_RULES)
 
    sqli_conf = _noisy_or(w for _, w in sqli)
    xss_conf = _noisy_or(w for _, w in xss)
    sqli_specific = any(rid not in GENERIC_RULES for rid, _ in sqli)
 
    # SQLi wins if a real SQL rule fired; generic signals alone defer to XSS.
    if sqli_conf >= threshold and (sqli_specific or xss_conf < threshold):
        return RuleHit("sqli", round(sqli_conf, 3), [r for r, _ in sqli])
    if xss_conf >= threshold:
        return RuleHit("xss", round(xss_conf, 3), [r for r, _ in xss])
    return None
 
 
if __name__ == "__main__":
    # Quick look at how the stateless rules do on the labelled dataset
    from collections import Counter
    from parser import iter_events
 
    with open("data/labelled_dataset.jsonl") as f:
        records = list(iter_events(f))
 
    for use_ua in (False, True):
        counts = Counter()
        for rec in records:
            hit = check_request(rec, use_tool_ua=use_ua)
            counts[(rec["label"], hit.attack_type if hit else "-")] += 1
        print(f"\n=== use_tool_ua={use_ua} ===  (label, predicted): count")
        for key, n in sorted(counts.items()):
            print(f"  {key}: {n}")
 