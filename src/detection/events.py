
"""
Detection event schema.
 
Every detection the detector makes is returned as a DetectionEvent.
Knowledge Engineering (Ivan) and Agent/Integration (Tyler) consume
DetectionEvent.to_dict(), a plain JSON-ready dict.
"""
 
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
 
# OWASP top 10 and MITRE ATT&CK mappingfor each attack type
ATTACK_META = {
    "sqli": {
        "owasp": "A03:2021-Injection",
        "mitre": "T1190",          # Exploit Public Facing Application
    },
    "xss": {
        "owasp": "A03:2021-Injection",
        "mitre": "T1189",          # Drive by Compromise
    },
    "brute_force": {
        "owasp": "A07:2021-Identification and Authentication Failures",
        "mitre": "T1110.001",      # Brute Force: Password Guessing
    },
    "dir_scan": {
        "owasp": "A05:2021-Security Misconfiguration",
        "mitre": "T1595.003",      # Active Scanning: Wordlist Scanning
    },
}
 
SEVERITIES = ("low", "medium", "high", "critical")
 
# Fields from a log record that are safe and useful to show as evidence
EVIDENCE_FIELDS = ("ts", "method", "path", "query", "status")
MAX_EVIDENCE = 5
 
# Dataset label -> detector attack type (used by evaluate.py)
LABEL_TO_TYPE = {
    "sqli_attempt": "sqli",
    "brute_force": "brute_force",
    "dir_scan": "dir_scan",
}
 
@dataclass
 
class DetectionEvent:
    # --- required: the detector must fill these ---
    attack_type: str            # one of ATTACK_META keys
    severity: str               # low / medium / high / critical
    confidence: float           # 0.0 - 1.0
    src_ip: str
    window_start: datetime      # ts of first request in the window
    window_end: datetime        # ts of last request in the window
    request_count: int
 
    # --- optional / defaulted ---
    rule_ids: list = field(default_factory=list)       # e.g. ["SQLI-UNION"]
    evidence: list = field(default_factory=list)       # raw log records
    possible_compromise: bool = False                  # brute force then success
    request_idx: list = field(default_factory=list)    # _idx values, for evaluate.py only
    owasp: Optional[str] = None                        # auto filled from ATTACK_META
    mitre: Optional[str] = None                        # auto filled from ATTACK_META
 
    # --- auto-generated ---
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
 
    def __post_init__(self):
        if self.attack_type not in ATTACK_META:
            raise ValueError(f"unknown attack_type {self.attack_type!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be 0-1, got {self.confidence}")
        if self.window_end < self.window_start:
            raise ValueError("window_end is before window_start")
 
        meta = ATTACK_META[self.attack_type]
        self.owasp = self.owasp or meta["owasp"]
        self.mitre = self.mitre or meta["mitre"]
        self.confidence = round(float(self.confidence), 3)
 
    def to_dict(self) -> dict:
        """JSON-ready dict for Knowledge Engineering / Agent. Excludes request_idx."""
        evidence = [
            {k: rec[k] for k in EVIDENCE_FIELDS if k in rec}
            for rec in self.evidence[:MAX_EVIDENCE]
        ]
        return {
            "event_id": self.event_id,
            "detected_at": self.detected_at.isoformat(),
            "attack_type": self.attack_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "src_ip": self.src_ip,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "request_count": self.request_count,
            "rule_ids": list(self.rule_ids),
            "evidence": evidence,
            "possible_compromise": self.possible_compromise,
            "owasp": self.owasp,
            "mitre": self.mitre,
        }
 
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
 
if __name__ == "__main__":
    from datetime import timedelta
 
    t0 = datetime(2026, 11, 18, 0, 51, 28, tzinfo=timezone.utc)
    recs = [
        {"ts": "2026-11-18T00:51:28+00:00", "method": "POST",
         "path": "/rest/user/login", "query": "", "status": 401,
         "_idx": 711 + i, "label": "brute_force"}
        for i in range(7)
    ]
    ev = DetectionEvent(
        attack_type="brute_force",
        severity="high",
        confidence=0.9,
        src_ip="10.0.0.60",
        window_start=t0,
        window_end=t0 + timedelta(seconds=5),
        request_count=len(recs),
        rule_ids=["BF-LOGIN-401"],
        evidence=recs,
        request_idx=[r["_idx"] for r in recs],
    )
    print(json.dumps(ev.to_dict(), indent=2))
 
    # should raise
    try:
        DetectionEvent("ddos", "high", 0.9, "1.2.3.4", t0, t0, 1)
    except ValueError as e:
        print("validation works:", e)