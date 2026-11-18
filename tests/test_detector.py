"""End-to-end tests: raw records in, DetectionEvents out."""
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
 
from detection.detector import Detector
 
T0 = datetime(2026, 11, 18, 0, 0, 0, tzinfo=timezone.utc)
 
 
def rec(ip, path, status=200, method="GET", query="", t=0.0, idx=None):
    r = {"ts": (T0 + timedelta(seconds=t)).isoformat(), "ip": ip, "method": method,
         "path": path, "query": query, "status": status, "user_agent": "x",
         "request_time": 0.01, "body": ""}
    if idx is not None:
        r["_idx"] = idx
    return r
 
 
def sqli(t, idx=None):
    return rec("10.0.0.80", "/rest/products/search",
               query="q=" + quote("test' AND 1=1--"), status=500, t=t, idx=idx)
 
 
def test_one_event_per_sqli_attack_but_every_request_flagged():
    det = Detector()
    events = []
    for i in range(20):
        events += det.process(sqli(t=i, idx=i))
    assert len(events) == 1
    assert events[0].attack_type == "sqli" and events[0].severity == "high"
    assert len(det.flagged) == 20
 
 
def test_new_event_after_cooldown():
    det = Detector(cooldown_s=300)
    assert det.process(sqli(t=0))
    assert det.process(sqli(t=100)) == []
    assert det.process(sqli(t=100 + 301))       # quiet > 5 min -> new incident
 
 
def test_brute_force_event_and_compromise():
    det = Detector()
    events = []
    for i in range(16):
        events += det.process(rec("10.0.0.60", "/rest/user/login", 401, "POST", t=i * 0.3, idx=i))
    events += det.process(rec("10.0.0.60", "/rest/user/login", 200, "POST", t=5, idx=16))
    types = [(e.attack_type, e.severity, e.possible_compromise) for e in events]
    assert types == [("brute_force", "high", False), ("brute_force", "critical", True)]
    assert len(det.flagged) == 17
    assert events[1].request_count == 17
 
 
def test_event_serialises_to_json():
    det = Detector()
    ev = det.process(sqli(t=0))[0]
    d = json.loads(ev.to_json())
    assert d["owasp"] == "A03:2021-Injection" and d["mitre"] == "T1190"
    assert "request_idx" not in d and "_idx" not in d["evidence"][0]
 
 
def test_benign_traffic_produces_nothing():
    det = Detector()
    for i in range(50):
        assert det.process(rec("10.1.0.5", f"/api/Products/{i}", t=i)) == []
        assert det.process(rec("10.1.0.5", "/rest/products/search",
                               query="q=apple", t=i + 0.5)) == []
 
 
def test_process_line_skips_bad_lines():
    det = Detector()
    assert det.process_line("not json") == []
    assert det.process_line("") == []
    assert det.process_line(json.dumps(sqli(t=0)))[0].attack_type == "sqli"
 