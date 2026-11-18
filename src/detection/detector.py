"""
Detector: the single entry point for the rest of the pipeline
 
    from detection.detector import Detector
    det = Detector()
    for line in tail("access.log"):
        for event in det.process_line(line):
            send(event.to_dict())
 
Each request goes through:
  1. stateless rules   (rules.py)    -> SQLi / XSS in this one request
  2. stateful windows  (stateful.py) -> brute force / dir scan from this IP over 60s
and comes out as 0+ DetectionEvents (events.py). One attack = one event:
repeat hits from the same IP within the cooldown are folded into the same
incident and not re-alerted.
"""
from datetime import datetime, timedelta
 
from detection.events import DetectionEvent
from detection.rules import DEFAULT_THRESHOLD, check_request
from detection.stateful import SlidingWindows
from parser import ParseError, parse_line, parse_ts
 
SEVERITY = {"sqli": "high", "xss": "medium"}
 
 
class Detector:
    def __init__(self, sqli_threshold: float = DEFAULT_THRESHOLD,
                 use_tool_ua: bool = False, cooldown_s: int = 300, **window_kwargs):
        self.sqli_threshold = sqli_threshold
        self.use_tool_ua = use_tool_ua
        self.cooldown = timedelta(seconds=cooldown_s)
        self.windows = SlidingWindows(cooldown_s=cooldown_s, **window_kwargs)
        self.last_hit = {}       # (ip, attack_type) -> ts cooldown for stateless rules
        self.flagged = {}        # _idx -> attack_type read by evaluate.py
 
    # ---------- helpers ----------
    def _is_new(self, ip: str, attack_type: str, now: datetime) -> bool:
        key = (ip, attack_type)
        prev = self.last_hit.get(key)
        self.last_hit[key] = now
        return prev is None or now - prev > self.cooldown
 
    def _flag(self, records: list, attack_type: str) -> None:
        for r in records:
            if "_idx" in r:
                self.flagged[r["_idx"]] = attack_type
 
    @staticmethod
    def _window(records: list):
        times = [parse_ts(r["ts"]) for r in records]
        return min(times), max(times)
 
    # ---------- main entry points ----------
    def process(self, rec: dict) -> list:
        """Feed one parsed log record; returns a list of NEW DetectionEvents."""
        now = parse_ts(rec["ts"])
        events = []
 
        # 1. stateless: SQLi / XSS in this single request
        hit = check_request(rec, threshold=self.sqli_threshold, use_tool_ua=self.use_tool_ua)
        if hit:
            self._flag([rec], hit.attack_type)
            if self._is_new(rec["ip"], hit.attack_type, now):
                events.append(DetectionEvent(
                    attack_type=hit.attack_type,
                    severity=SEVERITY[hit.attack_type],
                    confidence=hit.confidence,
                    src_ip=rec["ip"],
                    window_start=now,
                    window_end=now,
                    request_count=1,
                    rule_ids=hit.rule_ids,
                    evidence=[rec],
                    request_idx=[rec["_idx"]] if "_idx" in rec else [],
                ))
 
        # 2. stateful: brute force / dir scan over the IP's recent window
        for wh in self.windows.update(rec, now):
            self._flag(wh.records, wh.attack_type)
            if wh.is_new:
                start, end = self._window(wh.records)
                events.append(DetectionEvent(
                    attack_type=wh.attack_type,
                    severity=wh.severity,
                    confidence=wh.confidence,
                    src_ip=rec["ip"],
                    window_start=start,
                    window_end=end,
                    request_count=len(wh.records),
                    rule_ids=wh.rule_ids,
                    evidence=wh.records[-5:],          # most recent requests
                    possible_compromise=wh.possible_compromise,
                    request_idx=[r["_idx"] for r in wh.records if "_idx" in r],
                ))
        return events
 
    def process_line(self, line: str) -> list:
        """Convenience for the live pipeline: raw log line in, events out.
        Bad lines are skipped instead of crashing the agent."""
        try:
            rec = parse_line(line)
        except ParseError:
            return []
        return self.process(rec)
 
 
if __name__ == "__main__":
    # Run from repo root:  PYTHONPATH=src python -m detection.detector
    import json
    import sys
    from collections import Counter
    from parser import iter_events
 
    use_ua = "--ua" in sys.argv
    with open("data/labelled_dataset.jsonl") as f:
        records = list(iter_events(f))
    for i, r in enumerate(records):
        r["_idx"] = i
    records.sort(key=lambda r: (parse_ts(r["ts"]), r["_idx"]))
 
    det = Detector(use_tool_ua=use_ua)
    events = []
    for rec in records:
        label = rec.pop("label")          # never let the detector see the answer
        events.extend(det.process(rec))
        rec["label"] = label
 
    counts = Counter((r["label"], det.flagged.get(r["_idx"], "-")) for r in records)
    print(f"use_tool_ua={use_ua}\n(label, predicted): count")
    for k, n in sorted(counts.items()):
        print(f"  {k}: {n}")
    print(f"\nevents emitted: {len(events)}")
    for ev in events:
        print(f"  {ev.attack_type:12} {ev.severity:9} {ev.src_ip:12} "
              f"conf={ev.confidence} requests={ev.request_count} "
              f"compromise={ev.possible_compromise}")
    print("\nexample event:")
    print(json.dumps(events[0].to_dict(), indent=2) if events else "none")
 