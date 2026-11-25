"""
Detector: the single entry point for the rest of the pipeline.

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
import json
import logging
import os
from datetime import datetime, timedelta

from detection.events import DetectionEvent
from detection.rules import DEFAULT_THRESHOLD, GENERIC_RULES, SQLI_RULES, XSS_RULES, check_request
from detection.stateful import SlidingWindows
from parser import ParseError, parse_line, parse_ts

log = logging.getLogger(__name__)

SEVERITY = {"sqli": "high", "xss": "medium"}

# The four thresholds the feedback loop (feedback/tune_thresholds.py) may change.
# Must match DEFAULTS in feedback/tune_thresholds.py (tests/test_overrides.py checks this).
DETECTOR_DEFAULTS = {
    "sqli_threshold": DEFAULT_THRESHOLD,   # 0.7
    "bf_threshold": 5,
    "scan_sensitive": 5,
    "scan_distinct": 45,
}
_TYPES = {"sqli_threshold": float, "bf_threshold": int,
          "scan_sensitive": int, "scan_distinct": int}

# Safety limits applied when loading tuned thresholds. However far the feedback
# loop pushes a knob the detector never goes below its defaults or above these.
# sqli_threshold is capped at 0.9: standard sqlmap payloads such as
# "' AND 8975=9629--" score 0.928 so a higher threshold would start missing them.
SAFE_MAX = {
    "sqli_threshold": 0.9,
    "bf_threshold": 20,
    "scan_sensitive": 15,
    "scan_distinct": 120,
}

# Every rule_id the detector can put in an event. Any rule_id that
# feedback/tune_thresholds.py's RULE_TUNING refers to must be in here
# (tests/test_overrides.py checks this so renaming a rule can't silently break tuning).
ALL_RULE_IDS = (
    set(SQLI_RULES) | set(XSS_RULES) | set(GENERIC_RULES)
    | {"BF-LOGIN-401", "BF-SUCCESS-AFTER-FAIL",
       "SCAN-SENSITIVE-PATHS", "SCAN-DISTINCT-PATHS"}
)


class Detector:
    def __init__(self,
                 sqli_threshold: float = DETECTOR_DEFAULTS["sqli_threshold"],
                 bf_threshold: int = DETECTOR_DEFAULTS["bf_threshold"],
                 scan_sensitive: int = DETECTOR_DEFAULTS["scan_sensitive"],
                 scan_distinct: int = DETECTOR_DEFAULTS["scan_distinct"],
                 use_tool_ua: bool = False, cooldown_s: int = 300, window_s: int = 60):
        self.sqli_threshold = sqli_threshold
        self.use_tool_ua = use_tool_ua
        self.cooldown = timedelta(seconds=cooldown_s)
        self.windows = SlidingWindows(window_s=window_s, bf_threshold=bf_threshold,
                                      scan_sensitive=scan_sensitive,
                                      scan_distinct=scan_distinct, cooldown_s=cooldown_s)
        self.last_hit = {}       # (ip, attack_type) -> ts, cooldown for stateless rules
        self.flagged = {}        # _idx -> attack_type read by evaluate.py

    @classmethod
    def from_overrides(cls, path: str = None, **kwargs) -> "Detector":
        """Build a Detector with any thresholds the feedback loop has tuned.

        Reads threshold_overrides.json written by feedback/tune_thresholds.py.
        Missing file, broken JSON or unknown keys -> falls back to the defaults,
        so a bad overrides file can never stop the detector starting.
        Each value is kept between the default and SAFE_MAX, so the feedback
        loop can make the detector stricter but never blind.
        Explicit kwargs (e.g. use_tool_ua=True) win over the file.
        """
        settings = dict(DETECTOR_DEFAULTS)
        if path is None:
            try:
                from feedback.tune_thresholds import OVERRIDES_PATH
                path = OVERRIDES_PATH
            except ImportError:
                path = None

        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    loaded = json.load(f)
                for key, value in loaded.items():
                    if key not in _TYPES:
                        log.warning("ignoring unknown override %r in %s", key, path)
                        continue
                    value = _TYPES[key](value)
                    safe = min(max(value, DETECTOR_DEFAULTS[key]), SAFE_MAX[key])
                    if safe != value:
                        log.warning("override %s=%s outside safe range, using %s",
                                    key, value, safe)
                    settings[key] = round(safe, 4) if isinstance(safe, float) else safe
                log.info("loaded threshold overrides from %s: %s", path, settings)
            except (OSError, ValueError, TypeError, AttributeError) as exc:
                log.warning("could not read %s (%s); using defaults", path, exc)
                settings = dict(DETECTOR_DEFAULTS)

        settings.update(kwargs)
        return cls(**settings)

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

 