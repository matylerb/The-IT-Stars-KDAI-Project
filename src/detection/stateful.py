"""
Stateful detection rules: brute force and directory scanning.
 
These attacks are invisible in a single request; they show up as a PATTERN
from one IP over time. We keep a 60 second sliding window per IP, using the
log's own timestamps (not the wall clock) so replays give identical results.
 
Thresholds come from the data check on labelled_dataset.jsonl:
  brute force : attacker 16 failed logins in 5s   | benign max 1 failure
  dir scan    : attacker 66 distinct paths / 18 sensitive in 60s
                | benign max 34 distinct (real browser) / 0 sensitive
"""
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import NamedTuple, Optional
 
from detection.features import is_sensitive, is_static, normalise_path
 
LOGIN_PATH = "/rest/user/login"
 
 
class WindowHit(NamedTuple):
    attack_type: str            # "brute_force" or "dir_scan"
    severity: str
    confidence: float
    rule_ids: list
    records: list               # every request in the window that tripped
    is_new: bool                # True -> send an alert; False -> same incident, already alerted
    possible_compromise: bool = False
 
 
class SlidingWindows:
    def __init__(self, window_s: int = 60, bf_threshold: int = 5,
                 scan_sensitive: int = 5, scan_distinct: int = 45,
                 cooldown_s: int = 300):
        self.window = timedelta(seconds=window_s)
        self.cooldown = timedelta(seconds=cooldown_s)
        self.bf_threshold = bf_threshold
        self.scan_sensitive = scan_sensitive
        self.scan_distinct = scan_distinct
 
        self.login_fails = defaultdict(deque)   # ip -> deque[(ts, rec)]
        self.paths = defaultdict(deque)         # ip -> deque[(ts, norm_path, rec)]
        self.last_hit = {}                      # (ip, attack_type) -> ts of last hit
 
    # ---------- helpers ----------
    def _trim(self, dq: deque, now: datetime) -> None:
        while dq and now - dq[0][0] > self.window:
            dq.popleft()
 
    def _is_new(self, ip: str, attack_type: str, now: datetime) -> bool:
        """New incident unless this IP hit the same rule within the cooldown.
        Every hit refreshes the timer, so one long attack = one alert."""
        key = (ip, attack_type)
        prev = self.last_hit.get(key)
        self.last_hit[key] = now
        return prev is None or now - prev > self.cooldown
 
    # ---------- brute force ----------
    def check_brute_force(self, rec: dict, now: datetime) -> Optional[WindowHit]:
        if rec["method"] != "POST" or rec["path"] != LOGIN_PATH:
            return None
        ip = rec["ip"]
        dq = self.login_fails[ip]
        self._trim(dq, now)
 
        if rec["status"] == 401:
            dq.append((now, rec))
            if len(dq) >= self.bf_threshold:
                conf = min(0.99, 0.5 + 0.05 * len(dq))
                return WindowHit("brute_force", "high", conf, ["BF-LOGIN-401"],
                                 [r for _, r in dq], self._is_new(ip, "brute_force", now))
 
        elif 200 <= rec["status"] < 300 and len(dq) >= self.bf_threshold:
            # Successful login straight after a burst of failures: escalate
            # Always a new alert even inside the cooldown
            self._is_new(ip, "brute_force", now)
            return WindowHit("brute_force", "critical", 0.99,
                             ["BF-LOGIN-401", "BF-SUCCESS-AFTER-FAIL"],
                             [r for _, r in dq] + [rec], True, possible_compromise=True)
        return None
 
    # ---------- directory scan ----------
    def check_dir_scan(self, rec: dict, now: datetime) -> Optional[WindowHit]:
        if is_static(rec["path"]):
            return None
        ip = rec["ip"]
        dq = self.paths[ip]
        dq.append((now, normalise_path(rec["path"]), rec))
        self._trim(dq, now)
 
        distinct = {p for _, p, _ in dq}
        sensitive = sum(is_sensitive(p) for p in distinct)
 
        rules = []
        if sensitive >= self.scan_sensitive:
            rules.append("SCAN-SENSITIVE-PATHS")
        if len(distinct) >= self.scan_distinct:
            rules.append("SCAN-DISTINCT-PATHS")
        if not rules:
            return None
 
        conf = min(0.99, 0.5 + 0.05 * sensitive + 0.005 * len(distinct))
        return WindowHit("dir_scan", "medium", round(conf, 3), rules,
                         [r for _, _, r in dq], self._is_new(ip, "dir_scan", now))
 
    # ---------- entry point ----------
    def update(self, rec: dict, now: datetime) -> list:
        """Feed one request; returns 0-2 WindowHits."""
        hits = [self.check_brute_force(rec, now), self.check_dir_scan(rec, now)]
        return [h for h in hits if h is not None]
 
 
if __name__ == "__main__":
    # Run from repo root:  PYTHONPATH=src python -m detection.stateful
    from collections import Counter
    from parser import iter_events, parse_ts
 
    with open("data/labelled_dataset.jsonl") as f:
        records = list(iter_events(f))
    for i, r in enumerate(records):
        r["_idx"] = i
    records.sort(key=lambda r: (parse_ts(r["ts"]), r["_idx"]))
 
    sw = SlidingWindows()
    flagged = {}            # _idx -> attack_type
    alerts = []
    for rec in records:
        for hit in sw.update(rec, parse_ts(rec["ts"])):
            for r in hit.records:
                flagged[r["_idx"]] = hit.attack_type
            if hit.is_new:
                alerts.append((hit.attack_type, hit.severity, rec["ip"], rec["ts"],
                               hit.possible_compromise))
 
    counts = Counter((r["label"], flagged.get(r["_idx"], "-")) for r in records)
    print("(label, predicted): count")
    for k, n in sorted(counts.items()):
        print(f"  {k}: {n}")
    print(f"\nalerts sent: {len(alerts)}")
    for a in alerts:
        print("  ", a)
 