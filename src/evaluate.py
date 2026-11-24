"""
Evaluation runner (Illya).

Replays the labelled dataset through the real detector and measures the three
numbers the proposal commits to:

  recall             >= 90%   - of all attack requests, how many did we flag?
  false-positive rate <= 5%   - of all benign requests, how many did we flag?
  alert latency       < 30s   - from the first request of an attack window to
                                the DetectionEvent being emitted.

Method (matches the detector's own __main__ so numbers are comparable):
  * load labelled_dataset.jsonl
  * give every record a stable _idx and sort by timestamp
  * feed each record to the detector WITHOUT its label (never cheat)
  * compare the detector's per-request flag (det.flagged) to the ground-truth
    label for recall / FPR, and use emitted events for latency.

Per-request scoring rather than per-incident keeps it simple and strict: a
request labelled as an attack that the detector never flagged is a miss.

Run it:
    PYTHONPATH=src python -m evaluate
    PYTHONPATH=src python -m evaluate --data data/labelled_dataset.jsonl --ua
"""
import argparse
import json
from collections import defaultdict

from detection.detector import Detector
from detection.events import LABEL_TO_TYPE
from parser import iter_events, parse_ts

TARGET_RECALL = 0.90
TARGET_FPR = 0.05
TARGET_LATENCY_S = 30.0

ATTACK_LABELS = set(LABEL_TO_TYPE)        # sqli_attempt, brute_force, dir_scan


def load_records(path: str) -> list:
    with open(path) as f:
        records = list(iter_events(f))
    for i, r in enumerate(records):
        r["_idx"] = i
    records.sort(key=lambda r: (parse_ts(r["ts"]), r["_idx"]))
    return records


def evaluate(path: str, use_tool_ua: bool = False) -> dict:
    records = load_records(path)
    det = Detector(use_tool_ua=use_tool_ua)

    events = []
    for rec in records:
        label = rec.pop("label", None)          # hide the answer from the detector
        events.extend(det.process(rec))
        if label is not None:
            rec["label"] = label

    # ---- recall / false-positive rate, per request ----
    attack_total = attack_hit = benign_total = benign_flagged = 0
    for r in records:
        label = r.get("label", "benign")
        flagged = r["_idx"] in det.flagged
        if label in ATTACK_LABELS:
            attack_total += 1
            if flagged:
                attack_hit += 1
        else:
            benign_total += 1
            if flagged:
                benign_flagged += 1

    recall = attack_hit / attack_total if attack_total else 0.0
    fpr = benign_flagged / benign_total if benign_total else 0.0

    # ---- per-attack-type recall ----
    by_type = defaultdict(lambda: [0, 0])      # label -> [hit, total]
    for r in records:
        label = r.get("label", "benign")
        if label in ATTACK_LABELS:
            by_type[label][1] += 1
            if r["_idx"] in det.flagged:
                by_type[label][0] += 1

    # ---- alert latency, measured inside the log's own timeline ----
    # In a replay, detected_at is today's wall clock while the window times are
    # from when the data was recorded, so detected_at - window_start is
    # meaningless. The honest replay latency is how long the attack had to run
    # before the detector had enough evidence to fire: the span of the window
    # that produced the event (first triggering request -> last).
    latencies = []
    for ev in events:
        latency = (ev.window_end - ev.window_start).total_seconds()
        latencies.append(latency)
    max_latency = max(latencies) if latencies else 0.0

    return {
        "data": path,
        "use_tool_ua": use_tool_ua,
        "records": len(records),
        "events_emitted": len(events),
        "recall": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
        "max_alert_latency_s": round(max_latency, 3),
        "attack_hit": attack_hit,
        "attack_total": attack_total,
        "benign_flagged": benign_flagged,
        "benign_total": benign_total,
        "recall_by_type": {k: {"hit": v[0], "total": v[1],
                               "recall": round(v[0] / v[1], 4) if v[1] else 0.0}
                           for k, v in by_type.items()},
    }


def print_report(res: dict) -> bool:
    """Print a human-readable report. Returns True if all targets met."""
    def mark(ok):
        return "PASS" if ok else "FAIL"

    recall_ok = res["recall"] >= TARGET_RECALL
    fpr_ok = res["false_positive_rate"] <= TARGET_FPR
    latency_ok = res["max_alert_latency_s"] < TARGET_LATENCY_S

    print(f"Evaluation on {res['data']}  (use_tool_ua={res['use_tool_ua']})")
    print(f"  records {res['records']}   events emitted {res['events_emitted']}")
    print("-" * 56)
    print(f"  recall              {res['recall']*100:5.1f}%  "
          f"({res['attack_hit']}/{res['attack_total']})  "
          f"target >= {TARGET_RECALL*100:.0f}%   [{mark(recall_ok)}]")
    print(f"  false-positive rate {res['false_positive_rate']*100:5.1f}%  "
          f"({res['benign_flagged']}/{res['benign_total']})  "
          f"target <= {TARGET_FPR*100:.0f}%    [{mark(fpr_ok)}]")
    print(f"  max alert latency   {res['max_alert_latency_s']:5.1f}s  "
          f"              target <  {TARGET_LATENCY_S:.0f}s   [{mark(latency_ok)}]")
    print("-" * 56)
    print("  recall by attack type:")
    for label, v in sorted(res["recall_by_type"].items()):
        print(f"    {label:14} {v['recall']*100:5.1f}%  ({v['hit']}/{v['total']})")

    all_ok = recall_ok and fpr_ok and latency_ok
    print("-" * 56)
    print(f"  OVERALL: {mark(all_ok)}")
    return all_ok


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Evaluate the detector against the labelled dataset.")
    ap.add_argument("--data", default="data/labelled_dataset.jsonl")
    ap.add_argument("--ua", action="store_true", help="let the detector use tool user-agents")
    ap.add_argument("--json", action="store_true", help="print raw JSON metrics only")
    args = ap.parse_args()

    res = evaluate(args.data, use_tool_ua=args.ua)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print_report(res)
