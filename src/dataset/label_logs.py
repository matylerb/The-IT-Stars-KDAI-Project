"""
Labelled dataset builder (Task H).

Reads one or more raw nginx access log files plus data/ground_truth.jsonl,
and writes a single combined JSONL file where every line has a `label`
field: benign, brute_force, dir_scan, or sqli_attempt.

A log line is labelled with an attack type if its `ip` matches a
ground-truth record's `ip` AND its `ts` falls within that record's
[start_ts, end_ts] window (with a small configurable buffer on each side,
to allow for clock/logging slack). Everything else is labelled benign.

Usage:
    python src/dataset/label_logs.py \
        --ground-truth data/ground_truth.jsonl \
        --logs data/sample_logs.jsonl data/locust_logs.jsonl \
               data/brute_force_logs.jsonl data/dir_scan_logs.jsonl \
               data/sqlmap_logs.jsonl \
        --out data/labelled_dataset.jsonl
"""
import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from parser import ParseError, parse_line, parse_ts  # noqa: E402


@dataclass
class AttackWindow:
    attack_type: str
    ip: str
    start: datetime
    end: datetime


def load_ground_truth(path: str, buffer_seconds: float) -> List[AttackWindow]:
    """Read ground_truth.jsonl and build one time window per attack run."""
    windows = []
    with open(path, "r") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[label_logs] skipping bad ground-truth line {line_number}: {exc}")
                continue

            required = {"attack_type", "ip", "start_ts", "end_ts"}
            missing = required - record.keys()
            if missing:
                print(f"[label_logs] skipping ground-truth line {line_number}, "
                      f"missing fields: {missing}")
                continue

            try:
                start = parse_ts(record["start_ts"]) - timedelta(seconds=buffer_seconds)
                end = parse_ts(record["end_ts"]) + timedelta(seconds=buffer_seconds)
            except ValueError as exc:
                print(f"[label_logs] skipping ground-truth line {line_number}, "
                      f"bad timestamp: {exc}")
                continue

            windows.append(AttackWindow(
                attack_type=record["attack_type"],
                ip=record["ip"],
                start=start,
                end=end,
            ))
    return windows


def label_for(ip: str, ts: datetime, windows: List[AttackWindow]) -> str:
    """Return the attack type whose window covers this ip+timestamp, else benign."""
    for w in windows:
        if ip == w.ip and w.start <= ts <= w.end:
            return w.attack_type
    return "benign"


def label_file(log_path: str, windows: List[AttackWindow], out_f) -> dict:
    """Label every valid line in one log file, writing results to out_f.

    Returns a small per-file summary dict for the final report.
    """
    counts = {}
    skipped = 0

    with open(log_path, "r") as f:
        for line in f:
            try:
                event = parse_line(line)
            except ParseError:
                skipped += 1
                continue

            ts = parse_ts(event["ts"])
            label = label_for(event["ip"], ts, windows)
            event["label"] = label
            counts[label] = counts.get(label, 0) + 1

            out_f.write(json.dumps(event) + "\n")

    return {"file": log_path, "counts": counts, "skipped_invalid": skipped}


def main(ground_truth_path: str, log_paths: List[str], out_path: str,
         buffer_seconds: float):
    windows = load_ground_truth(ground_truth_path, buffer_seconds)
    print(f"[label_logs] loaded {len(windows)} attack window(s) from {ground_truth_path}")
    for w in windows:
        print(f"  - {w.attack_type}: ip={w.ip} window=[{w.start} .. {w.end}]")

    summaries = []
    with open(out_path, "w") as out_f:
        for log_path in log_paths:
            summary = label_file(log_path, windows, out_f)
            summaries.append(summary)

    print(f"\n[label_logs] wrote labelled dataset to {out_path}\n")
    totals = {}
    for s in summaries:
        print(f"{s['file']}: {s['counts']}  (skipped {s['skipped_invalid']} invalid lines)")
        for label, count in s["counts"].items():
            totals[label] = totals.get(label, 0) + count

    print(f"\n[label_logs] totals across all files: {totals}")
    total_lines = sum(totals.values())
    if total_lines:
        print(f"[label_logs] {total_lines} labelled lines written")
        for label, count in sorted(totals.items()):
            pct = 100 * count / total_lines
            print(f"  {label}: {count} ({pct:.1f}%)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build a labelled dataset from raw logs.")
    parser.add_argument("--ground-truth", default="data/ground_truth.jsonl",
                         help="Path to ground_truth.jsonl (default: %(default)s)")
    parser.add_argument("--logs", nargs="+", required=True,
                         help="One or more raw access-log JSONL files to label")
    parser.add_argument("--out", default="data/labelled_dataset.jsonl",
                         help="Output path for the labelled dataset (default: %(default)s)")
    parser.add_argument("--buffer-seconds", type=float, default=2.0,
                         help="Seconds of slack added before/after each attack "
                              "window, to absorb clock/logging lag (default: %(default)s)")
    args = parser.parse_args()

    main(
        ground_truth_path=args.ground_truth,
        log_paths=args.logs,
        out_path=args.out,
        buffer_seconds=args.buffer_seconds,
    )