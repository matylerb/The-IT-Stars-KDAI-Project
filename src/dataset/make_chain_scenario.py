"""
Scan-then-injection scenario builder (Illya).

The attack-chain rules R2/R3 (Cillian's rule engine) only fire when ONE source
IP first runs a directory scan and then an SQL injection:

    R2: attack(E1, dir_scan) ∧ attack(E2, sqli) ∧ same_ip(E1, E2) ∧ before(E1, E2) → chain(E2)
    R3: chain(E) → severity(E, critical)

Our recorded data can't show this: the dir scan is from 10.0.0.70 and the SQLi
from 10.0.0.80, so `same_ip` is never satisfied and the chain can never fire.
This script builds `data/scan_then_sqli_logs.jsonl`: the real dir-scan lines,
then the real sqlmap attacker lines with their IP rewritten to the scanner's
(10.0.0.70) and their timestamps shifted to start just after the scan, so the
two stages belong to one attacker in the right order.

It reuses the real recordings rather than inventing traffic, so the SQLi burst
still carries sqlmap's own paths, user-agent and request shape — only the IP and
the absolute timestamps change (the inter-request gaps are preserved).

Run it from the repository root:
    python src/dataset/make_chain_scenario.py
    python src/dataset/make_chain_scenario.py --out data/scan_then_sqli_logs.jsonl
"""
import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from parser import ParseError, parse_line, parse_ts  # noqa: E402

# The scanner's IP in data/dir_scan_logs.jsonl. The rewritten SQLi stage is
# attributed to this same IP so the two stages share one attacker.
CHAIN_IP = "10.0.0.70"

# Only these rows in sqlmap_logs.jsonl are the actual attacker; the rest
# (e.g. 192.168.65.1) are Juice Shop's own socket.io traffic recorded alongside.
SQLMAP_ATTACKER_IP = "10.0.0.80"

# How long after the last scan request the injection stage begins. A real
# recon-then-exploit chain has a pause while the attacker reads the results;
# 60s is comfortably inside any per-IP correlation window and keeps the SQLi
# clearly "after" the scan.
GAP_AFTER_SCAN_S = 60.0


def _load(path: str) -> list:
    """Parse every line of a recorded log, skipping any that don't validate."""
    events = []
    with open(path) as f:
        for n, line in enumerate(f, start=1):
            try:
                events.append(parse_line(line))
            except ParseError as exc:
                print(f"[make_chain] {path}: skipping bad line {n}: {exc}",
                      file=sys.stderr)
    return events


def build_chain(scan_path: str, sqlmap_path: str) -> list:
    """Return the combined scan-then-SQLi event list, all from CHAIN_IP, in order."""
    scan = sorted(_load(scan_path), key=lambda e: parse_ts(e["ts"]))
    if not scan:
        raise SystemExit(f"[make_chain] no scan events in {scan_path}")

    sqli = [e for e in _load(sqlmap_path) if e["ip"] == SQLMAP_ATTACKER_IP]
    sqli.sort(key=lambda e: parse_ts(e["ts"]))
    if not sqli:
        raise SystemExit(f"[make_chain] no attacker rows ({SQLMAP_ATTACKER_IP}) "
                         f"in {sqlmap_path}")

    # New time base: SQLi stage starts GAP_AFTER_SCAN_S after the last scan line,
    # keeping the original gaps between sqlmap requests.
    last_scan_ts = parse_ts(scan[-1]["ts"])
    sqli_origin = parse_ts(sqli[0]["ts"])
    shift = (last_scan_ts + timedelta(seconds=GAP_AFTER_SCAN_S)) - sqli_origin

    chained = list(scan)                      # scan stage, unchanged (already CHAIN_IP)
    for e in sqli:
        shifted = dict(e)
        shifted["ip"] = CHAIN_IP              # same attacker as the scan
        shifted["ts"] = (parse_ts(e["ts"]) + shift).isoformat()
        chained.append(shifted)
    return chained


def main(scan_path: str, sqlmap_path: str, out_path: str):
    chained = build_chain(scan_path, sqlmap_path)
    with open(out_path, "w") as f:
        for e in chained:
            f.write(json.dumps(e) + "\n")

    n_scan = sum(1 for e in chained if e["path"] and e["user_agent"].startswith("python-requests"))
    first, last = parse_ts(chained[0]["ts"]), parse_ts(chained[-1]["ts"])
    print(f"[make_chain] wrote {len(chained)} events to {out_path}")
    print(f"[make_chain] all from {CHAIN_IP}; "
          f"scan then SQLi over {(last - first).total_seconds():.0f}s "
          f"({chained[0]['ts']} .. {chained[-1]['ts']})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Build the scan-then-SQLi chain scenario from recorded logs.")
    ap.add_argument("--scan", default="data/dir_scan_logs.jsonl")
    ap.add_argument("--sqlmap", default="data/sqlmap_logs.jsonl")
    ap.add_argument("--out", default="data/scan_then_sqli_logs.jsonl")
    args = ap.parse_args()
    main(args.scan, args.sqlmap, args.out)
