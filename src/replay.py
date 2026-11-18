"""
Replay script (Task I).

Reads a recorded JSONL access log (labelled or raw) and "replays" it by
printing each event to stdout with realistic time delays between them,
matching the original gaps between requests. This lets the rest of the
pipeline (detection, knowledge graph, response, alerting) be tested against
a fixed, reproducible sequence of events instead of live traffic, and
serves as a demo fallback if a live attack fails on presentation day.

By default this just prints each event as JSON to stdout, one per line,
with real-time delays - exactly like tailing a live log. Pipe it into
the agent's stdin, or redirect main.py to read from a FIFO/pipe fed by
this script, once Tyler's pipeline is ready to consume it that way.

Usage:
    python src/replay.py data/labelled_dataset.jsonl
    python src/replay.py data/labelled_dataset.jsonl --speed 10
    python src/replay.py data/labelled_dataset.jsonl --speed 0   # no delay, dump instantly
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from parser import ParseError, parse_line, parse_ts  # noqa: E402


def load_events(path: str):
    """Read and validate every line, keeping only lines that parse cleanly.

    Skipped (invalid) lines are reported to stderr but do not stop replay.
    """
    events = []
    skipped = 0
    with open(path, "r") as f:
        for line_number, line in enumerate(f, start=1):
            try:
                events.append(parse_line(line))
            except ParseError as exc:
                skipped += 1
                print(f"[replay] skipping invalid line {line_number}: {exc}", file=sys.stderr)
    if skipped:
        print(f"[replay] skipped {skipped} invalid line(s)", file=sys.stderr)
    return events


def replay(events, speed: float, loop: bool):
    """Print events in order, sleeping between them to match original timing.

    speed > 1 replays faster than real time (e.g. speed=10 is 10x speed).
    speed == 0 disables delays entirely (dump everything immediately).
    """
    if not events:
        print("[replay] no events to replay", file=sys.stderr)
        return

    # Sort by timestamp so events replay in the order they actually happened,
    # even if they came from several concatenated log files.
    events = sorted(events, key=lambda e: parse_ts(e["ts"]))

    while True:
        prev_ts = None
        for i, event in enumerate(events, start=1):
            ts = parse_ts(event["ts"])
            if prev_ts is not None and speed > 0:
                gap = (ts - prev_ts).total_seconds() / speed
                if gap > 0:
                    time.sleep(gap)
            prev_ts = ts

            print(json.dumps(event), flush=True)
            label = event.get("label", "")
            tag = f" [{label}]" if label else ""
            print(f"[replay] {i}/{len(events)} ip={event['ip']} "
                  f"{event['method']} {event['path']}{tag}", file=sys.stderr)

        if not loop:
            break
        print("[replay] reached end of file, looping", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Replay a recorded JSONL log with realistic timing.")
    parser.add_argument("logfile", help="Path to the JSONL log file to replay")
    parser.add_argument("--speed", type=float, default=1.0,
                         help="Playback speed multiplier. 1.0 = real time, "
                              "10.0 = 10x faster, 0 = no delay at all "
                              "(default: %(default)s)")
    parser.add_argument("--loop", action="store_true",
                         help="Loop the replay forever instead of stopping "
                              "at the end of the file")
    args = parser.parse_args()

    events = load_events(args.logfile)
    print(f"[replay] loaded {len(events)} event(s) from {args.logfile}", file=sys.stderr)
    replay(events, speed=args.speed, loop=args.loop)