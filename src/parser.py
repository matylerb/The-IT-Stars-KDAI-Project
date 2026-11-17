"""
Log parser for the KDAI project.

Turns one line of the nginx JSON access log into a validated Python dict.
Cillian's detection code imports this:

    from parser import parse_line, iter_events, parse_ts

Schema (agreed with Cillian):
    ts, ip, method, path, query, status, user_agent, request_time, body
    (+ optional "label" in the labelled dataset)
"""
import json
import sys
from datetime import datetime
from typing import Callable, Iterable, Iterator, Optional

FIELDS = {
    "ts": str,
    "ip": str,
    "method": str,
    "path": str,
    "query": str,
    "status": int,
    "user_agent": str,
    "request_time": float,
    "body": str,
}

LABELS = {"benign", "sqli_attempt", "brute_force", "dir_scan"}


class ParseError(ValueError):
    """Raised when a log line is empty, not JSON, or breaks the schema."""


def parse_ts(ts: str) -> datetime:
    """Convert the ISO 8601 `ts` string to a datetime (for time windows)."""
    return datetime.fromisoformat(ts)


def _check_type(name: str, value, expected: type):
    if expected is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ParseError(f"field '{name}' must be an integer, got {value!r}")
        return value
    if expected is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ParseError(f"field '{name}' must be a number, got {value!r}")
        return float(value)
    if not isinstance(value, str):
        raise ParseError(f"field '{name}' must be a string, got {value!r}")
    return value


def parse_line(line: str) -> dict:
    """Parse and validate one log line. Raises ParseError if it is bad."""
    line = line.strip()
    if not line:
        raise ParseError("empty line")

    try:
        raw = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise ParseError("line is JSON but not an object")

    missing = [name for name in FIELDS if name not in raw]
    if missing:
        raise ParseError(f"missing fields: {', '.join(missing)}")

    event = {name: _check_type(name, raw[name], typ) for name, typ in FIELDS.items()}

    # If a client sent several IPs ("a, b"), the first one is the original client.
    ip = event["ip"].split(",")[0].strip()
    if not ip:
        raise ParseError("empty ip")
    event["ip"] = ip

    try:
        parse_ts(event["ts"])
    except ValueError as exc:
        raise ParseError(f"bad timestamp {event['ts']!r}") from exc

    if "label" in raw:
        if raw["label"] not in LABELS:
            raise ParseError(f"unknown label {raw['label']!r}")
        event["label"] = raw["label"]

    return event


def iter_events(
    lines: Iterable[str],
    on_error: Optional[Callable[[int, str, ParseError], None]] = None,
) -> Iterator[dict]:
    """Yield a valid event for each good line; skip bad lines without crashing.

    on_error(line_number, line, error) is called for every skipped line.
    """
    for number, line in enumerate(lines, start=1):
        try:
            yield parse_line(line)
        except ParseError as exc:
            if on_error:
                on_error(number, line, exc)


if __name__ == "__main__":
    # Quick check of a file:  python src/parser.py data/sample_logs.jsonl
    if len(sys.argv) != 2:
        sys.exit("usage: python parser.py <logfile.jsonl>")

    good = 0
    bad = 0

    def report(number, line, error):
        global bad
        bad += 1
        print(f"line {number}: {error}")

    with open(sys.argv[1], "r") as handle:
        for _ in iter_events(handle, on_error=report):
            good += 1

    print(f"valid: {good}  invalid: {bad}")