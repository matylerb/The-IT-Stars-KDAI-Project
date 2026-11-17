import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from parser import ParseError, iter_events, parse_line, parse_ts  # noqa: E402

GOOD = {
    "ts": "2026-11-16T17:20:58+00:00",
    "ip": "10.0.0.50",
    "method": "GET",
    "path": "/rest/products/search",
    "query": "q=apple",
    "status": 200,
    "user_agent": "Mozilla/5.0",
    "request_time": 0.012,
    "body": "",
}


def line(**overrides):
    data = {**GOOD, **overrides}
    return json.dumps(data)


def test_valid_line_returns_dict():
    event = parse_line(line())
    assert event["ip"] == "10.0.0.50"
    assert event["status"] == 200
    assert event["request_time"] == 0.012


def test_empty_query_is_allowed():
    assert parse_line(line(query=""))["query"] == ""


def test_request_time_int_becomes_float():
    assert isinstance(parse_line(line(request_time=1))["request_time"], float)


def test_multiple_ips_keep_first():
    assert parse_line(line(ip="10.0.0.1, 172.18.0.2"))["ip"] == "10.0.0.1"


def test_label_is_kept_when_valid():
    assert parse_line(line(label="dir_scan"))["label"] == "dir_scan"


def test_unknown_label_rejected():
    with pytest.raises(ParseError):
        parse_line(line(label="hacker"))


def test_empty_line_rejected():
    with pytest.raises(ParseError):
        parse_line("   ")


def test_broken_json_rejected():
    with pytest.raises(ParseError):
        parse_line('{"ts": "2026-11-16", ')


def test_missing_field_rejected():
    data = dict(GOOD)
    del data["status"]
    with pytest.raises(ParseError):
        parse_line(json.dumps(data))


def test_status_must_be_integer():
    with pytest.raises(ParseError):
        parse_line(line(status="200"))


def test_empty_ip_rejected():
    with pytest.raises(ParseError):
        parse_line(line(ip=""))


def test_bad_timestamp_rejected():
    with pytest.raises(ParseError):
        parse_line(line(ts="yesterday"))


def test_parse_ts_returns_datetime():
    assert parse_ts("2026-11-16T17:20:58+00:00").year == 2026


def test_iter_events_skips_bad_lines():
    errors = []
    lines = [line(), "not json", line(path="/admin"), ""]
    events = list(iter_events(lines, on_error=lambda n, l, e: errors.append(n)))
    assert [e["path"] for e in events] == ["/rest/products/search", "/admin"]
    assert errors == [2, 4]