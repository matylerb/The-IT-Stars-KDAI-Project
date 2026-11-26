"""Tests for the agent (src/agent/main.py): recorded logs in, one alert per incident out."""
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "agent"))

from detection.detector import Detector  # noqa: E402
from main import follow, load_env, run    # noqa: E402

NO_LLM = lambda facts: None               # noqa: E731  (template only, never calls Groq)


def alerts_for(log_name, send=None):
    sent = []
    with open(ROOT / "data" / log_name) as f:
        run(f, send or (lambda e, p, a: sent.append((e, p, a))), llm=NO_LLM, detector=Detector())
    return sent


def test_brute_force_gives_two_alerts():
    sent = alerts_for("brute_force_logs.jsonl")
    assert [p.severity for _, p, _ in sent] == ["high", "critical"]
    assert all(a["actions"] for _, _, a in sent)


def test_one_alert_each_for_scan_and_sqli():
    assert [e["attack_type"] for e, _, _ in alerts_for("dir_scan_logs.jsonl")] == ["dir_scan"]
    assert [e["attack_type"] for e, _, _ in alerts_for("sqlmap_logs.jsonl")] == ["sqli"]


def test_benign_traffic_gives_no_alerts():
    assert alerts_for("locust_logs.jsonl") == []


def test_failed_alert_does_not_stop_detection():
    calls = []

    def broken_send(event, plan, alert):
        calls.append(event)
        raise RuntimeError("Telegram is down")

    alerts_for("brute_force_logs.jsonl", send=broken_send)
    assert len(calls) == 2                 # second alert still attempted after the first failed


def test_follow_yields_only_new_complete_lines(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("old line\n")
    got = []
    t = threading.Thread(target=lambda: [got.append(x) for x in follow(str(log))], daemon=True)
    t.start()
    time.sleep(0.3)
    with open(log, "a") as f:
        f.write("new ")
        f.flush()
        time.sleep(0.3)
        assert got == []                   # half a line is not yielded
        f.write("line\n")
    time.sleep(0.5)
    assert got == ["new line\n"]           # old line skipped, new line whole


def test_load_env_reads_file_but_real_env_wins(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nKDAI_TEST_A=from_file\nKDAI_TEST_B=from_file\n")
    monkeypatch.delenv("KDAI_TEST_A", raising=False)
    monkeypatch.setenv("KDAI_TEST_B", "already_set")
    load_env(env)
    assert os.environ["KDAI_TEST_A"] == "from_file"
    assert os.environ["KDAI_TEST_B"] == "already_set"
    monkeypatch.delenv("KDAI_TEST_A")
