"""Tests for Illya's scenario work: the chain-scenario generator and the
whole-pipeline scenario evaluator.

The generator tests run unconditionally. The evaluator tests need Cillian's
rule engine (src/detection/rule_engine.py + data/rules.json); until that is
merged they skip cleanly, so the suite stays green, and they start exercising
the real pipeline the moment it lands.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from dataset.make_chain_scenario import (  # noqa: E402
    CHAIN_IP, SQLMAP_ATTACKER_IP, build_chain,
)
from parser import parse_ts  # noqa: E402

SCAN = str(ROOT / "data" / "dir_scan_logs.jsonl")
SQLMAP = str(ROOT / "data" / "sqlmap_logs.jsonl")


# --- chain scenario generator (no rule engine needed) ---------------------------

def test_chain_is_one_ip_scan_then_sqli():
    events = build_chain(SCAN, SQLMAP)

    # Every event is attributed to the single scanner IP: same_ip(E1, E2) holds.
    assert {e["ip"] for e in events} == {CHAIN_IP}

    scan = [e for e in events if e["user_agent"].startswith("python-requests")]
    sqli = [e for e in events if "sqlmap" in e["user_agent"]]
    assert scan and sqli, "both stages must be present"

    # before(E1, E2): every scan request precedes every injection request.
    last_scan = max(parse_ts(e["ts"]) for e in scan)
    first_sqli = min(parse_ts(e["ts"]) for e in sqli)
    assert last_scan < first_sqli


def test_chain_preserves_sqlmap_payloads():
    events = build_chain(SCAN, SQLMAP)
    sqli = [e for e in events if "sqlmap" in e["user_agent"]]
    # The real sqlmap payloads survive the IP/timestamp rewrite, so the detector
    # still recognises them as SQLi rather than needing hand-written attacks.
    assert all(e["path"].startswith("/rest/products/search") for e in sqli)
    assert any("UNION" in e["query"].upper() or "SELECT" in e["query"].upper()
               for e in sqli)


def test_chain_only_takes_the_attacker_rows():
    events = build_chain(SCAN, SQLMAP)
    # The sqlmap recording also holds unrelated socket.io noise from another IP;
    # only the attacker's own rows (rewritten) should appear.
    raw_ips = {l.split('"ip":"', 1)[1].split('"', 1)[0]
               for l in open(SQLMAP) if '"ip":"' in l}
    assert SQLMAP_ATTACKER_IP in raw_ips and len(raw_ips) > 1   # noise really is there
    assert {e["ip"] for e in events} == {CHAIN_IP}              # but not in the output


def test_chain_detector_sees_scan_before_sqli(tmp_path):
    """The generated file must make the detector emit dir_scan then sqli from one
    IP — the precondition for the rule engine's R2/R3 chain."""
    import json
    from detection.detector import Detector

    out = tmp_path / "chain.jsonl"
    out.write_text("\n".join(json.dumps(e) for e in build_chain(SCAN, SQLMAP)))

    det = Detector()
    events = []
    for line in out.read_text().splitlines():
        events.extend(det.process_line(line))
    got = [(e.attack_type, e.src_ip) for e in events]
    assert got == [("dir_scan", CHAIN_IP), ("sqli", CHAIN_IP)]


# --- scenario evaluator (needs Cillian's rule engine) ---------------------------

def test_scenario_evaluation_all_pass():
    pytest.importorskip(
        "detection.rule_engine",
        reason="scenario evaluation needs Cillian's rule engine (not merged yet)",
    )
    import evaluate_scenarios as es

    engine = es.load_engine()
    results = [es.run_scenario(s, engine) for s in es.SCENARIOS]
    failed = [(r["name"], d) for r in results for d, ok in r["checks"] if not ok]
    assert not failed, f"scenario checks failed: {failed}"


def test_scan_then_sqli_is_critical():
    """The headline result: the chain rule lifts the SQLi stage to critical."""
    pytest.importorskip(
        "detection.rule_engine",
        reason="scenario evaluation needs Cillian's rule engine (not merged yet)",
    )
    import evaluate_scenarios as es

    engine = es.load_engine()
    chain = next(s for s in es.SCENARIOS if s["name"] == "scan_then_sqli")
    result = es.run_scenario(chain, engine)
    assert result["incidents"] == [("dir_scan", "medium"), ("sqli", "critical")]


def test_benign_scenario_has_no_alerts():
    pytest.importorskip(
        "detection.rule_engine",
        reason="scenario evaluation needs Cillian's rule engine (not merged yet)",
    )
    import evaluate_scenarios as es

    engine = es.load_engine()
    benign = next(s for s in es.SCENARIOS if s["name"] == "benign")
    assert es.run_scenario(benign, engine)["alerts"] == 0
