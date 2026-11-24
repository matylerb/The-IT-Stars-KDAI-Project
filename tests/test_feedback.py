"""Tests for the feedback store and threshold tuner (Illya's modules)."""
import json

from feedback.store import FeedbackStore, VERDICTS
from feedback import tune_thresholds as tt


def _store(tmp_path):
    return FeedbackStore(str(tmp_path / "feedback.jsonl"))


def test_record_and_load_roundtrip(tmp_path):
    s = _store(tmp_path)
    s.record({"event_id": "e1", "attack_type": "sqli", "src_ip": "1.1.1.1",
              "rule_ids": ["SQLI-FUNC"]}, verdict="false_positive")
    s.record({"event_id": "e2", "attack_type": "brute_force", "src_ip": "2.2.2.2",
              "rule_ids": ["BF-LOGIN-401"]}, verdict="confirmed")
    decisions = list(s.load())
    assert [d["event_id"] for d in decisions] == ["e1", "e2"]
    assert decisions[0]["verdict"] == "false_positive"
    assert decisions[0]["rule_ids"] == ["SQLI-FUNC"]


def test_record_accepts_detection_event():
    """record() should accept a real DetectionEvent via .to_dict()."""
    from datetime import datetime, timezone
    from detection.events import DetectionEvent
    t0 = datetime(2026, 11, 18, tzinfo=timezone.utc)
    ev = DetectionEvent("sqli", "high", 0.9, "1.1.1.1", t0, t0, 1,
                        rule_ids=["SQLI-UNION"])
    import tempfile, os
    path = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False).name
    try:
        s = FeedbackStore(path)
        written = s.record(ev, verdict="confirmed")
        assert written["event_id"] == ev.event_id
        assert written["rule_ids"] == ["SQLI-UNION"]
    finally:
        os.unlink(path)


def test_bad_verdict_rejected(tmp_path):
    s = _store(tmp_path)
    try:
        s.record({"event_id": "e1"}, verdict="maybe")
        assert False, "should have raised"
    except ValueError:
        pass


def test_load_missing_file_is_empty(tmp_path):
    s = FeedbackStore(str(tmp_path / "does_not_exist.jsonl"))
    assert list(s.load()) == []


def test_verdict_for_takes_latest(tmp_path):
    s = _store(tmp_path)
    s.record({"event_id": "e1", "rule_ids": []}, verdict="confirmed")
    s.record({"event_id": "e1", "rule_ids": []}, verdict="false_positive")
    assert s.verdict_for("e1") == "false_positive"
    assert s.verdict_for("missing") is None


def test_false_positives_by_rule_counts_and_dedupes(tmp_path):
    s = _store(tmp_path)
    s.record({"event_id": "e1", "rule_ids": ["SQLI-FUNC", "SQLI-COMMENT"]},
             verdict="false_positive")
    s.record({"event_id": "e2", "rule_ids": ["SQLI-FUNC"]}, verdict="false_positive")
    s.record({"event_id": "e3", "rule_ids": ["BF-LOGIN-401"]}, verdict="confirmed")
    # e1 later changed to confirmed -> must drop out of the counts
    s.record({"event_id": "e1", "rule_ids": ["SQLI-FUNC", "SQLI-COMMENT"]},
             verdict="confirmed")
    counts = s.false_positives_by_rule()
    assert counts == {"SQLI-FUNC": 1}      # only e2 remains a false positive


def test_tuner_raises_threshold_past_limit(tmp_path):
    s = _store(tmp_path)
    # three distinct false positives all blaming SQLI-FUNC
    for i in range(3):
        s.record({"event_id": f"e{i}", "rule_ids": ["SQLI-FUNC"]},
                 verdict="false_positive")
    overrides_path = str(tmp_path / "overrides.json")
    log_path = str(tmp_path / "tuning_log.jsonl")
    after = tt.tune(s, overrides_path=overrides_path, log_path=log_path, fp_limit=3)
    assert after["sqli_threshold"] > tt.DEFAULTS["sqli_threshold"]
    # one step of 0.05 from 0.7
    assert abs(after["sqli_threshold"] - 0.75) < 1e-9
    assert json.load(open(overrides_path))["sqli_threshold"] == after["sqli_threshold"]


def test_tuner_ignores_below_limit(tmp_path):
    s = _store(tmp_path)
    s.record({"event_id": "e0", "rule_ids": ["SQLI-FUNC"]}, verdict="false_positive")
    overrides_path = str(tmp_path / "overrides.json")
    after = tt.tune(s, overrides_path=overrides_path,
                    log_path=str(tmp_path / "log.jsonl"), fp_limit=3)
    assert after["sqli_threshold"] == tt.DEFAULTS["sqli_threshold"]


def test_tuner_respects_bound(tmp_path):
    s = _store(tmp_path)
    for i in range(3):
        s.record({"event_id": f"e{i}", "rule_ids": ["BF-LOGIN-401"]},
                 verdict="false_positive")
    overrides_path = str(tmp_path / "overrides.json")
    # start already at the bound
    json.dump({"bf_threshold": 20}, open(overrides_path, "w"))
    after = tt.tune(s, overrides_path=overrides_path,
                    log_path=str(tmp_path / "log.jsonl"), fp_limit=3)
    assert after["bf_threshold"] == 20       # clamped, not 21


def test_all_verdicts_are_valid_constants():
    assert set(VERDICTS) == {"confirmed", "false_positive", "dismissed"}
