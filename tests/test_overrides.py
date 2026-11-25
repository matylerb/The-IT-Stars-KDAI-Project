
"""Tests for loading the feedback loop's threshold overrides into the Detector."""
import json
 
import pytest
 
from detection.detector import ALL_RULE_IDS, DETECTOR_DEFAULTS, SAFE_MAX, Detector
 
 
def test_defaults_without_file(tmp_path):
    det = Detector.from_overrides(path=str(tmp_path / "missing.json"))
    assert det.sqli_threshold == DETECTOR_DEFAULTS["sqli_threshold"]
    assert det.windows.bf_threshold == DETECTOR_DEFAULTS["bf_threshold"]
    assert det.windows.scan_sensitive == DETECTOR_DEFAULTS["scan_sensitive"]
    assert det.windows.scan_distinct == DETECTOR_DEFAULTS["scan_distinct"]
 
 
def test_overrides_are_applied(tmp_path):
    p = tmp_path / "ov.json"
    p.write_text(json.dumps({"sqli_threshold": 0.8, "bf_threshold": 7,
                             "scan_sensitive": 6, "scan_distinct": 50}))
    det = Detector.from_overrides(path=str(p))
    assert det.sqli_threshold == 0.8
    assert det.windows.bf_threshold == 7
    assert det.windows.scan_sensitive == 6
    assert det.windows.scan_distinct == 50
 
 
def test_partial_overrides_keep_other_defaults(tmp_path):
    p = tmp_path / "ov.json"
    p.write_text(json.dumps({"bf_threshold": 8}))
    det = Detector.from_overrides(path=str(p))
    assert det.windows.bf_threshold == 8
    assert det.sqli_threshold == DETECTOR_DEFAULTS["sqli_threshold"]
 
 
def test_broken_file_falls_back_to_defaults(tmp_path):
    p = tmp_path / "ov.json"
    p.write_text("{not json")
    det = Detector.from_overrides(path=str(p))
    assert det.windows.bf_threshold == DETECTOR_DEFAULTS["bf_threshold"]
 
 
def test_unknown_keys_ignored(tmp_path):
    p = tmp_path / "ov.json"
    p.write_text(json.dumps({"made_up_knob": 99, "bf_threshold": 6}))
    det = Detector.from_overrides(path=str(p))
    assert det.windows.bf_threshold == 6
 
 
def test_overrides_clamped_to_safe_range(tmp_path):
    p = tmp_path / "ov.json"
    p.write_text(json.dumps({"sqli_threshold": 0.95, "bf_threshold": 999,
                             "scan_sensitive": 1, "scan_distinct": 45}))
    det = Detector.from_overrides(path=str(p))
    assert det.sqli_threshold == SAFE_MAX["sqli_threshold"]           # capped
    assert det.windows.bf_threshold == SAFE_MAX["bf_threshold"]       # capped
    assert det.windows.scan_sensitive == DETECTOR_DEFAULTS["scan_sensitive"]  # never looser
 
 
def test_float_drift_is_rounded(tmp_path):
    p = tmp_path / "ov.json"
    p.write_text(json.dumps({"sqli_threshold": 0.8500000000000001}))
    assert Detector.from_overrides(path=str(p)).sqli_threshold == 0.85
 
 
def test_kwargs_win_over_file(tmp_path):
    p = tmp_path / "ov.json"
    p.write_text(json.dumps({"bf_threshold": 9}))
    det = Detector.from_overrides(path=str(p), bf_threshold=4, use_tool_ua=True)
    assert det.windows.bf_threshold == 4 and det.use_tool_ua
 
 
# ---------- keeps Illyas tuner in sync with the detector ----------
tune = pytest.importorskip("feedback.tune_thresholds")
 
 
def test_feedback_defaults_match_detector_defaults():
    for key, value in DETECTOR_DEFAULTS.items():
        assert tune.DEFAULTS.get(key) == value, (
            f"{key}: detector={value} vs feedback DEFAULTS={tune.DEFAULTS.get(key)}")
 
 
def test_tuner_rule_ids_exist_in_detector():
    """Every rule the tuner knows about must still be a rule the detector emits."""
    unknown = sorted(set(tune.RULE_TUNING) - ALL_RULE_IDS)
    assert not unknown, f"tuner refers to rule_ids the detector no longer has: {unknown}"
 
 
def test_tuner_knobs_are_detector_settings():
    for rule_id, spec in tune.RULE_TUNING.items():
        assert spec["knob"] in DETECTOR_DEFAULTS, f"{rule_id} -> unknown knob {spec['knob']}"
 
 
def test_tuner_bounds_within_detector_safe_range():
    """Overrides the tuner can write are always accepted (or safely capped)."""
    for rule_id, spec in tune.RULE_TUNING.items():
        assert spec["bound"] >= DETECTOR_DEFAULTS[spec["knob"]], rule_id
 
 
def test_real_tuner_output_loads(tmp_path):
    """Run Illya's tune() end to end and load its output into the Detector."""
    class Store:
        def false_positives_by_rule(self):
            return {"SQLI-COMMENT": 3, "SQLI-QUOTE-PAREN": 3, "BF-LOGIN-401": 3}
    ov = tmp_path / "ov.json"
    tune.tune(Store(), str(ov), str(tmp_path / "log.jsonl"))
    det = Detector.from_overrides(path=str(ov))
    assert DETECTOR_DEFAULTS["sqli_threshold"] < det.sqli_threshold <= SAFE_MAX["sqli_threshold"]
    assert det.windows.bf_threshold == DETECTOR_DEFAULTS["bf_threshold"] + 1