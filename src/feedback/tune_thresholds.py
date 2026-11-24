"""
Threshold tuning (Illya).

The dashed `I -.->|threshold tuning| B` arrow in the system diagram: the
feedback a human gives is turned back into a small, explicit change to the
detector's thresholds. This is knowledge revision by editing data, not
machine learning retraining (Lecture 7).

How it works:
  1. Read the feedback store and count false positives per rule_id.
  2. For any rule whose false-positive count is at or above FP_LIMIT, nudge
     the threshold it belongs to by ONE bounded step, in the direction that
     makes that rule fire less often.
  3. Write the new thresholds to data/threshold_overrides.json and append a
     line to data/tuning_log.jsonl explaining what changed and why.

The change is bounded: each rule can only move a threshold a fixed step, and
never past a hard ceiling/floor, so a noisy feedback stream cannot blind the
detector. Every change is logged for human review.

The detector reads the overrides at startup:

    import json, os
    overrides = {}
    if os.path.exists("data/threshold_overrides.json"):
        overrides = json.load(open("data/threshold_overrides.json"))
    det = Detector(
        sqli_threshold=overrides.get("sqli_threshold", DEFAULT_THRESHOLD),
        bf_threshold=overrides.get("bf_threshold", 5),
        scan_distinct=overrides.get("scan_distinct", 45),
    )

Run it:
    PYTHONPATH=src python -m feedback.tune_thresholds
"""
import json
import os
from datetime import datetime, timezone

from feedback.store import FeedbackStore

# A rule must cause at least this many false positives before we touch
# anything. One or two stray clicks should not move a threshold.
FP_LIMIT = 3

OVERRIDES_PATH = "data/threshold_overrides.json"
TUNING_LOG_PATH = "data/tuning_log.jsonl"

# Which detector knob each rule belongs to, how to nudge it to fire LESS,
# the step size, and the hard limit we will never cross.
#   step is signed: +step raises a confidence threshold (stricter),
#                    +step raises a count threshold (needs more hits).
#   bound is the ceiling we clamp to.
RULE_TUNING = {
    # stateless SQLi / XSS rules -> raise the confidence threshold
    "SQLI-FUNC":        {"knob": "sqli_threshold", "step": 0.05, "bound": 0.95},
    "SQLI-COMMENT":     {"knob": "sqli_threshold", "step": 0.05, "bound": 0.95},
    "SQLI-QUOTE-PAREN": {"knob": "sqli_threshold", "step": 0.05, "bound": 0.95},
    "SQLI-CHAR-DENSITY":{"knob": "sqli_threshold", "step": 0.05, "bound": 0.95},
    "XSS-TAG":          {"knob": "sqli_threshold", "step": 0.05, "bound": 0.95},
    # stateful brute force -> need more failed logins before alerting
    "BF-LOGIN-401":     {"knob": "bf_threshold",   "step": 1,    "bound": 20},
    # stateful dir scan -> need more distinct paths before alerting
    "SCAN-DISTINCT-PATHS": {"knob": "scan_distinct", "step": 5,  "bound": 120},
    "SCAN-SENSITIVE-PATHS":{"knob": "scan_sensitive","step": 1,  "bound": 15},
}

# Starting values if no override file exists yet. Must match the detector
# defaults in rules.py / stateful.py.
DEFAULTS = {
    "sqli_threshold": 0.7,
    "bf_threshold": 5,
    "scan_distinct": 45,
    "scan_sensitive": 5,
}


def load_overrides(path: str = OVERRIDES_PATH) -> dict:
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return dict(DEFAULTS)


def _clamp(knob: str, value, step, bound):
    new = value + step
    # step is always positive here (stricter), so bound is a ceiling.
    return min(new, bound)


def tune(store: FeedbackStore,
         overrides_path: str = OVERRIDES_PATH,
         log_path: str = TUNING_LOG_PATH,
         fp_limit: int = FP_LIMIT) -> dict:
    """Run one tuning pass. Returns the (possibly updated) overrides dict."""
    fp_counts = store.false_positives_by_rule()
    overrides = load_overrides(overrides_path)
    changes = []

    for rule_id, count in sorted(fp_counts.items()):
        if count < fp_limit:
            continue
        spec = RULE_TUNING.get(rule_id)
        if spec is None:
            # Rule we don't know how to tune: record it for a human, skip.
            changes.append({"rule_id": rule_id, "fp_count": count,
                            "knob": None, "note": "no tuning rule for this id"})
            continue

        knob = spec["knob"]
        old = overrides.get(knob, DEFAULTS[knob])
        new = _clamp(knob, old, spec["step"], spec["bound"])
        if new != old:
            overrides[knob] = new
            changes.append({"rule_id": rule_id, "fp_count": count, "knob": knob,
                            "old": old, "new": new, "note": "raised one step"})
        else:
            changes.append({"rule_id": rule_id, "fp_count": count, "knob": knob,
                            "old": old, "new": new, "note": "already at bound"})

    if changes:
        os.makedirs(os.path.dirname(overrides_path) or ".", exist_ok=True)
        with open(overrides_path, "w") as f:
            json.dump(overrides, f, indent=2)
        with open(log_path, "a") as f:
            f.write(json.dumps({
                "tuned_at": datetime.now(timezone.utc).isoformat(),
                "fp_limit": fp_limit,
                "changes": changes,
            }) + "\n")

    return overrides


if __name__ == "__main__":
    store = FeedbackStore()
    before = load_overrides()
    after = tune(store)
    print("false positives by rule:", store.false_positives_by_rule())
    print("thresholds before:", before)
    print("thresholds after: ", after)
    if before == after:
        print("(no change — not enough false-positive feedback yet)")
