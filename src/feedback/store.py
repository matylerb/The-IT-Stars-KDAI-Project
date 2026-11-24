"""
Feedback store (Illya).

The bottom-left box in the system diagram: when Tyler's Telegram bot gets a
human verdict on an alert, it calls record() here. Everything a human decided
is appended to one JSONL file, one decision per line. The threshold tuner
(tune_thresholds.py) reads this file back to count false positives per rule.

Schema agreed in the proposal: each decision is (event_id, rule_ids, verdict).
We also keep the attack_type, src_ip and a timestamp so the tuner and the
report have enough context without having to join back to the event log.

    from feedback.store import FeedbackStore, VERDICTS

    store = FeedbackStore("data/feedback.jsonl")
    store.record(event, verdict="false_positive")   # event is a DetectionEvent or its dict
    for d in store.load():
        ...

Verdicts (what the human pressed in Telegram):
    confirmed      - real attack, the alert was right  (Block / Escalate)
    false_positive - benign traffic wrongly flagged    (Ignore, "this is fine")
    dismissed      - not acted on, no judgement made    (Ignore, unsure)

Only false_positive feeds threshold tuning. confirmed attackers can later
become knowledge-graph facts (Ivan's side); dismissed is recorded but neutral.
"""
import json
import os
from datetime import datetime, timezone
from typing import Iterator, Optional, Union

VERDICTS = ("confirmed", "false_positive", "dismissed")

DEFAULT_PATH = "data/feedback.jsonl"


class FeedbackStore:
    def __init__(self, path: str = DEFAULT_PATH):
        self.path = path

    def record(
        self,
        event: Union[dict, "object"],
        verdict: str,
        decided_by: str = "human",
        note: str = "",
    ) -> dict:
        """Append one human decision about one DetectionEvent.

        `event` may be a DetectionEvent (we call .to_dict()) or an already
        plain dict. Returns the decision dict that was written.
        """
        if verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {verdict!r}; expected one of {VERDICTS}")

        ev = event.to_dict() if hasattr(event, "to_dict") else event
        if "event_id" not in ev:
            raise ValueError("event has no event_id")

        decision = {
            "decided_at": datetime.now(timezone.utc).isoformat(),
            "event_id": ev["event_id"],
            "attack_type": ev.get("attack_type"),
            "src_ip": ev.get("src_ip"),
            "rule_ids": list(ev.get("rule_ids", [])),
            "verdict": verdict,
            "decided_by": decided_by,
            "note": note,
        }

        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "a") as f:
            f.write(json.dumps(decision) + "\n")
        return decision

    def load(self) -> Iterator[dict]:
        """Yield every recorded decision in order. Empty if the file is absent."""
        if not os.path.exists(self.path):
            return
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verdict_for(self, event_id: str) -> Optional[str]:
        """Latest verdict recorded for an event_id, or None if never judged.

        A human can change their mind, so the last line wins.
        """
        latest = None
        for d in self.load():
            if d["event_id"] == event_id:
                latest = d["verdict"]
        return latest

    def false_positives_by_rule(self) -> dict:
        """rule_id -> how many times a false_positive decision involved that rule.

        This is exactly what the threshold tuner needs. One false-positive
        decision counts once for every rule_id that fired on that event.
        """
        counts: dict = {}
        seen = set()
        # Collapse to the latest verdict per event so flip-flopping a decision
        # doesn't double count.
        latest_rules = {}
        latest_verdict = {}
        for d in self.load():
            latest_verdict[d["event_id"]] = d["verdict"]
            latest_rules[d["event_id"]] = d.get("rule_ids", [])
        for event_id, verdict in latest_verdict.items():
            if verdict != "false_positive" or event_id in seen:
                continue
            seen.add(event_id)
            for rule_id in latest_rules[event_id]:
                counts[rule_id] = counts.get(rule_id, 0) + 1
        return counts


if __name__ == "__main__":
    # Tiny smoke test against a scratch file.
    import tempfile

    tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False).name
    store = FeedbackStore(tmp)
    store.record(
        {"event_id": "e1", "attack_type": "sqli", "src_ip": "10.0.0.80",
         "rule_ids": ["SQLI-FUNC", "SQLI-COMMENT"]},
        verdict="false_positive",
    )
    store.record(
        {"event_id": "e2", "attack_type": "brute_force", "src_ip": "10.0.0.60",
         "rule_ids": ["BF-LOGIN-401"]},
        verdict="confirmed",
    )
    print("decisions:", list(store.load()))
    print("verdict_for(e1):", store.verdict_for("e1"))
    print("false positives by rule:", store.false_positives_by_rule())
    os.unlink(tmp)
