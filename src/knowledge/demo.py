"""
Demo for the presentation: how knowledge in the graph shapes the advice.

Run from the repo root:
    PYTHONPATH=src python -m knowledge.demo

Four short scenes:
  1. real attacks from the labelled dataset -> what the graph adds, and why
  2. edit one fact in the graph -> the recommendation changes, no code changed
  3. a human confirms an alert -> the graph learns the attacker
  4. an attack the graph knows nothing about -> nothing is invented
"""
import tempfile
from pathlib import Path

from detection.detector import Detector
from feedback.store import FeedbackStore
from knowledge.enrich import enrich
from knowledge.feedback_facts import learn_from_feedback
from knowledge.graph import KnowledgeGraph
from parser import iter_events, parse_ts

DATASET = Path(__file__).resolve().parents[2] / "data" / "labelled_dataset.jsonl"


def detect_dataset(path=DATASET) -> list:
    """Run Cillian's detector over a recorded log, return event dicts."""
    with open(path) as f:
        records = sorted(iter_events(f), key=lambda r: parse_ts(r["ts"]))
    det = Detector()
    events = []
    for rec in records:
        rec.pop("label", None)               # the detector must not see the answer
        events += [e.to_dict() for e in det.process(rec)]
    return events


def show_actions(result) -> None:
    for slot, actions in result["action_domains"].items():
        names = ", ".join(a["label"] for a in actions) or "-"
        print(f"      {slot:12} {names}")


def title(text) -> None:
    print(f"\n{'=' * 70}\n{text}\n{'=' * 70}")


def main():
    kg = KnowledgeGraph.load()
    print(f"Knowledge graph: {len(kg)} triples, consistent with the ontology")

    title("1. Real attacks from the dataset")
    events = detect_dataset()
    for ev in events:
        r = enrich(ev, kg)
        a = r["attack"]
        print(f"\n  {a['label']} from {r['src_ip']}  "
              f"[{a['technique']['id']} {a['technique']['label']} | "
              f"OWASP {a['weakness']['id']} {a['weakness']['label']}]")
        show_actions(r)

    sqli = next(e for e in events if e["attack_type"] == "sqli")
    block = enrich(sqli, kg)["action_domains"]["network"][0]
    print(f"\n  Why is '{block['label']}' offered for SQL injection? Proof path:")
    for step in block["path"]:
        print(f"      {step}")

    title("2. Change the knowledge, not the code")
    ev = {"event_id": "demo", "src_ip": "10.0.0.60", "attack_type": "brute_force"}
    print("\n  before:")
    show_actions(enrich(ev, kg))
    edited = KnowledgeGraph.load()
    edited.remove("T1110", "mitigatedBy", "account_lockout")
    edited.remove("A07:2021", "mitigatedBy", "account_lockout")
    print("\n  after removing (T1110, mitigatedBy, account_lockout)"
          " and (A07:2021, mitigatedBy, account_lockout):")
    show_actions(enrich(ev, edited))

    title("3. Feedback becomes knowledge")
    with tempfile.TemporaryDirectory() as tmp:
        store = FeedbackStore(str(Path(tmp) / "feedback.jsonl"))
        bf = next(e for e in events if e["attack_type"] == "brute_force")
        store.record(bf, verdict="confirmed")
        learned = KnowledgeGraph.load()
        for t in learn_from_feedback(learned, store):
            print(f"  learned: ({t[0]}, {t[1]}, {t[2]})")
        later = dict(sqli, src_ip=bf["src_ip"])
        print(f"  next alert from {bf['src_ip']}: already confirmed attacker of "
              f"{enrich(later, learned)['known_attacker']}")

    title("4. Open world: unknown attack")
    r = enrich({"event_id": "demo", "src_ip": "1.2.3.4", "attack_type": "ddos"}, kg)
    print(f"\n  ddos -> {r['graph_status']}")
    print(f"  mitigations: {r['mitigations']}")


if __name__ == "__main__":
    main()
