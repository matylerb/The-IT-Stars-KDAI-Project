"""
Feedback -> new facts in the knowledge graph.

When a human presses "Block / Escalate" in Telegram, Illya's feedback store
records the verdict "confirmed". Here those decisions become graph facts:

    (10.0.0.60, type, Attacker)
    (10.0.0.60, confirmedAttackerOf, brute_force)

So the next alert about the same IP can say "this address was already
confirmed as an attacker". This is knowledge revision by adding explicit
facts, not retraining (Lecture 7). Only the LATEST verdict per event counts,
because a human can change their mind.

    from feedback.store import FeedbackStore
    learn_from_feedback(kg, FeedbackStore())   # once at startup
    known_attacks(kg, "10.0.0.60")              # -> ["brute_force"]
"""


def learn_from_feedback(kg, store) -> list:
    """Add facts for every confirmed event. Returns the triples added."""
    latest = {}
    for d in store.load():
        latest[d["event_id"]] = d

    added = []
    for d in latest.values():
        ip, attack = d.get("src_ip"), d.get("attack_type")
        if d["verdict"] != "confirmed" or not ip or not kg.is_attack(attack):
            continue
        for triple in ((ip, "type", "Attacker"), (ip, "confirmedAttackerOf", attack)):
            if triple not in kg:
                kg.add(*triple)
                added.append(triple)
    return added


def known_attacks(kg, ip: str) -> list:
    """Attack types a human has already confirmed for this IP (empty = none known)."""
    return [t.o for t in kg.match(s=ip, p="confirmedAttackerOf")]
