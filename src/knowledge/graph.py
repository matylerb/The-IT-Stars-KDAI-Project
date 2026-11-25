"""
Security knowledge graph: the questions the rest of the pipeline asks.

    kg = KnowledgeGraph.load()                 # reads data/kg/*.csv and checks it
    kg.describe("brute_force")                 # technique + OWASP category
    kg.mitigations("brute_force")              # what reduces the risk, and why
    kg.actions("brute_force")                  # one-tap actions per CSP slot
    kg.justify("brute_force", "block_ip")      # proof path, or None if not in the graph

Why this is more than a lookup table
------------------------------------
Mitigations are not stored next to the attack. They are DERIVED by
following links, using four graph rules (each is a small query):

  K1  attack --mitigatedBy--> m
  K2  attack --mapsTo--> technique --mitigatedBy--> m
  K3  attack --mapsTo--> technique --subTechniqueOf--> parent --mitigatedBy--> m
      (inheritance: a sub-technique gets its parent's mitigations, like
       "Rex is a Dog, a Dog is a Mammal" in Lecture 8)
  K4  attack --classifiedAs--> OWASP category --mitigatedBy--> m

Then an action is offered only if one of those mitigations is implementedBy
it. Changing one line in facts.csv changes the recommendations without any
code change. Which of these actions are finally shown (allowlist, severity)
is decided later by the CSP, not here.

Every answer carries its path (the triples that prove it). That is the
explanation the alert shows and what the grounding check uses.

Open-world assumption: if the graph has no path, the answer is "unknown",
never an invented mitigation.
"""
from pathlib import Path

from knowledge.ontology import validate
from knowledge.triple_store import TripleStore

DEFAULT_DIR = Path(__file__).resolve().parents[2] / "data" / "kg"
SLOTS = ("network", "account", "application")

MITIGATION_RULES = [
    ("K1", "the attack itself is mitigated by it",
     [("?a", "mitigatedBy", "?m")]),
    ("K2", "its ATT&CK technique is mitigated by it",
     [("?a", "mapsTo", "?t"), ("?t", "mitigatedBy", "?m")]),
    ("K3", "it is inherited from the parent ATT&CK technique",
     [("?a", "mapsTo", "?t"), ("?t", "subTechniqueOf", "?p"), ("?p", "mitigatedBy", "?m")]),
    ("K4", "its OWASP category is mitigated by it",
     [("?a", "classifiedAs", "?w"), ("?w", "mitigatedBy", "?m")]),
]


class KnowledgeGraph(TripleStore):
    @classmethod
    def load(cls, kg_dir=DEFAULT_DIR, check: bool = True) -> "KnowledgeGraph":
        kg = cls()
        kg.load_csv(Path(kg_dir) / "ontology.csv")
        kg.load_csv(Path(kg_dir) / "facts.csv")
        if check:
            errors = validate(kg)
            if errors:
                raise ValueError("knowledge graph is inconsistent:\n  " + "\n  ".join(errors))
        return kg

    # ---------- small helpers ----------
    def label(self, thing: str) -> str:
        return self.value(thing, "label") or thing

    def is_attack(self, attack_type: str) -> bool:
        return (attack_type, "type", "AttackPattern") in self

    def _info(self, thing):
        if thing is None:
            return None
        return {"id": thing, "label": self.label(thing), "source": self.value(thing, "source")}

    # ---------- what is this attack? ----------
    def describe(self, attack_type: str) -> dict:
        if not self.is_attack(attack_type):
            return {"id": attack_type, "known": False}
        technique = self.value(attack_type, "mapsTo")
        tech = self._info(technique)
        if tech:
            tech["parent"] = self._info(self.value(technique, "subTechniqueOf"))
        return {
            "id": attack_type,
            "known": True,
            "label": self.label(attack_type),
            "description": self.value(attack_type, "description"),
            "technique": tech,
            "weakness": self._info(self.value(attack_type, "classifiedAs")),
        }

    # ---------- what mitigates it? ----------
    def mitigations(self, attack_type: str) -> list:
        """All mitigations the graph links to this attack, each with the rule
        and the path that proves it. A mitigation reachable by several rules is
        listed once, with the first (most direct) path."""
        found = {}
        for rule_id, reason, patterns in MITIGATION_RULES:
            for answer in self.query(patterns, {"?a": attack_type}):
                m = answer["?m"]
                if m in found:
                    continue
                found[m] = {
                    "id": m,
                    "label": self.label(m),
                    "description": self.value(m, "description"),
                    "source": self.value(m, "source"),
                    "rule": rule_id,
                    "reason": reason,
                    "path": [str(t) for t in answer["_triples"]],
                }
        return list(found.values())

    # ---------- which actions may we offer? ----------
    def actions(self, attack_type: str) -> dict:
        """One-tap actions the graph links to this attack, grouped by CSP slot
        (the domains of Tyler's CSP variables). Always has all three slots."""
        domains = {slot: [] for slot in SLOTS}
        seen = set()

        for m in self.mitigations(attack_type):
            for t in self.match(s=m["id"], p="implementedBy"):
                action = t.o
                if action in seen:
                    continue
                seen.add(action)
                slot = self.value(action, "actsOn")
                domains[slot].append({
                    "id": action,
                    "label": self.label(action),
                    "description": self.value(action, "description"),
                    "slot": slot,
                    "mitigation": m["id"],
                    "path": m["path"] + [str(t)],
                })
        return domains

    # ---------- grounding check ----------
    def justify(self, attack_type: str, action: str):
        """Path proving the graph links this action to this attack, or None.
        Used to check that the LLM / CSP never offers an action the graph
        does not support."""
        for m in self.mitigations(attack_type):
            t = (m["id"], "implementedBy", action)
            if t in self:
                return m["path"] + [f"({t[0]}, {t[1]}, {t[2]})"]
        return None


if __name__ == "__main__":
    # Run from repo root:  PYTHONPATH=src python -m knowledge.graph
    kg = KnowledgeGraph.load()
    print(f"{len(kg)} triples loaded, graph is consistent\n")
    for t in kg.match(p="type", o="AttackPattern"):
        d = kg.describe(t.s)
        print(f"{d['label']}  ->  {d['technique']['id']}  /  OWASP {d['weakness']['id']}")
        for m in kg.mitigations(t.s):
            print(f"   [{m['rule']}] {m['id']}")
        print()
