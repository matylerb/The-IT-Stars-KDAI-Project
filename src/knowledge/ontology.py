"""
Checks the facts against the ontology.

The ontology (data/kg/ontology.csv) says which classes exist and, for each
property, what its subject (domain) and object (range) must be. For example:

    mapsTo  domain AttackPattern   range Technique

so (brute_force, mapsTo, T1110.001) is valid only if brute_force is an
AttackPattern and T1110.001 is a Technique. A typo like
(brute_force, mapsTo, T1110.01) is caught because T1110.01 has no type.

This keeps hand-written knowledge consistent (Lecture 8: a contradiction or a
broken link in the knowledge base gives wrong conclusions).
"""
from knowledge.triple_store import TripleStore

LITERAL = "Literal"
BUILT_IN = {"type", "domain", "range"}


def classes(store: TripleStore) -> set:
    return {t.s for t in store.match(p="type", o="Class")}


def properties(store: TripleStore) -> set:
    return {t.s for t in store.match(p="type", o="Property")}


def types_of(store: TripleStore, thing: str) -> set:
    return {t.o for t in store.match(s=thing, p="type")}


def validate(store: TripleStore) -> list:
    """Return a list of problems (empty list = the graph is consistent)."""
    errors = []
    known_classes = classes(store)
    known_props = properties(store)
    schema = known_classes | known_props

    individuals = set()
    for t in store.triples:
        if t.s in schema:
            continue                      # ontology line, not a fact
        individuals.add(t.s)

        if t.p == "type":
            if t.o not in known_classes:
                errors.append(f"{t}: unknown class {t.o!r}")
            continue

        if t.p not in known_props:
            errors.append(f"{t}: unknown property {t.p!r}")
            continue

        domains = {x.o for x in store.match(s=t.p, p="domain")}
        if domains and not (types_of(store, t.s) & domains):
            errors.append(f"{t}: subject should be one of {sorted(domains)}")

        ranges = {x.o for x in store.match(s=t.p, p="range")}
        if ranges and LITERAL not in ranges and not (types_of(store, t.o) & ranges):
            errors.append(f"{t}: object should be one of {sorted(ranges)}")

    for ind in sorted(individuals):
        if not types_of(store, ind):
            errors.append(f"{ind}: has no type")
        # attackers are IPs learned from feedback, they need no label
        elif not store.value(ind, "label") and "Attacker" not in types_of(store, ind):
            errors.append(f"{ind}: has no label")
    return errors
