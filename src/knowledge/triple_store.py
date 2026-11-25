"""
Triple store with pattern-matching queries (Lecture 8).

A knowledge graph is a set of triples (subject, predicate, object), e.g.

    (brute_force, mapsTo, T1110.001)

Two ways to ask questions:

1. match(s, p, o): None means "anything".
       store.match(p="mapsTo")             -> every mapsTo triple
       store.match(s="brute_force")        -> everything about brute_force

2. query(patterns): several patterns joined by shared variables (words
   starting with "?"), like a small SPARQL query:

       store.query([("?a", "mapsTo", "?t"),
                    ("?t", "mitigatedBy", "?m")])

   returns one dict per answer, e.g. {"?a": "brute_force", "?t": "T1110", "?m": "..."}
   Each answer also says which triples matched (key "_triples"), so the
   caller can show WHY the answer is true.
"""
import csv
from pathlib import Path
from typing import Iterable, List, NamedTuple, Optional


class Triple(NamedTuple):
    s: str
    p: str
    o: str

    def __str__(self):
        return f"({self.s}, {self.p}, {self.o})"


def is_var(term: str) -> bool:
    return isinstance(term, str) and term.startswith("?")


class TripleStore:
    def __init__(self, triples: Iterable = ()):
        self.triples = []        # list keeps the order they were added
        self._seen = set()       # fast duplicate check
        for t in triples:
            self.add(*t)

    # ---------- adding and removing ----------
    def add(self, s: str, p: str, o: str) -> None:
        t = Triple(s.strip(), p.strip(), o.strip())
        if t not in self._seen:
            self._seen.add(t)
            self.triples.append(t)

    def remove(self, s: str, p: str, o: str) -> None:
        t = Triple(s, p, o)
        if t in self._seen:
            self._seen.remove(t)
            self.triples.remove(t)

    def load_csv(self, path) -> int:
        """Read a CSV with columns subject,predicate,object.
        Empty lines and lines starting with # are skipped. Returns triples added."""
        before = len(self.triples)
        with open(Path(path), newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
                    continue
                if row[0].strip() == "subject":        # header line
                    continue
                if len(row) != 3:
                    raise ValueError(f"{path}: expected 3 columns, got {row}")
                self.add(*row)
        return len(self.triples) - before

    def __len__(self):
        return len(self.triples)

    def __contains__(self, triple) -> bool:
        return Triple(*triple) in self._seen

    # ---------- questions ----------
    def match(self, s: Optional[str] = None, p: Optional[str] = None,
              o: Optional[str] = None) -> List[Triple]:
        return [t for t in self.triples
                if (s is None or t.s == s) and (p is None or t.p == p)
                and (o is None or t.o == o)]

    def value(self, s: str, p: str) -> Optional[str]:
        """First object for (s, p, ?), or None if the graph does not say."""
        found = self.match(s=s, p=p)
        return found[0].o if found else None

    def query(self, patterns: list, bindings: Optional[dict] = None) -> List[dict]:
        """Answer a list of (s, p, o) patterns with ?variables.
        A variable must have the same value in every pattern it appears in."""
        results = []
        self._solve(list(patterns), dict(bindings or {}), [], results)
        return results

    def _solve(self, patterns, bindings, used, results) -> None:
        if not patterns:
            results.append({**bindings, "_triples": list(used)})
            return
        first, rest = patterns[0], patterns[1:]
        # replace variables we already know with their values
        s, p, o = (bindings.get(term, term) if is_var(term) else term for term in first)
        for t in self.match(None if is_var(s) else s,
                            None if is_var(p) else p,
                            None if is_var(o) else o):
            new = dict(bindings)
            for term, val in zip((s, p, o), t):
                if is_var(term):
                    new[term] = val
            self._solve(rest, new, used + [t], results)
