"""
Generic constraint satisfaction solver (Lecture 5), AIMA style.

This module knows nothing about security. It defines a CSP as (X, D, C) and
solves it with backtracking search plus the Lecture 5 heuristics:

    variable ordering : MRV (fewest remaining values), Degree as tie-break
    value ordering    : LCV (value that removes the fewest neighbour options)
    inference         : forward checking, with pruned values restored on backtrack

The problem definition lives elsewhere (response/selector.py), so the same
solver could be reused for any other CSP: separation of problem and algorithm
(Lecture 1, "AIMA: separation of concerns").

Every value removed from a domain is recorded as a Prune with the constraint
that removed it and a plain-English reason. That record is the explanation
facility for the response selector (Lecture 8): it answers "why was this
action not offered?".
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Callable, Dict, Hashable, Iterable, List, Optional, Sequence, Tuple

Value = Hashable
Assignment = Dict[str, Value]


@dataclass(frozen=True)
class Constraint:
    """A constraint C_i = <scope, relation>.

    `predicate` receives the values of the variables in `scope`, in order, and
    returns True when the combination is allowed. `reason` is shown to the user
    when this constraint removes a value, so write it for a non-expert.
    """
    id: str
    scope: Tuple[str, ...]
    predicate: Callable[..., bool]
    reason: str = ""

    @property
    def kind(self) -> str:
        n = len(self.scope)
        return {1: "unary", 2: "binary", 3: "ternary"}.get(n, "global")

    def holds(self, assignment: Assignment) -> bool:
        """True if satisfied, or if not every variable in the scope is assigned yet."""
        if not all(v in assignment for v in self.scope):
            return True
        return bool(self.predicate(*(assignment[v] for v in self.scope)))


@dataclass(frozen=True)
class Prune:
    """One value removed from one domain, and why."""
    variable: str
    value: Value
    constraint: str
    reason: str
    stage: str  # "node_consistency" or "forward_checking"


@dataclass
class SearchStats:
    nodes: int = 0          # values tried
    backtracks: int = 0     # assignments undone because no solution lay below them
    prunes: List[Prune] = field(default_factory=list)


class CSP:
    """CSP = (X, D, C).

    variables   : X, an ordered list of variable names
    domains     : D, variable -> list of values (list order = preference order)
    constraints : C, any arity; unary ones are applied by node consistency
    """

    def __init__(self, variables: Sequence[str], domains: Dict[str, Iterable[Value]],
                 constraints: Sequence[Constraint]):
        self.variables = list(variables)
        self.domains: Dict[str, List[Value]] = {v: list(domains[v]) for v in self.variables}
        self.constraints = list(constraints)

        unknown = {v for c in self.constraints for v in c.scope} - set(self.variables)
        if unknown:
            raise ValueError(f"constraints mention unknown variables: {sorted(unknown)}")

        self.constraints_on: Dict[str, List[Constraint]] = {v: [] for v in self.variables}
        self.neighbours: Dict[str, set] = {v: set() for v in self.variables}
        for c in self.constraints:
            for v in c.scope:
                self.constraints_on[v].append(c)
                self.neighbours[v].update(u for u in c.scope if u != v)

    # --- checking -----------------------------------------------------------

    def violated(self, var: str, value: Value, assignment: Assignment) -> Optional[Constraint]:
        """First constraint on `var` broken by adding var=value, else None."""
        trial = {**assignment, var: value}
        for c in self.constraints_on[var]:
            if not c.holds(trial):
                return c
        return None

    def is_solution(self, assignment: Assignment) -> bool:
        return (len(assignment) == len(self.variables)
                and all(c.holds(assignment) for c in self.constraints))


# --- naive search, for comparison and testing ---------------------------------

def enumerate_solutions(csp: CSP) -> List[Assignment]:
    """Generate-and-test over every complete assignment (d^n of them).

    Lecture 5's "naive search: try everything". Used in tests to prove the
    backtracking solver is sound and complete on our problems.
    """
    out = []
    for values in itertools.product(*(csp.domains[v] for v in csp.variables)):
        a = dict(zip(csp.variables, values))
        if csp.is_solution(a):
            out.append(a)
    return out


# --- backtracking with heuristics and forward checking ------------------------

class BacktrackingSolver:
    """Backtracking search with MRV + Degree, LCV and forward checking.

    `current` holds the live domains. Every removal is pushed onto a removal
    list for the current level and undone when that level backtracks, so
    values pruned in an abandoned branch reappear in later branches
    (the restoration point stressed on Lecture 5's MAC slide).
    """

    def __init__(self, csp: CSP, use_mrv: bool = True, use_lcv: bool = True,
                 forward_check: bool = True):
        self.csp = csp
        self.use_mrv = use_mrv
        self.use_lcv = use_lcv
        self.forward_check = forward_check
        self.current: Dict[str, List[Value]] = {}
        self.stats = SearchStats()

    # -- setup: node consistency for unary constraints --

    def _node_consistency(self) -> None:
        for var in self.csp.variables:
            for c in self.csp.constraints_on[var]:
                if len(c.scope) != 1:
                    continue
                for value in list(self.current[var]):
                    if not c.predicate(value):
                        self.current[var].remove(value)
                        self.stats.prunes.append(
                            Prune(var, value, c.id, c.reason, "node_consistency"))

    # -- variable ordering --

    def _unassigned_degree(self, var: str, assignment: Assignment) -> int:
        return sum(1 for n in self.csp.neighbours[var] if n not in assignment)

    def select_unassigned_variable(self, assignment: Assignment) -> str:
        unassigned = [v for v in self.csp.variables if v not in assignment]
        if not self.use_mrv:
            return unassigned[0]
        # MRV: argmin |D_current|; Degree: argmax unassigned neighbours on ties.
        # Ties after both keep the declared variable order (min is stable).
        return min(unassigned, key=lambda v: (len(self.current[v]),
                                              -self._unassigned_degree(v, assignment)))

    # -- value ordering --

    def impact(self, var: str, value: Value, assignment: Assignment) -> int:
        """LCV impact: neighbour values ruled out by choosing var=value."""
        trial = {**assignment, var: value}
        removed = 0
        for n in self.csp.neighbours[var]:
            if n in assignment:
                continue
            for nv in self.current[n]:
                if self.csp.violated(n, nv, trial) is not None:
                    removed += 1
        return removed

    def order_domain_values(self, var: str, assignment: Assignment) -> List[Value]:
        values = list(self.current[var])
        if not self.use_lcv:
            return values
        # sorted() is stable, so equal impact keeps the domain's preference order
        return sorted(values, key=lambda val: self.impact(var, val, assignment))

    # -- inference --

    def _forward_check(self, var: str, assignment: Assignment,
                       removals: List[Tuple[str, Value]]) -> bool:
        """Prune neighbours that are the last unassigned variable of a constraint.

        For binary constraints this is classic forward checking. For n-ary
        (global) constraints we check once all but one variable is assigned.
        Returns False if some domain becomes empty (dead end).
        """
        for c in self.csp.constraints_on[var]:
            pending = [u for u in c.scope if u not in assignment]
            if len(pending) != 1:
                continue
            n = pending[0]
            for nv in list(self.current[n]):
                if not c.holds({**assignment, n: nv}):
                    self.current[n].remove(nv)
                    removals.append((n, nv))
                    self.stats.prunes.append(
                        Prune(n, nv, c.id, c.reason, "forward_checking"))
            if not self.current[n]:
                return False
        return True

    def _restore(self, removals: List[Tuple[str, Value]]) -> None:
        for n, nv in reversed(removals):
            # put the value back in its original preference position
            order = self.csp.domains[n]
            self.current[n].append(nv)
            self.current[n].sort(key=order.index)

    # -- search --

    def solve(self, find_all: bool = False) -> List[Assignment]:
        """Return the first solution (as a one-item list) or every solution."""
        self.current = {v: list(d) for v, d in self.csp.domains.items()}
        self.stats = SearchStats()
        self._node_consistency()
        solutions: List[Assignment] = []
        if all(self.current[v] for v in self.csp.variables):
            self._backtrack({}, solutions, find_all)
        return solutions

    def _backtrack(self, assignment: Assignment, solutions: List[Assignment],
                   find_all: bool) -> bool:
        if len(assignment) == len(self.csp.variables):
            solutions.append(dict(assignment))
            return not find_all          # stop at the first one unless enumerating

        var = self.select_unassigned_variable(assignment)
        for value in self.order_domain_values(var, assignment):
            self.stats.nodes += 1
            if self.csp.violated(var, value, assignment) is not None:
                continue
            assignment[var] = value
            removals: List[Tuple[str, Value]] = []
            found_before = len(solutions)
            ok = self._forward_check(var, assignment, removals) if self.forward_check else True
            if ok and self._backtrack(assignment, solutions, find_all):
                return True
            self._restore(removals)
            del assignment[var]
            if len(solutions) == found_before:
                self.stats.backtracks += 1   # a dead end: this branch held no solution
        return False
