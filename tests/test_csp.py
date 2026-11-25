"""Tests for the generic CSP solver (src/response/csp.py), using Lecture 5's examples."""
import random

from response.csp import CSP, BacktrackingSolver, Constraint, enumerate_solutions


def as_set(solutions):
    return {tuple(sorted(s.items())) for s in solutions}


def dinner_party():
    # Lecture 5: Alice not in seat 3, Charlie not in seat 1, Bob next to Alice, all different
    return CSP(
        ["A", "B", "C"],
        {v: [1, 2, 3] for v in "ABC"},
        [
            Constraint("alice", ("A",), lambda a: a != 3),
            Constraint("charlie", ("C",), lambda c: c != 1),
            Constraint("next", ("A", "B"), lambda a, b: abs(a - b) == 1),
            Constraint("alldiff", ("A", "B", "C"), lambda a, b, c: len({a, b, c}) == 3),
        ],
    )


def test_dinner_party_matches_naive_search():
    csp = dinner_party()
    solutions = BacktrackingSolver(csp).solve(find_all=True)
    assert as_set(solutions) == as_set(enumerate_solutions(csp))
    assert {"A": 1, "B": 2, "C": 3} in solutions


def test_map_colouring_triangle_has_six_solutions():
    csp = CSP(
        ["A", "B", "C"],
        {v: ["R", "G", "B"] for v in "ABC"},
        [Constraint(f"{x}{y}", (x, y), lambda a, b: a != b) for x, y in ("AB", "BC", "AC")],
    )
    assert len(BacktrackingSolver(csp).solve(find_all=True)) == 6


def test_first_solution_only_returns_one():
    sols = BacktrackingSolver(dinner_party()).solve()
    assert len(sols) == 1 and dinner_party().is_solution(sols[0])


def test_mrv_picks_variable_with_fewest_values():
    # Lecture 5 timetabling: Physics only fits room B, so MRV picks it first
    csp = CSP(
        ["Maths", "Physics", "Chemistry"],
        {"Maths": ["A", "B", "C"], "Physics": ["B"], "Chemistry": ["A", "C"]},
        [Constraint("mp", ("Maths", "Physics"), lambda a, b: a != b)],
    )
    solver = BacktrackingSolver(csp)
    solver.current = {v: list(d) for v, d in csp.domains.items()}
    assert solver.select_unassigned_variable({}) == "Physics"


def test_degree_breaks_mrv_tie():
    # A and B both have 2 values; A constrains three others, B one
    csp = CSP(
        ["B", "A", "C", "D", "E"],
        {"A": [1, 2], "B": [1, 2], "C": [1, 2, 3], "D": [1, 2, 3], "E": [1, 2, 3]},
        [Constraint(f"A{x}", ("A", x), lambda a, b: a != b) for x in "CDE"]
        + [Constraint("BC", ("B", "C"), lambda a, b: a != b)],
    )
    solver = BacktrackingSolver(csp)
    solver.current = {v: list(d) for v, d in csp.domains.items()}
    assert solver.select_unassigned_variable({}) == "A"


def test_lcv_orders_values_by_impact():
    # Lecture 5 rooms example: impact(A)=2, impact(B)=1, impact(C)=1
    csp = CSP(
        ["X", "Y", "Z"],
        {"X": ["A", "B", "C"], "Y": ["A", "B"], "Z": ["A", "C"]},
        [Constraint("XY", ("X", "Y"), lambda a, b: a != b),
         Constraint("XZ", ("X", "Z"), lambda a, b: a != b)],
    )
    solver = BacktrackingSolver(csp)
    solver.current = {v: list(d) for v, d in csp.domains.items()}
    assert [solver.impact("X", v, {}) for v in "ABC"] == [2, 1, 1]
    assert solver.order_domain_values("X", {}) == ["B", "C", "A"]


def test_forward_checking_restores_pruned_values_on_backtrack():
    # X=1 prunes Y=2 (C_a) and empties Z (C_b) -> dead end. The only solution
    # needs Y=2, so it is found only if that pruned value is restored.
    csp = CSP(
        ["X", "Y", "Z"],
        {"X": [1, 2], "Y": [2, 3], "Z": [1]},
        [Constraint("C_a", ("X", "Y"), lambda x, y: y != x + 1),
         Constraint("C_b", ("X", "Z"), lambda x, z: z != x)],
    )
    solver = BacktrackingSolver(csp, use_mrv=False, use_lcv=False)
    assert solver.solve(find_all=True) == [{"X": 2, "Y": 2, "Z": 1}]
    assert solver.stats.backtracks >= 1
    assert any(p.constraint == "C_a" and p.variable == "Y" and p.value == 2
               for p in solver.stats.prunes)


def test_unary_constraints_applied_by_node_consistency():
    solver = BacktrackingSolver(dinner_party())
    solver.solve()
    stages = {(p.constraint, p.stage) for p in solver.stats.prunes}
    assert ("alice", "node_consistency") in stages
    assert ("charlie", "node_consistency") in stages


def test_unsatisfiable_returns_empty():
    # three mutually different variables, two values (Lecture 5's arc-consistency example)
    csp = CSP(
        ["A", "B", "C"],
        {v: [1, 2] for v in "ABC"},
        [Constraint(f"{x}{y}", (x, y), lambda a, b: a != b) for x, y in ("AB", "BC", "AC")],
    )
    assert BacktrackingSolver(csp).solve(find_all=True) == []


def test_unknown_variable_in_constraint_rejected():
    try:
        CSP(["A"], {"A": [1]}, [Constraint("bad", ("A", "Q"), lambda a, q: True)])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_solver_is_sound_and_complete_on_random_csps():
    # Same solution set as generate-and-test, with every heuristic combination
    rng = random.Random(7)
    for _ in range(40):
        names = ["V1", "V2", "V3", "V4"]
        domains = {v: rng.sample(range(5), rng.randint(1, 4)) for v in names}
        constraints = []
        for i, (x, y) in enumerate((x, y) for x in names for y in names if x < y):
            if rng.random() < 0.6:
                allowed = {(a, b) for a in range(5) for b in range(5) if rng.random() < 0.6}
                constraints.append(Constraint(f"c{i}", (x, y),
                                              lambda a, b, allowed=allowed: (a, b) in allowed))
        csp = CSP(names, domains, constraints)
        expected = as_set(enumerate_solutions(csp))
        for mrv in (True, False):
            for lcv in (True, False):
                for fc in (True, False):
                    got = BacktrackingSolver(csp, mrv, lcv, fc).solve(find_all=True)
                    assert as_set(got) == expected
