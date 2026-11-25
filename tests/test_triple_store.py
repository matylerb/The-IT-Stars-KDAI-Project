"""Tests for the triple store and its pattern-matching queries."""
import pytest

from knowledge.triple_store import Triple, TripleStore

# Same example as Lecture 8
LECTURE = [
    ("Alice", "enrolledIn", "AI101"),
    ("Bob", "enrolledIn", "DS201"),
    ("AI101", "taughtBy", "DrSmith"),
    ("DrSmith", "worksAt", "UniversityX"),
]


def store():
    return TripleStore(LECTURE)


def test_duplicates_are_stored_once():
    s = TripleStore(LECTURE + [("Alice", "enrolledIn", "AI101")])
    assert len(s) == 4


def test_match_with_wildcards():
    assert store().match(p="enrolledIn", o="AI101") == [Triple("Alice", "enrolledIn", "AI101")]
    assert len(store().match(p="enrolledIn")) == 2
    assert len(store().match()) == 4


def test_value_returns_none_when_unknown():
    assert store().value("AI101", "taughtBy") == "DrSmith"
    assert store().value("DS201", "taughtBy") is None   # open world: unknown, not "nobody"


def test_query_like_sparql():
    # SELECT ?student WHERE { ?student enrolledIn AI101 }
    answers = store().query([("?student", "enrolledIn", "AI101")])
    assert [a["?student"] for a in answers] == ["Alice"]


def test_query_joins_on_shared_variables():
    # Who teaches Alice's course?  (Lecture 8 example)
    answers = store().query([("Alice", "enrolledIn", "?c"), ("?c", "taughtBy", "?t")])
    assert len(answers) == 1
    assert answers[0]["?t"] == "DrSmith"


def test_query_returns_the_triples_that_prove_the_answer():
    answer = store().query([("Alice", "enrolledIn", "?c"), ("?c", "taughtBy", "?t"),
                            ("?t", "worksAt", "?u")])[0]
    assert answer["?u"] == "UniversityX"
    assert answer["_triples"] == [Triple(*t) for t in (LECTURE[0], LECTURE[2], LECTURE[3])]


def test_query_with_no_answer_is_empty():
    assert store().query([("Bob", "enrolledIn", "?c"), ("?c", "taughtBy", "?t")]) == []


def test_starting_bindings():
    answers = store().query([("?x", "enrolledIn", "?c")], {"?x": "Bob"})
    assert answers[0]["?c"] == "DS201"


def test_remove():
    s = store()
    s.remove("Alice", "enrolledIn", "AI101")
    assert ("Alice", "enrolledIn", "AI101") not in s
    assert len(s) == 3


def test_load_csv_skips_header_comments_and_blank_lines(tmp_path):
    f = tmp_path / "t.csv"
    f.write_text('subject,predicate,object\n# a comment\n\nAlice,enrolledIn,AI101\n'
                 'AI101,label,"Intro to AI, part 1"\n')
    s = TripleStore()
    assert s.load_csv(f) == 2
    assert s.value("AI101", "label") == "Intro to AI, part 1"


def test_load_csv_rejects_broken_rows(tmp_path):
    f = tmp_path / "bad.csv"
    f.write_text("Alice,enrolledIn\n")
    with pytest.raises(ValueError):
        TripleStore().load_csv(f)
