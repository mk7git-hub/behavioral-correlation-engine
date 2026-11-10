from datetime import timedelta

from bce.engine import Correlator, Rule, Stage, atomic_alerts
from bce.evaluate import evaluate
from bce.synth import generate


def rule(window=60):
    return Rule("chain", "actor", timedelta(minutes=window), [
        Stage("a", {"action": "token"}),
        Stage("b", {"action": "clone"}, min_count=3, distinct="repo", min_distinct=3),
        Stage("c", {"action": "role", "new_ip": True}),
    ])


def ev(m, action, actor="u1", **kw):
    return {"timestamp": f"2026-10-01T10:{m:02d}:00+00:00", "action": action, "actor": actor, **kw}


def test_fires_on_complete_ordered_chain():
    events = [ev(0, "token"), ev(1, "clone", repo="r1"), ev(2, "clone", repo="r2"), ev(3, "clone", repo="r3"), ev(5, "role", new_ip=True)]
    alerts = Correlator([rule()]).run(events)
    assert len(alerts) == 1 and alerts[0].entity == "u1"


def test_needs_distinct_values_not_just_count():
    events = [ev(0, "token")] + [ev(i, "clone", repo="same") for i in range(1, 6)] + [ev(7, "role", new_ip=True)]
    assert Correlator([rule()]).run(events) == []


def test_out_of_order_does_not_fire():
    events = [ev(0, "role", new_ip=True), ev(1, "token"), ev(2, "clone", repo="r1"), ev(3, "clone", repo="r2"), ev(4, "clone", repo="r3")]
    assert Correlator([rule()]).run(events) == []


def test_window_expiry_resets_chain():
    events = [ev(0, "token"), ev(1, "clone", repo="r1"), ev(2, "clone", repo="r2"), ev(3, "clone", repo="r3"),
              {"timestamp": "2026-10-01T12:30:00+00:00", "action": "role", "actor": "u1", "new_ip": True}]
    assert Correlator([rule(window=60)]).run(events) == []


def test_entities_do_not_mix():
    events = [ev(0, "token", actor="u1"), ev(1, "clone", actor="u2", repo="r1"), ev(2, "clone", actor="u2", repo="r2"),
              ev(3, "clone", actor="u2", repo="r3"), ev(4, "role", actor="u1", new_ip=True)]
    assert Correlator([rule()]).run(events) == []


def test_atomic_counts_every_matching_event():
    events = [ev(0, "token"), ev(1, "clone", repo="r1"), ev(2, "noise")]
    assert len(atomic_alerts([rule()], events)) == 2


def test_tuned_rules_catch_all_attacks_without_false_positives(tmp_path):
    rows = {r["rule"]: r for r in evaluate("rules", generate(seed=7))}
    for name, r in rows.items():
        assert r["recall"] == "3/3", name
        assert r["fp"] == 0, name


def test_v1_rules_show_the_false_positives_that_motivated_tuning():
    rows = evaluate("rules/v1", generate(seed=7))
    assert sum(r["fp"] for r in rows) > 0
