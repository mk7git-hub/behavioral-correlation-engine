"""Stateful sliding-window correlation.

A rule has an entity field (who or what the chain is about), a window, and ordered stages.
Each stage matches events and may require a count and/or a number of distinct values of a field
inside the window. The rule fires when every stage completes in order for the same entity within
the window. State is kept per (rule, entity) and expires as the window slides, so memory stays bounded.
"""
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import yaml


def _ts(v):
    return v if isinstance(v, datetime) else datetime.fromisoformat(str(v).replace("Z", "+00:00"))


def _get(event, path):
    cur = event
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def _match(cond: dict, event: dict) -> bool:
    for key, expected in cond.items():
        fld, *mods = key.split("|")
        actual = _get(event, fld)
        options = expected if isinstance(expected, list) else [expected]
        if "not" in mods:
            if actual is not None and str(actual).lower() in [str(o).lower() for o in options]:
                return False
            continue
        if actual is None:
            return False
        a = str(actual).lower()
        if "contains" in mods:
            ok = any(str(o).lower() in a for o in options)
        elif "startswith" in mods:
            ok = any(a.startswith(str(o).lower()) for o in options)
        elif "gte" in mods:
            ok = float(actual) >= float(options[0])
        else:
            ok = a in [str(o).lower() for o in options]
        if not ok:
            return False
    return True


@dataclass
class Stage:
    id: str
    match: dict
    min_count: int = 1
    distinct: str | None = None      # field whose distinct values are counted
    min_distinct: int = 0


@dataclass
class Rule:
    name: str
    entity: str
    window: timedelta
    stages: list
    severity: str = "high"
    attack: list = field(default_factory=list)
    runbook: str = ""
    atomic_severity: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path):
        d = yaml.safe_load(open(path, encoding="utf-8"))
        stages = [Stage(s["id"], s["match"], s.get("min_count", 1), s.get("distinct"), s.get("min_distinct", 0)) for s in d["stages"]]
        return cls(d["name"], d["entity"], timedelta(minutes=d["window_minutes"]), stages, d.get("severity", "high"),
                   d.get("attack", []), d.get("runbook", ""))


@dataclass
class Alert:
    rule: str
    entity: str
    first_seen: datetime
    last_seen: datetime
    evidence: dict
    severity: str
    attack: list
    runbook: str

    @property
    def scenario_ids(self):
        return {e.get("scenario") for evs in self.evidence.values() for e in evs if e.get("scenario")}


class Correlator:
    def __init__(self, rules):
        self.rules = rules
        # per rule, per entity: index of the stage in progress, and matching events kept for the window
        self.state = defaultdict(lambda: {"stage": 0, "events": defaultdict(deque), "start": None})

    def _stage_done(self, stage, events):
        if len(events) < stage.min_count:
            return False
        if stage.distinct and len({_get(e, stage.distinct) for e in events}) < stage.min_distinct:
            return False
        return True

    def process(self, event):
        alerts = []
        t = _ts(event["timestamp"])
        for rule in self.rules:
            ent = _get(event, rule.entity)
            if ent is None:
                continue
            st = self.state[(rule.name, ent)]
            # slide the window: drop events older than the window and restart the chain if its start expired
            if st["start"] and t - st["start"] > rule.window:
                st.update(stage=0, start=None)
                st["events"].clear()
            stage_idx = st["stage"]
            # an event can also re-arm earlier stages (e.g. more clones while waiting for the role assumption)
            for i in range(stage_idx + 1):
                stage = rule.stages[i]
                if _match(stage.match, event):
                    q = st["events"][stage.id]
                    q.append(event)
                    while q and t - _ts(q[0]["timestamp"]) > rule.window:
                        q.popleft()
                    if st["start"] is None:
                        st["start"] = t
            # advance through every stage that is now complete
            while st["stage"] < len(rule.stages) and self._stage_done(rule.stages[st["stage"]], st["events"][rule.stages[st["stage"]].id]):
                st["stage"] += 1
            if st["stage"] == len(rule.stages):
                evidence = {s.id: list(st["events"][s.id]) for s in rule.stages}
                first = min(_ts(e["timestamp"]) for evs in evidence.values() for e in evs)
                alerts.append(Alert(rule.name, ent, first, t, evidence, rule.severity, rule.attack, rule.runbook))
                st.update(stage=0, start=None)
                st["events"].clear()
        return alerts

    def run(self, events):
        out = []
        for e in sorted(events, key=lambda e: _ts(e["timestamp"])):
            out += self.process(e)
        return out


def atomic_alerts(rules, events):
    """What a single-event (signature) approach would raise: one alert per event matching any stage."""
    hits = []
    for e in events:
        for r in rules:
            for s in r.stages:
                if _get(e, r.entity) is not None and _match(s.match, e):
                    hits.append((r.name, s.id, e))
                    break
    return hits
