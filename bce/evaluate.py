"""Measure composite rules against single-event alerting on labeled data.

Metrics per rule: atomic (single-event) alert volume, composite alerts, true and false positives,
recall on injected attack chains, precision, signal-to-noise (TP:FP), alert reduction versus atomic,
and time to detect (first malicious event to composite alert).
"""
import argparse
import json
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .engine import Correlator, Rule, atomic_alerts

SCENARIO_PREFIX = {"token-to-cloud-theft": "ATTACK-token", "ransomware-precursor": "ATTACK-ransom", "spray-to-mailbox-access": "ATTACK-spray"}


def _ts(s):
    return datetime.fromisoformat(s)


def evaluate(rules_dir, events):
    rules = [Rule.load(p) for p in sorted(Path(rules_dir).glob("*.yml"))]
    alerts = Correlator(rules).run(events)
    atomic = atomic_alerts(rules, events)
    first_seen = defaultdict(lambda: None)
    for e in events:
        s = e.get("scenario")
        if s and (first_seen[s] is None or e["timestamp"] < first_seen[s]):
            first_seen[s] = e["timestamp"]
    rows = []
    for r in rules:
        prefix = SCENARIO_PREFIX[r.name]
        injected = {s for s in first_seen if s.startswith(prefix)}
        mine = [a for a in alerts if a.rule == r.name]
        tp = [a for a in mine if any(s.startswith(prefix) for s in a.scenario_ids)]
        fp = [a for a in mine if a not in tp]
        found = {s for a in tp for s in a.scenario_ids if s.startswith(prefix)}
        atomic_n = sum(1 for name, _, _ in atomic if name == r.name)
        atomic_attack = sum(1 for name, _, e in atomic if name == r.name and str(e.get("scenario", "")).startswith(prefix))
        ttd = [(a.last_seen - _ts(first_seen[s])).total_seconds() / 60 for a in tp for s in a.scenario_ids if s in found]
        rows.append({
            "rule": r.name, "atomic_alerts": atomic_n, "atomic_alerts_from_attacks": atomic_attack,
            "composite_alerts": len(mine), "tp": len(tp), "fp": len(fp),
            "recall": f"{len(found)}/{len(injected)}", "precision": round(len(tp) / len(mine), 2) if mine else None,
            "snr": f"{len(tp)}:{len(fp)}", "alert_reduction_pct": round(100 * (1 - len(mine) / atomic_n), 2) if atomic_n else None,
            "median_minutes_to_detect": round(statistics.median(ttd), 1) if ttd else None,
            "fp_examples": sorted({str(a.entity) for a in fp})[:5],
        })
    return rows


def table(title, rows):
    out = [f"### {title}", "", "| Rule | Single-event alerts | Composite alerts | TP | FP | Recall | Precision | SNR (TP:FP) | Alert reduction | Median time to detect |",
           "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        prec = "–" if r["precision"] is None else f"{r['precision']:.2f}"
        mttd = "–" if r["median_minutes_to_detect"] is None else f"{r['median_minutes_to_detect']} min"
        out.append(f"| {r['rule']} | {r['atomic_alerts']:,} ({r['atomic_alerts_from_attacks']} from attacks) | {r['composite_alerts']} | {r['tp']} | {r['fp']} | "
                   f"{r['recall']} | {prec} | {r['snr']} | {r['alert_reduction_pct']}% | {mttd} |")
    return "\n".join(out) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--events", default="data/events.jsonl")
    p.add_argument("--out", default="reports/evaluation.md")
    a = p.parse_args(argv)
    events = [json.loads(line) for line in open(a.events)]
    v1, final = evaluate("rules/v1", events), evaluate("rules", events)
    md = ["# Evaluation", "", f"Dataset: {len(events):,} events over 14 days (seeded synthetic, labeled): 9 injected attack chains, "
          "11 near-miss benign chains, plus realistic background noise.", "", table("v1 (first draft)", v1), table("Tuned", final),
          "False-positive entities (tuned): " + "; ".join(f"{r['rule']}: {r['fp_examples'] or 'none'}" for r in final), ""]
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text("\n".join(md))
    Path(a.out).with_suffix(".json").write_text(json.dumps({"v1": v1, "tuned": final}, indent=2))
    print("\n".join(md))
    return v1, final


if __name__ == "__main__":
    main()
