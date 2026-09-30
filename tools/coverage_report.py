#!/usr/bin/env python3
"""Generate the program metrics and an ATT&CK Navigator layer.

Writes build/metrics.json and build/navigator-layer.json. The Navigator layer
scores a technique by validation state rather than by mere existence of a rule,
because an unvalidated rule is a hypothesis, not coverage.

  score 100  production and validated within the last 30 days
  score  60  production but validation is stale or unit tested only
  score  30  in development or in test
  score   0  no rule
"""
import json
import pathlib
import sys
from datetime import date, datetime

import rulefile

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"


def age_days(value):
    """YAML parses an unquoted ISO date into a date object. Accept both."""
    if not value:
        return None
    if not isinstance(value, date):
        value = datetime.strptime(str(value), "%Y-%m-%d").date()
    return (date.today() - value).days


def score(rule):
    de = rule.get("detection_engineering", {})
    stage = de.get("lifecycle", {}).get("stage")
    val = de.get("validation", {})
    validated = age_days(val.get("last_validated"))
    if stage == "production":
        if val.get("method") not in (None, "none", "unit_only") and validated is not None and validated <= 30:
            return 100
        return 60
    if stage in ("in_development", "in_test"):
        return 30
    return 0


def main():
    rules = []
    for path in sorted((ROOT / "detections").rglob("*.y*ml")):
        rule = rulefile.primary(rulefile.load_documents(path))
        if rule and rule.get("id"):
            rules.append((path.relative_to(ROOT).as_posix(), rule))

    techniques = {}
    for rel, rule in rules:
        for tag in rule.get("tags", []):
            if tag.startswith("attack.t"):
                tid = tag.split(".", 1)[1].upper()
                techniques[tid] = max(techniques.get(tid, 0), score(rule))

    total = len(rules)
    production = [r for _, r in rules if r["detection_engineering"]["lifecycle"]["stage"] == "production"]
    detonation_backed = [
        r for _, r in rules
        if r["detection_engineering"]["validation"]["method"] not in (None, "none", "unit_only", "manual")
    ]
    fresh = [
        r for _, r in rules
        if (a := age_days(r["detection_engineering"]["validation"].get("last_validated"))) is not None and a <= 30
    ]
    stale_review = [
        r for _, r in rules
        if (a := age_days(r["detection_engineering"]["lifecycle"]["last_reviewed"])) is not None
        and a > r["detection_engineering"]["lifecycle"]["review_interval_days"]
    ]

    metrics = {
        "generated": date.today().isoformat(),
        "rules_total": total,
        "rules_production": len(production),
        "rules_with_detonation_test": len(detonation_backed),
        "pct_with_detonation_test": round(100 * len(detonation_backed) / total, 1) if total else 0,
        "rules_validated_last_30d": len(fresh),
        "pct_validated_last_30d": round(100 * len(fresh) / total, 1) if total else 0,
        "rules_past_review_date": len(stale_review),
        "techniques_touched": len(techniques),
        "techniques_validated": sum(1 for v in techniques.values() if v == 100),
    }

    layer = {
        "name": "Detection coverage by validation state",
        "versions": {"layer": "4.5", "navigator": "4.9.1"},
        "domain": "enterprise-attack",
        "description": "Scored by validation freshness, not by rule existence.",
        "gradient": {"colors": ["#ffffff", "#fff3cd", "#2e7d32"], "minValue": 0, "maxValue": 100},
        "techniques": [{"techniqueID": tid, "score": s} for tid, s in sorted(techniques.items())],
    }

    BUILD.mkdir(exist_ok=True)
    (BUILD / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (BUILD / "navigator-layer.json").write_text(json.dumps(layer, indent=2))
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
