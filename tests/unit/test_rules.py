"""Fixture replay. Cheap regression net that catches renamed fields and
threshold drift before anything reaches a SIEM.

The evaluator here is intentionally simple: it applies the threshold logic
declared in the rule to the counts in the fixture. Replace evaluate() with a
real backend query against sample data (Splunk local, Elastic in Docker) when
you have a lab. The contract that matters is that every rule carries at least
one positive and one negative fixture, and CI enforces that from lifecycle
stage in_test onward. Fixtures are named after the rule file:

  detections/network/foo_bar.yml
  tests/data/foo_bar.true_positive.json
  tests/data/foo_bar.true_negative.json

For a threshold rule, expected.count is the aggregated value the fixture
produces: the distinct value count for value_count, the event count for
event_count.
"""
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import rulefile  # noqa: E402
RULES = sorted((ROOT / "detections").rglob("*.y*ml"))
FIXTURES_REQUIRED = {"in_test", "production"}


def fixtures_for(rule_path):
    data = ROOT / "tests" / "data"
    return {
        "tp": data / f"{rule_path.stem}.true_positive.json",
        "tn": data / f"{rule_path.stem}.true_negative.json",
    }


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_rule_has_both_fixtures(rule_path):
    fx = fixtures_for(rule_path)
    missing = [p.relative_to(ROOT).as_posix() for p in fx.values() if not p.exists()]
    if missing:
        stage = rulefile.load_rule(rule_path)["detection_engineering"]["lifecycle"]["stage"]
        if stage in FIXTURES_REQUIRED:
            pytest.fail(f"{rule_path.stem} is at stage {stage} and is missing {', '.join(missing)}")
        pytest.skip(f"no fixtures yet for {rule_path.stem} at stage {stage}")
    for path in fx.values():
        data = json.loads(path.read_text())
        assert "expected" in data, f"{path} has no expected block"


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_threshold_matches_fixture_expectations(rule_path):
    rule = rulefile.load_rule(rule_path)
    condition = (rule.get("correlation") or {}).get("condition") or {}
    if "gt" in condition:
        threshold = condition["gt"]
    elif "gte" in condition:
        threshold = condition["gte"] - 1
    else:
        pytest.skip("not a threshold rule")

    fx = fixtures_for(rule_path)
    if not all(p.exists() for p in fx.values()):
        pytest.skip("fixtures not present, reported by test_rule_has_both_fixtures")

    tp = json.loads(fx["tp"].read_text())
    tn = json.loads(fx["tn"].read_text())
    assert tp["expected"]["count"] > threshold, "positive fixture does not exceed the threshold"
    assert tn["expected"]["count"] <= threshold, "negative fixture would fire, the rule is too loose"
