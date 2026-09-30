#!/usr/bin/env python3
"""Stamp detection_engineering.validation.last_validated after a passing run.

Reads the Threatest --output JSON, matches each passing scenario back to the
rule whose signal name it asserted, and writes today's date onto that rule.
This is what makes "percentage of rules validated in the last 30 days" a
measurement rather than a claim. Intended to run in CI and commit the diff.
"""
import argparse
import json
import pathlib
import re
import sys
from datetime import date

import yaml

import rulefile

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAST_VALIDATED = re.compile(r"^(\s+last_validated:[ \t]*).*$", re.MULTILINE)


def signal_names(scenario_path):
    """Map scenario name to the expected signal name it asserts."""
    doc = yaml.safe_load(scenario_path.read_text())
    out = {}
    for sc in doc.get("scenarios", []):
        for exp in sc.get("expectations", []):
            for matcher in ("datadogSecuritySignal", "elasticSecuritySignal"):
                if matcher in exp:
                    out[sc["name"]] = exp[matcher]["name"]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results", type=pathlib.Path)
    ap.add_argument("--scenarios", type=pathlib.Path, default=ROOT / "scenarios")
    args = ap.parse_args()

    expected = {}
    for sc in args.scenarios.rglob("*.threatest.yaml"):
        expected.update(signal_names(sc))

    passed_signals = {
        expected[r["description"]]
        for r in json.loads(args.results.read_text())
        if r.get("isSuccess") and r.get("description") in expected
    }
    if not passed_signals:
        print("no passing scenarios mapped to a signal name, nothing stamped")
        return 0

    today = date.today().isoformat()
    stamped = 0
    for path in sorted((ROOT / "detections").rglob("*.y*ml")):
        text = path.read_text()
        rule = rulefile.load_rule(path)
        if rule.get("title") not in passed_signals:
            continue
        # Quoted, because the schema requires a string and YAML reads a bare
        # ISO date as a date object.
        text, n = LAST_VALIDATED.subn(rf'\g<1>"{today}"', text, count=1)
        if not n:
            print(f"no last_validated line in {path.relative_to(ROOT)}, not stamped")
            continue
        path.write_text(text)
        stamped += 1
        print(f"stamped {path.relative_to(ROOT)} last_validated={today}")

    print(f"{stamped} rules stamped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
