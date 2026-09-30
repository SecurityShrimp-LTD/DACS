#!/usr/bin/env python3
"""Deploy compiled rules to the SIEM.

Deliberately a thin stub because this is the one file that cannot be platform
neutral. Implement push() for your platform and nothing else in this repo has
to change:

  Splunk      REST /services/saved/searches, or ship a packaged app
  Sentinel    az sentinel alert-rule create, or ARM / Bicep templates
  Elastic     Kibana detection engine API, see elastic/detection-rules
  Chronicle   the rules API
  Panther     panther_analysis_tool upload

Rules are selected by lifecycle stage, so a rule sitting in in_test never
reaches production even if it is merged to main. Deployment is idempotent and
keyed on rule id, so a rerun updates rather than duplicates.
"""
import argparse
import os
import pathlib
import sys

import rulefile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def select(stages):
    for path in sorted((ROOT / "detections").rglob("*.y*ml")):
        rule = rulefile.load_rule(path)
        if rule["detection_engineering"]["lifecycle"]["stage"] in stages:
            yield path, rule


def push(rule, target, url, token):
    raise NotImplementedError(
        "implement the platform call here, keyed on rule['id'] for idempotency"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, choices=["staging", "production"])
    ap.add_argument("--stage", action="append", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    url, token = os.environ.get("SIEM_URL"), os.environ.get("SIEM_TOKEN")
    if not args.dry_run and not (url and token):
        sys.exit("SIEM_URL and SIEM_TOKEN must be set")

    count = 0
    for path, rule in select(set(args.stage)):
        print(f"{'would deploy' if args.dry_run else 'deploying'} {rule['id']} {rule['title']}")
        if not args.dry_run:
            push(rule, args.target, url, token)
        count += 1
    print(f"{count} rules targeted at {args.target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
