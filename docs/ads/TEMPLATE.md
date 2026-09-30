# ADS: <detection title>

Rule id: <uuid>
Rule file: detections/<path>
Status: <proposed | in_development | in_test | production | deprecated>
Author: <name>
Last reviewed: <YYYY-MM-DD>

All nine sections are required before a rule may move to production. An empty
section is a failed review, not a placeholder.

## 1. Goal

One sentence. What adversary behavior is this detecting and on what evidence.

## 2. Categorization

MITRE ATT&CK parent and subtechnique. Name both, for example
Command and Control / Application Layer Protocol: DNS (T1071.004).

## 3. Strategy Abstract

Walk through how the detection functions: what it looks for, which data sources
feed it, what enrichment is applied, and what false positive reduction is built
in. A reader should be able to reimplement the rule from this section alone.

## 4. Technical Context

Everything a responder needs to judge an alert without being the author.
Background on the technique, what normal looks like in this environment, which
fields matter, and links to platform or tooling documentation. Write for the
analyst at 2am who has never seen this alert before.

## 5. Blind Spots and Assumptions

Where this will not fire. Be specific and be honest. At minimum:
- Assumptions about telemetry coverage and collection
- Thresholds an adversary can stay under
- Protocol or tooling variants that bypass the logic entirely
- Hosts or segments not covered by the data source

## 6. False Positives

Known benign sources, and what suppression is applied for each. Point at the
lookup or allow list file rather than burying values in the query.

## 7. Validation

The exact, reproducible way to make this fire. A command, an Atomic test id, a
flightsim module, a Threatest scenario path, or a written manual procedure.
If validation requires approval or a change window, say so here.

## 8. Priority

Severity, and the reasoning. What the analyst should assume about urgency and
what the expected weekly volume is.

## 9. Response

What the analyst does. Triage steps, containment options, escalation criteria,
and who owns the decision. Link the runbook rather than duplicating it.

## Additional resources

References, related detections, related hunts.
