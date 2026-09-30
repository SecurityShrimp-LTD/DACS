"""Load a detection file.

A detection file holds one or more YAML documents. A simple rule is a single
Sigma rule. An aggregating rule is one or more base Sigma rules followed by a
Sigma correlation that references them by name. In both cases exactly one
document carries the detection_engineering block, and that document is the
detection record: its id, title and lifecycle are what the pipeline tracks,
stamps and deploys.
"""
import yaml


def load_documents(path):
    return [doc for doc in yaml.safe_load_all(path.read_text()) if doc is not None]


def primary(docs):
    """Return the document that carries detection_engineering, or None."""
    carriers = [d for d in docs if isinstance(d, dict) and "detection_engineering" in d]
    return carriers[0] if len(carriers) == 1 else None


def load_rule(path):
    """Return the detection record of a file, or raise ValueError."""
    rule = primary(load_documents(path))
    if rule is None:
        raise ValueError(f"{path}: expected exactly one document with a detection_engineering block")
    return rule
