"""
Module 6: Cloud IAM Security Review.

Loads two AWS-style IAM policies (insecure + secure) from `data/` and
computes a small risk score for each so the UI can highlight the
difference.
"""

import os
import json

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


def _load(name: str) -> dict:
    with open(os.path.join(DATA_DIR, name), "r", encoding="utf-8") as f:
        return json.load(f)


def _score(policy: dict) -> dict:
    risk = 0
    reasons = []
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action")
        if actions == "*" or (isinstance(actions, list) and "*" in actions):
            risk += 50
            reasons.append("Uses wildcard Action '*'")
        resources = stmt.get("Resource")
        if resources == "*" or (isinstance(resources, list) and "*" in resources):
            risk += 30
            reasons.append("Uses wildcard Resource '*'")
        principal = stmt.get("Principal")
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            risk += 20
            reasons.append("Principal '*' = public access")
        if "Condition" not in stmt:
            # not a problem by itself, but reduces defense-in-depth
            reasons.append("No Condition block (no extra guardrails)")

    risk = min(risk, 100)
    rating = "LOW" if risk < 25 else "MEDIUM" if risk < 60 else "HIGH"
    return {"risk_score": risk, "rating": rating, "reasons": reasons}


def compare() -> dict:
    insecure = _load("iam_insecure.json")
    secure = _load("iam_secure.json")
    return {
        "insecure": {"policy": insecure, "analysis": _score(insecure)},
        "secure":   {"policy": secure,   "analysis": _score(secure)},
        "recommendations": [
            "Always start from 'deny everything' and grant only what is needed.",
            "Avoid wildcards ('*') in Action, Resource and Principal.",
            "Use Conditions (e.g. aws:SourceVpc, aws:MultiFactorAuthPresent).",
            "Enable CloudTrail and review access with IAM Access Analyzer.",
            "Rotate keys, prefer IAM Roles + STS over long-lived access keys.",
        ],
    }
