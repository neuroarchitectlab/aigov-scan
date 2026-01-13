from __future__ import annotations
from aigov_scan.policy.dsl import Policy

SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

def _get_summary(evidence: list[dict]) -> dict:
    license_spdx = {}
    pii_total = 0
    for ev in evidence:
        if ev.get("kind") == "license":
            spdx = ev.get("payload", {}).get("detected_spdx", "Unknown")
            license_spdx[spdx] = license_spdx.get(spdx, 0) + 1
        if ev.get("kind") == "pii":
            pii_total += int(ev.get("payload", {}).get("total", 0))
    return {"license": {"spdx": license_spdx}, "pii": {"total": pii_total}}

def _match_when(summary: dict, when: dict) -> bool:
    for k, v in when.items():
        if k == "license.spdx":
            return summary["license"]["spdx"].get(v, 0) > 0
        if k == "pii.total":
            if isinstance(v, str) and v.strip() == "> 0":
                return summary["pii"]["total"] > 0
            if isinstance(v, int):
                return summary["pii"]["total"] == v
    return False

def evaluate_policy(evidence: list[dict], policy: Policy) -> tuple[list[dict], dict]:
    summary = _get_summary(evidence)
    findings: list[dict] = []
    highest = "low"
    has_fail = False
    failing_rules: list[str] = []

    for rule in policy.rules:
        triggered = _match_when(summary, rule.when)
        status = "pass"
        msg = "Rule not triggered."
        if triggered:
            status = "fail" if rule.action == "fail" else ("warn" if rule.action == "warn" else "pass")
            msg = f"Rule triggered: {rule.id}"
            if status == "fail":
                has_fail = True
                failing_rules.append(rule.id)

        findings.append({
            "evidence_id": "sha256:" + "0" * 64,
            "severity": rule.severity,
            "rule_id": rule.id,
            "status": status,
            "message": msg
        })

        if triggered and SEV_ORDER.get(rule.severity, 1) > SEV_ORDER.get(highest, 1):
            highest = rule.severity

    return findings, {"highest_severity": highest, "has_fail": has_fail, "failing_rules": failing_rules}
