from __future__ import annotations
from pathlib import Path
import json

from aigov_scan.ingest.local_fs import IngestedDataset
from aigov_scan.fingerprint.manifest import ProvenanceManifest

def write_datacard(path: Path,
                   dataset: IngestedDataset,
                   manifest: ProvenanceManifest,
                   evidence: list[dict],
                   findings: list[dict],
                   evidence_ids: list[str]) -> None:
    spdx = {}
    pii = {"email": 0, "phone": 0, "ip": 0, "address": 0, "total": 0}

    for ev in evidence:
        if ev.get("kind") == "license":
            detected = ev.get("payload", {}).get("detected_spdx", "Unknown")
            spdx[detected] = spdx.get(detected, 0) + 1
        if ev.get("kind") == "pii":
            pii = ev.get("payload", pii)

    total = sum(spdx.values()) or 1
    spdx_percent = {k: round(v * 100.0 / total, 2) for k, v in spdx.items()}
    unknown_percent = float(spdx_percent.get("Unknown", 0.0))

    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    highest = "low"
    failing = []
    for f in findings:
        if f.get("status") == "fail":
            failing.append(f.get("rule_id"))
        sev = f.get("severity", "low")
        if order.get(sev, 1) > order.get(highest, 1):
            highest = sev

    obj = {
        "datacard_version": "1.0",
        "dataset": {
            "name": dataset.name,
            "asset_id": dataset.asset_id,
            "created_at": dataset.created_at,
            "size_bytes": dataset.size_bytes,
            "file_count": len(dataset.files),
        },
        "provenance": {"sources": manifest.sources},
        "license_summary": {"spdx": spdx_percent, "unknown_percent": unknown_percent},
        "pii_summary": pii,
        "risk_summary": {"highest_severity": highest, "failing_rules": failing},
        "evidence_refs": evidence_ids
    }
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
