from __future__ import annotations
from datetime import datetime, timezone

from aigov_scan.ingest.local_fs import IngestedDataset
from aigov_scan.fingerprint.manifest import ProvenanceManifest
from aigov_scan.output._hashing import canonical_sha256

def detect_pii_stub(dataset: IngestedDataset, manifest: ProvenanceManifest) -> list[dict]:
    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {"email": 0, "phone": 0, "ip": 0, "address": 0, "total": 0}
    h = canonical_sha256(payload)
    return [{
        "evidence_id": h,
        "asset_id": dataset.asset_id,
        "kind": "pii",
        "tool": "pii-detector-stub",
        "timestamp": ts,
        "schema_version": "1.0",
        "payload": payload,
        "hash": h
    }]
