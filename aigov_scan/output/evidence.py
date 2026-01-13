from __future__ import annotations
from pathlib import Path
import json

def write_evidence_bundle(dir_path: Path, evidence: list[dict]) -> list[str]:
    dir_path.mkdir(parents=True, exist_ok=True)
    ids = []
    for i, ev in enumerate(evidence, start=1):
        p = dir_path / f"{ev['kind']}_{i:03d}.json"
        p.write_text(json.dumps(ev, indent=2, sort_keys=True), encoding="utf-8")
        ids.append(ev["evidence_id"])
    (dir_path / "manifest.json").write_text(
        json.dumps({"count": len(evidence), "evidence_ids": ids}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return ids
