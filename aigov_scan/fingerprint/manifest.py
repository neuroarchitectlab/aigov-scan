from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone

from aigov_scan.ingest.local_fs import IngestedDataset


@dataclass(frozen=True)
class ProvenanceManifest:
    retrieved_at: str
    sources: list[dict]
    file_count: int


def build_provenance_manifest(dataset: IngestedDataset) -> ProvenanceManifest:
    retrieved_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    sources = [{
        "type": "local",
        "uri": dataset.root,
        "retrieved_at": retrieved_at
    }]
    return ProvenanceManifest(retrieved_at=retrieved_at, sources=sources, file_count=len(dataset.files))
