from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from aigov_scan.ingest.local_fs import IngestedDataset
from aigov_scan.fingerprint.manifest import ProvenanceManifest
from aigov_scan.utils.text import normalize_text, safe_read_text
from aigov_scan.detectors.license_db import LICENSE_SIGNALS, MIN_CONFIDENCE
from aigov_scan.output._hashing import canonical_sha256

LICENSE_FILENAMES = ("license", "copying", "notice")
README_PREFIXES = ("readme",)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _is_license_file(name: str) -> bool:
    n = name.lower()
    return any(n == x or n.startswith(x + ".") for x in LICENSE_FILENAMES)

def _is_readme(name: str) -> bool:
    n = name.lower()
    return any(n == p or n.startswith(p + ".") for p in README_PREFIXES)

def _pick_candidate_paths(dataset: IngestedDataset) -> list[str]:
    root_files = [f.path for f in dataset.files if "/" not in f.path and "\\" not in f.path]
    license_files = [p for p in root_files if _is_license_file(Path(p).name)]
    readmes = [p for p in root_files if _is_readme(Path(p).name)]
    return license_files + readmes

def _score_license(text_norm: str) -> tuple[str, float, list[str]]:
    best_spdx = "Unknown"
    best_conf = 0.0
    best_signals: list[str] = []

    for spdx, signals in LICENSE_SIGNALS.items():
        matched = [sig for sig in signals if sig in text_norm]
        if not matched:
            continue
        conf = len(matched) / max(1, len(signals))
        if conf > best_conf:
            best_conf = conf
            best_spdx = spdx
            best_signals = matched

    if best_spdx == "Unknown":
        if "all rights reserved" in text_norm or "proprietary" in text_norm:
            return "Proprietary", 0.7, ["all rights reserved/proprietary"]

    return best_spdx, best_conf, best_signals

def detect_licenses_mvp(dataset: IngestedDataset, manifest: ProvenanceManifest) -> list[dict]:
    ts = _now()
    root = Path(dataset.root)

    candidates = _pick_candidate_paths(dataset)
    paths_scanned: list[str] = []
    combined_text = ""

    for rel in candidates:
        p = root / rel
        if not p.exists() or not p.is_file():
            continue
        paths_scanned.append(rel)
        combined_text += "\n" + safe_read_text(p)

    text_norm = normalize_text(combined_text) if combined_text else ""
    spdx, conf, signals = _score_license(text_norm)

    if spdx != "Unknown" and conf < MIN_CONFIDENCE:
        spdx, conf, signals = "Unknown", 0.0, []

    payload = {
        "scope": "dataset",
        "paths_scanned": paths_scanned,
        "detected_spdx": spdx,
        "confidence": round(conf, 2),
        "method": "text_fuzzy" if paths_scanned else "none",
        "matched_signals": signals
    }
    h = canonical_sha256(payload)

    return [{
        "evidence_id": h,
        "asset_id": dataset.asset_id,
        "kind": "license",
        "tool": "license-detector-mvp",
        "timestamp": ts,
        "schema_version": "1.0",
        "payload": payload,
        "hash": h
    }]
