from __future__ import annotations
import hashlib
import json

def canonical_sha256(payload: dict) -> str:
    b = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(b).hexdigest()
