from __future__ import annotations
from pathlib import Path
import json

def write_findings(path: Path, findings: list[dict]) -> None:
    path.write_text(json.dumps(findings, indent=2, sort_keys=True), encoding="utf-8")
