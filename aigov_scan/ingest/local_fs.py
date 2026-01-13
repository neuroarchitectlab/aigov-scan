from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import mimetypes
import os
import hashlib


@dataclass(frozen=True)
class IngestedFile:
    path: str
    size_bytes: int
    mime: str | None
    sha256: str


@dataclass(frozen=True)
class IngestedDataset:
    name: str
    root: str
    created_at: str
    files: list[IngestedFile]
    asset_id: str
    size_bytes: int


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def ingest_local_folder(root: Path) -> IngestedDataset:
    root = root.resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Not a folder: {root}")

    files: list[IngestedFile] = []
    total = 0

    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            p = Path(dirpath) / fn
            rel = str(p.relative_to(root))
            size = p.stat().st_size
            total += size
            mime, _ = mimetypes.guess_type(str(p))
            files.append(IngestedFile(path=rel, size_bytes=size, mime=mime, sha256=_sha256_file(p)))

    dataset_hash = hashlib.sha256()
    for f in sorted(files, key=lambda x: x.path):
        dataset_hash.update(f.sha256.encode("utf-8"))
    asset_id = "sha256:" + dataset_hash.hexdigest()

    from datetime import datetime, timezone
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    return IngestedDataset(
        name=root.name,
        root=str(root),
        created_at=created_at,
        files=files,
        asset_id=asset_id,
        size_bytes=total,
    )
