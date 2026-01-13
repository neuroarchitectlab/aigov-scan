from __future__ import annotations
import re

def normalize_text(s: str) -> str:
    s = s.lower()
    s = re.sub(r"\s+", " ", s)
    return s.strip()

def safe_read_text(path, max_bytes: int = 512_000) -> str:
    data = path.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="ignore")
