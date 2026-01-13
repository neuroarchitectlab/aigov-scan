from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import yaml

@dataclass(frozen=True)
class PolicyRule:
    id: str
    severity: str
    action: str  # pass|warn|fail
    when: dict

@dataclass(frozen=True)
class Policy:
    profile: str
    rules: list[PolicyRule]

def load_policy(path: Path) -> Policy:
    obj = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = [PolicyRule(**r) for r in obj.get("rules", [])]
    return Policy(profile=obj.get("profile", "default.v1"), rules=rules)
