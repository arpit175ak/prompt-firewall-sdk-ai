from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


STATUSES = {"PASS", "MONITOR", "BLOCK", "UNCHECKED", "ERROR"}


@dataclass(frozen=True)
class Case:
    case_id: str
    family: str
    direction: str
    content: str
    expected: str = "UNCHECKED"
    prompt: str | None = None
    user_info: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    case_id: str
    direction: str
    query_status: str
    sanitized_content: str
    modified: bool
    latency_ms: float
    session_id: str | None = None
    error: str | None = None
    fail_mode: str | None = None
    validation: str = "LOCAL/MOCK VALIDATION ONLY"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
