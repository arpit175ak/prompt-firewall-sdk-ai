from __future__ import annotations

from collections.abc import Mapping
from runner.models import STATUSES


def normalize_sdk_result(raw, original: str, direction: str, latency_ms: float, fail_closed: bool = True) -> dict:
    if not isinstance(raw, Mapping):
        return error_result("SDK returned a non-mapping result", original, direction, latency_ms, fail_closed)
    if raw.get("error"):
        return error_result(str(raw["error"]), original, direction, latency_ms, fail_closed)
    status = str(raw.get("query_status", "UNCHECKED")).upper()
    if status not in STATUSES - {"ERROR"}: status = "UNCHECKED"
    sanitized = raw.get("sanitized_content", original)
    if not isinstance(sanitized, str): sanitized = original
    return {"ok": True, "direction": direction, "query_status": status, "sanitized_content": sanitized,
            "modified": sanitized != original, "risk_score": raw.get("risk_score", {}), "latency_ms": latency_ms,
            "session_id": raw.get("session_id") if direction == "prompt" else None}


def error_result(error: str, original: str, direction: str, latency_ms: float, fail_closed: bool) -> dict:
    status = "BLOCK" if fail_closed else "PASS"
    return {"ok": False, "direction": direction, "query_status": status, "sanitized_content": original,
            "modified": False, "error": error, "latency_ms": latency_ms, "fail_mode": "closed" if fail_closed else "open"}
