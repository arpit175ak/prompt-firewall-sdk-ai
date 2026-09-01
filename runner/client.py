from __future__ import annotations

import time
from datetime import datetime, timezone
from collections.abc import Callable

from runner.normalize import normalize_sdk_result
from runner.retry import call_with_retry
from runner.safety import RequestAccountant


class LiveScanner:
    """Network-capable scanner. Construct only after authorize_live succeeds."""
    def __init__(self, token: str, accountant: RequestAccountant, *, timeout: float = 10, max_attempts: int = 2, client_factory: Callable | None = None):
        if accountant.data["budget"] <= 0: raise RuntimeError("refusing SDK client construction with zero live budget")
        if client_factory is None:
            from accuknox_llm_defense import LLMDefenseClient
            client_factory = LLMDefenseClient
        self.token, self.accountant, self.timeout, self.max_attempts, self.factory = token, accountant, timeout, max_attempts, client_factory
        self.clients = {}

    def _client(self, user_info: str):
        if user_info not in self.clients: self.clients[user_info] = self.factory(llm_defense_api_key=self.token, user_info=user_info)
        return self.clients[user_info]

    def scan(self, case, fail_closed=True):
        client = self._client(case.user_info or "pf-lab-user")
        started = time.perf_counter()
        first = True
        def invoke():
            nonlocal first
            self.accountant.reserve(case.direction, retry=not first); first = False
            if case.direction == "prompt": return client.scan_prompt(content=case.content)
            return client.scan_response(prompt=case.prompt or "", content=case.content, session_id=case.metadata.get("session_id", ""))
        try: raw = call_with_retry(invoke, max_attempts=self.max_attempts)
        except Exception as exc: raw = {"error": str(exc)}
        latency = round((time.perf_counter()-started)*1000, 2)
        result = normalize_sdk_result(raw, case.content, case.direction, latency, fail_closed)
        result.update({
            "case_id": case.case_id,
            "policy": case.family,
            "scanner": case.metadata.get("scanner", case.family),
            "category": case.metadata.get("category", case.family),
            "subcategory": case.metadata.get("subcategory"),
            "username": case.user_info,
            "expected_class": case.expected,
            "sdk_ok": result["ok"],
            "sanitized_modified": result["modified"],
            "pf_latency_ms": latency,
            "total_latency_ms": latency,
            "attempt": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "validation": "REAL ACCUKNOX RESULT",
            # Preserve the complete SDK mapping so reports never discard policy
            # fields that a newer backend/SDK may add.
            "raw_sdk_result": raw if isinstance(raw, dict) else {"raw_repr": repr(raw)},
        })
        return result
