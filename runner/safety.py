from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from threading import Lock


ACCOUNTING_PATH = Path("results/summaries/live_request_budget.json")
MAX_LIVE_REQUESTS = 20


class LiveExecutionRefused(RuntimeError):
    pass


def env_true(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class RequestEstimate:
    selected_cases: int
    prompt_scan_requests: int
    response_scan_requests: int
    maximum_retry_requests: int
    estimated_max_backend_requests: int
    configured_live_request_budget: int


def estimate_requests(selected: int, direction: str, max_attempts: int, budget: int) -> RequestEstimate:
    prompts = selected if direction in {"prompt", "both"} else 0
    responses = selected if direction in {"response", "both"} else 0
    base = prompts + responses
    retries = base * max(0, max_attempts - 1)
    return RequestEstimate(selected, prompts, responses, retries, base + retries, budget)


def authorize_live(*, confirm_live: bool, budget: int, estimate: RequestEstimate, confirm_massive: bool = False, massive_threshold: int = 1000) -> None:
    approved = confirm_live or env_true("PF_ALLOW_LIVE_SCAN")
    enabled = env_true("PF_LIVE_ENABLED")
    if not enabled or not approved:
        raise LiveExecutionRefused("live execution disabled; set PF_LIVE_ENABLED=true and explicitly confirm live")
    if budget <= 0 or budget > MAX_LIVE_REQUESTS:
        raise LiveExecutionRefused(f"live request budget must be between 1 and the authorized maximum of {MAX_LIVE_REQUESTS}")
    if estimate.estimated_max_backend_requests > budget:
        raise LiveExecutionRefused("maximum attempts exceed the configured live request budget")
    base=estimate.prompt_scan_requests+estimate.response_scan_requests
    if base > budget:
        raise LiveExecutionRefused("selected base scans exceed the configured budget; retries share the same budget")


class RequestAccountant:
    def __init__(self, path: Path = ACCOUNTING_PATH, budget: int = 0):
        self.path, self.lock = path, Lock()
        self.data = {"budget": budget, "used": 0, "remaining": budget, "prompt_requests": 0, "response_requests": 0, "retry_requests": 0}
        self._write()

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".budget-", text=True)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self.data, f, indent=2, sort_keys=True)
                f.write("\n")
            os.replace(name, self.path)
        finally:
            if os.path.exists(name): os.unlink(name)

    def reserve(self, direction: str, retry: bool = False) -> None:
        with self.lock:
            if self.data["used"] >= self.data["budget"]:
                raise LiveExecutionRefused("live request budget exhausted before network request")
            self.data["used"] += 1
            self.data["remaining"] -= 1
            self.data["retry_requests" if retry else f"{direction}_requests"] += 1
            self._write()
