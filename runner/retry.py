from __future__ import annotations

import random, time


class TransientScanError(RuntimeError):
    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message); self.retry_after = retry_after


def call_with_retry(call, *, max_attempts: int = 2, base_delay: float = .25, sleep=time.sleep, reserve_retry=lambda: None):
    for attempt in range(1, max_attempts + 1):
        try:
            return call()
        except TransientScanError as exc:
            if attempt >= max_attempts: raise
            reserve_retry()
            delay = exc.retry_after if exc.retry_after is not None else base_delay * (2 ** (attempt - 1))
            sleep(max(0, delay) + random.uniform(0, min(.1, max(0, delay))))
