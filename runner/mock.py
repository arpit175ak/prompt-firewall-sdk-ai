from __future__ import annotations

import time
from runner.normalize import normalize_sdk_result


class MockClient:
    def __init__(self, user_info="pf-lab-user"): self.user_info=user_info
    def scan_prompt(self, content): return self._result(content, True)
    def scan_response(self, prompt, content, session_id):
        result=self._result(content, False); result["received_session_id"]=session_id; return result
    def _result(self, content, prompt):
        low=content.lower()
        if "sdk-error" in low: return {"error":"synthetic SDK error"}
        status = "BLOCK" if "blocked" in low or "ignore prior" in low else "MONITOR" if "monitor" in low else "UNCHECKED" if "korean" in low or "안녕" in content else "PASS"
        sanitized = content.replace("person@example.test", "<EMAIL_ADDRESS>")
        return {"query_status":status,"sanitized_content":sanitized,"session_id":"mock-session-001" if prompt else None,"risk_score":{"mock":True}}


def mock_scan(client, case, fail_closed=True):
    start=time.perf_counter()
    raw=client.scan_prompt(case.content) if case.direction=="prompt" else client.scan_response(case.prompt or "",case.content,case.metadata.get("session_id","mock-session-001"))
    result=normalize_sdk_result(raw,case.content,case.direction,round((time.perf_counter()-start)*1000,4),fail_closed)
    result["user_info_client"] = client.user_info
    result["validation"] = "LOCAL/MOCK VALIDATION ONLY"
    return result
