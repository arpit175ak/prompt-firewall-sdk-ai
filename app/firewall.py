import os, time
from app.config import ACCUKNOX_PF_TOKEN, FAIL_CLOSED, PF_LIVE_ENABLED, PF_MAX_LIVE_REQUESTS, PF_USER_INFO
from runner.normalize import normalize_sdk_result
from runner.safety import RequestAccountant

class PromptFirewall:
    """Application adapter which refuses construction under zero-live defaults."""
    def __init__(self, client=None):
        self.client=client
        if client is None:
            if not PF_LIVE_ENABLED or PF_MAX_LIVE_REQUESTS <= 0: raise RuntimeError("Prompt Firewall live execution disabled or budget is zero")
            if os.getenv("PF_ALLOW_LIVE_SCAN","").lower() != "true": raise RuntimeError("explicit PF_ALLOW_LIVE_SCAN=true required")
            if not ACCUKNOX_PF_TOKEN: raise RuntimeError("ACCUKNOX_PF_TOKEN is missing")
            from accuknox_llm_defense import LLMDefenseClient
            self.client=LLMDefenseClient(llm_defense_api_key=ACCUKNOX_PF_TOKEN,user_info=PF_USER_INFO)
            self.accountant=RequestAccountant(budget=PF_MAX_LIVE_REQUESTS)
        else:
            self.accountant=None
    def scan_prompt(self, content):
        start=time.perf_counter()
        if self.accountant: self.accountant.reserve("prompt")
        raw=self.client.scan_prompt(content=content)
        return normalize_sdk_result(raw,content,"prompt",round((time.perf_counter()-start)*1000,2),FAIL_CLOSED)
    def scan_response(self, content, prompt, session_id):
        start=time.perf_counter()
        if self.accountant: self.accountant.reserve("response")
        raw=self.client.scan_response(content=content,prompt=prompt,session_id=session_id)
        return normalize_sdk_result(raw,content,"response",round((time.perf_counter()-start)*1000,2),FAIL_CLOSED)
