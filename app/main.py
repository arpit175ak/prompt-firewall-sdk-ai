import logging
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.firewall import PromptFirewall
from app.provider import call_llm
from app.config import (
    FAIL_CLOSED,
    BLOCK_UNCHECKED,
    BLOCK_MONITOR,
    EXPOSE_RAW_PF_RESULT,
)


Path("logs").mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s "
        "%(levelname)s "
        "%(name)s "
        "%(message)s"
    ),
    handlers=[
        logging.FileHandler("logs/pf.log"),
        logging.StreamHandler(),
    ],
)

logger = logging.getLogger("pf-app")


app = FastAPI(
    title="AccuKnox Prompt Firewall SDK Lab",
    description=(
        "Prompt + response enforcement lab using "
        "AccuKnox LLM Defense SDK"
    ),
    version="2.0",
)

pf = None

def get_firewall():
    global pf
    if pf is None:
        pf = PromptFirewall()
    return pf


class PromptRequest(BaseModel):
    prompt: str = Field(min_length=1)
    llm_mode: str = "normal"


class ResponseRequest(BaseModel):
    response: str
    prompt: str
    session_id: str


def should_block(status: str):
    if status == "BLOCK":
        return True

    if status == "UNCHECKED" and BLOCK_UNCHECKED:
        return True

    if status == "MONITOR" and BLOCK_MONITOR:
        return True

    return False


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "accuknox-pf-lab",
        "version": "2.0",
    }


@app.get("/security/config")
def security_config():
    return {
        "fail_closed": FAIL_CLOSED,
        "block_unchecked": BLOCK_UNCHECKED,
        "block_monitor": BLOCK_MONITOR,
        "expose_raw_pf_result": EXPOSE_RAW_PF_RESULT,
    }


@app.post("/scan/prompt")
def scan_prompt(req: PromptRequest):
    result = get_firewall().scan_prompt(req.prompt)

    return result


@app.post("/scan/response")
def scan_response(req: ResponseRequest):
    return get_firewall().scan_response(
        content=req.response,
        prompt=req.prompt,
        session_id=req.session_id,
    )


@app.post("/chat")
def chat(req: PromptRequest):
    total_start = time.perf_counter()

    original_prompt = req.prompt

    # ============================================
    # STAGE 1 — PROMPT FIREWALL INPUT INSPECTION
    # ============================================

    firewall = get_firewall()
    prompt_result = firewall.scan_prompt(original_prompt)

    prompt_status = prompt_result.get(
        "query_status",
        "UNCHECKED",
    )

    logger.info(
        "PF_PROMPT status=%s session=%s latency_ms=%s",
        prompt_status,
        prompt_result.get("session_id"),
        prompt_result.get("latency_ms"),
    )

    if should_block(prompt_status):
        raise HTTPException(
            status_code=403,
            detail={
                "stage": "prompt",
                "decision": prompt_status,
                "message": (
                    "Request stopped before LLM invocation"
                ),
                "pf": prompt_result,
            },
        )

    safe_prompt = prompt_result.get(
        "sanitized_content",
        original_prompt,
    )

    session_id = prompt_result.get("session_id")

    if not session_id:
        raise HTTPException(
            status_code=502,
            detail={
                "stage": "prompt",
                "message": (
                    "Prompt Firewall did not return session_id"
                ),
                "pf": prompt_result,
            },
        )

    # ============================================
    # STAGE 2 — DOWNSTREAM LLM
    # ============================================

    llm_result = call_llm(
        safe_prompt,
        mode=req.llm_mode,
    )

    raw_response = llm_result["content"]

    # ============================================
    # STAGE 3 — RESPONSE FIREWALL INSPECTION
    # ============================================

    response_result = firewall.scan_response(
        content=raw_response,
        prompt=safe_prompt,
        session_id=session_id,
    )

    response_status = response_result.get(
        "query_status",
        "UNCHECKED",
    )

    logger.info(
        "PF_RESPONSE status=%s session=%s latency_ms=%s",
        response_status,
        session_id,
        response_result.get("latency_ms"),
    )

    if should_block(response_status):
        raise HTTPException(
            status_code=403,
            detail={
                "stage": "response",
                "decision": response_status,
                "message": (
                    "LLM executed, but response was not "
                    "released to client"
                ),
                "session_id": session_id,
                "pf": response_result,
            },
        )

    safe_response = response_result.get(
        "sanitized_content",
        raw_response,
    )

    total_latency_ms = round(
        (time.perf_counter() - total_start) * 1000,
        2,
    )

    return {
        "status": "allowed",
        "session_id": session_id,

        "prompt_security": {
            "decision": prompt_status,
            "original": original_prompt,
            "sanitized": safe_prompt,
            "modified": original_prompt != safe_prompt,
            "risk_score": prompt_result.get("risk_score"),
            "latency_ms": prompt_result.get("latency_ms"),
        },

        "llm": {
            "provider": llm_result.get("provider"),
            "mode": llm_result.get("mode"),
            "raw_response": raw_response,
            "latency_ms": llm_result.get("latency_ms"),
        },

        "response_security": {
            "decision": response_status,
            "sanitized": safe_response,
            "modified": raw_response != safe_response,
            "risk_score": response_result.get("risk_score"),
            "latency_ms": response_result.get("latency_ms"),
        },

        "final_response": safe_response,

        "performance": {
            "pf_prompt_ms": prompt_result.get("latency_ms"),
            "llm_ms": llm_result.get("latency_ms"),
            "pf_response_ms": response_result.get(
                "latency_ms"
            ),
            "total_ms": total_latency_ms,
        },
    }
