#!/usr/bin/env python3
"""
FastAPI Reference Implementation - AI Security Gateway

Same pipeline as the n8n workflow, in code, so the logic is runnable and
testable without n8n:

  POST /secure-chat
    1. DLP scan + redact            (gateway.dlp)
    2. Heuristic injection filter   (gateway.injection_patterns)
    3. [Optional] LLM classifier    (stub by default; enable with env vars)
    4. Gate: block if critical DLP in strict mode, or injection_score >= 70
    5. Log incident (stdout here; Postgres in production - see db/schema.sql)
    6. Forward REDACTED prompt to the final LLM, return its answer + security metadata

Run:
  pip install -r requirements.txt
  uvicorn gateway.app:app --port 8000
  curl -X POST localhost:8000/secure-chat -H 'Content-Type: application/json' \
       -d '{"prompt":"My email is a@b.com - what is 2+2?","session_id":"demo"}'

Without OPENAI_API_KEY set, the final-LLM step returns a deterministic stub
echo so the full security pipeline can be tested offline.
Author: Gilberto A. Cedillo Soto
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from gateway.dlp import scan_and_redact
from gateway.injection_patterns import assess, BLOCK_THRESHOLD

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ai-security-gateway")

STRICT_DLP_BLOCK = os.getenv("STRICT_DLP_BLOCK", "true").lower() == "true"
FINAL_MODEL = os.getenv("FINAL_LLM_MODEL", "gpt-4o-mini")
CLASSIFIER_ENABLED = os.getenv("LLM_CLASSIFIER_ENABLED", "false").lower() == "true"

app = FastAPI(title="AI Security Gateway", version="1.0.0",
              description="DLP & anti-prompt-injection proxy in front of an LLM (OWASP LLM01)")


class SecureChatRequest(BaseModel):
    prompt: str = Field(..., max_length=20000)
    session_id: str | None = None
    source: str = "api"


def log_incident(record: dict) -> None:
    """Production: INSERT into incidents (db/schema.sql) via asyncpg/psycopg.
    Reference implementation logs structured JSON (redacted prompt only - never raw secrets)."""
    log.warning("INCIDENT %s", json.dumps(record))


def llm_classifier_stub(redacted_prompt: str, heuristic_score: int) -> dict:
    """Stub for the LLM classifier (prompts/llm-injection-classifier.md).
    When CLASSIFIER_ENABLED, replace with a real call to a small fast model
    and parse its JSON. The stub defers to the heuristic score so the gateway
    is safe-by-default offline."""
    return {"injection_score": heuristic_score, "source": "heuristic_only"}


def forward_to_final_llm(redacted_prompt: str) -> str:
    """Forward the SANITIZED prompt. With no API key, return a stub echo."""
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        return f"[stub-llm] Received sanitized prompt ({len(redacted_prompt)} chars). Set OPENAI_API_KEY for a real completion."
    # Real path (kept dependency-light with stdlib urllib)
    import urllib.request
    body = json.dumps({
        "model": FINAL_MODEL,
        "messages": [{"role": "user", "content": redacted_prompt}],
        "temperature": 0.2,
    }).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions", data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


@app.get("/health")
def health():
    return {"ok": True, "strict_dlp_block": STRICT_DLP_BLOCK, "classifier_enabled": CLASSIFIER_ENABLED}


@app.post("/secure-chat")
async def secure_chat(payload: SecureChatRequest, request: Request):
    started = datetime.now(timezone.utc)

    # 1-2. Deterministic layers first
    dlp = scan_and_redact(payload.prompt)
    heur = assess(dlp.redacted_text)

    # 3. Classifier (stub or real)
    cls = llm_classifier_stub(dlp.redacted_text, heur.score)
    injection_score = max(heur.score, int(cls.get("injection_score", 0)))

    # 4. Gate - fail closed
    block_reason = None
    if dlp.has_critical and STRICT_DLP_BLOCK:
        block_reason = "critical_dlp_secret_detected"
    elif injection_score >= BLOCK_THRESHOLD:
        block_reason = f"prompt_injection_score_{injection_score}"

    security_meta = {
        "dlp_redactions": dlp.total_redactions,
        "dlp_findings": [f.to_dict() for f in dlp.findings],
        "dlp_critical": dlp.has_critical,
        "injection_score": injection_score,
        "injection_category": heur.category,
        "heuristic_rules": heur.matched_rules,
    }

    if block_reason:
        record = {
            "timestamp": started.isoformat(), "source": payload.source,
            "session_id": payload.session_id, "category": heur.category,
            "injection_score": injection_score, "block_reason": block_reason,
            "dlp_findings": security_meta["dlp_findings"],
            "redacted_prompt": dlp.redacted_text[:2000], "blocked": True,
            "model": FINAL_MODEL,
        }
        log_incident(record)
        return JSONResponse(status_code=403, content={
            "blocked": True, "reason": block_reason, "security": security_meta,
        })

    # 6. Forward sanitized prompt only
    answer = forward_to_final_llm(dlp.redacted_text)
    if dlp.total_redactions or heur.score >= 40:
        log_incident({
            "timestamp": started.isoformat(), "source": payload.source,
            "session_id": payload.session_id, "category": heur.category,
            "injection_score": injection_score, "dlp_findings": security_meta["dlp_findings"],
            "redacted_prompt": dlp.redacted_text[:2000], "blocked": False, "model": FINAL_MODEL,
        })
    return {"answer": answer, "security": security_meta}
