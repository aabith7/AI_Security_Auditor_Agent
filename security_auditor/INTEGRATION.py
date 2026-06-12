"""
HOW TO INTEGRATE THE SECURITY AUDITOR INTO YOUR EXISTING app.py
================================================================

1. Add these imports at the top of your app.py:

    from fastapi.staticfiles import StaticFiles
    from security_auditor.auditor_routes import auditor_router

2. After your app = FastAPI() line, add:

    # Mount security auditor
    app.include_router(auditor_router)
    app.mount(
        "/security-ui",
        StaticFiles(directory="security_auditor/static"),
        name="security-ui"
    )

3. That's it. The auditor UI will be at:
       http://127.0.0.1:8000/security-ui/auditor.html

4. Add the shield icon to your existing static/index.html
   (see SHIELD_ICON_PATCH below — add it inside your top bar)
"""

SHIELD_ICON_PATCH = """
<!-- Add this button inside your existing top bar div in static/index.html -->
<!-- Place it on the RIGHT side of the top bar -->

<button
  id="security-auditor-btn"
  onclick="window.location.href='/security-ui/auditor.html'"
  title="AI Security Auditor"
  style="
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 38px;
    height: 38px;
    border-radius: 50%;
    border: 1px solid #2e3348;
    background: #1a1d27;
    cursor: pointer;
    transition: all 0.2s;
    margin-left: auto;
  "
  onmouseover="this.style.borderColor='#e84040';this.style.background='#2a1414'"
  onmouseout="this.style.borderColor='#2e3348';this.style.background='#1a1d27'"
>
  <!-- Shield SVG icon -->
  <svg width="18" height="20" viewBox="0 0 18 20" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path
      d="M9 1L1 4.5V9.5C1 13.75 4.5 17.75 9 19C13.5 17.75 17 13.75 17 9.5V4.5L9 1Z"
      stroke="#e84040"
      stroke-width="1.5"
      stroke-linejoin="round"
      fill="rgba(232,64,64,0.1)"
    />
    <circle cx="9" cy="10" r="2" fill="#e84040"/>
  </svg>

  <!-- Red pulse dot — shows there are active threats -->
  <span
    id="threat-pulse"
    style="
      position: absolute;
      top: 4px;
      right: 4px;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #e84040;
      animation: pulse-dot 1.5s ease-in-out infinite;
    "
  ></span>
</button>

<style>
@keyframes pulse-dot {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%       { opacity: 0.5; transform: scale(0.7); }
}
</style>
"""

# ── Full updated app.py example ───────────────────────────────────────────────
UPDATED_APP_PY = """
# app.py — Updated to include Security Auditor

import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import uuid

from agent import DomoAppDBAgent
from security_auditor.auditor_routes import auditor_router

app = FastAPI(title="Domo AppDB Agent")

# ── Mount security auditor routes and UI ─────────────────────────────────────
app.include_router(auditor_router)
app.mount(
    "/security-ui",
    StaticFiles(directory="security_auditor/static"),
    name="security-ui"
)

# ── Existing routes ───────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")

sessions: dict[str, DomoAppDBAgent] = {}


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None


@app.get("/")
async def serve_ui():
    return FileResponse("static/index.html")


@app.post("/chat")
async def chat(req: ChatRequest):
    session_id = req.session_id or str(uuid.uuid4())
    if session_id not in sessions:
        sessions[session_id] = DomoAppDBAgent()
    agent = sessions[session_id]
    reply = agent.chat(req.message)
    return {"session_id": session_id, "reply": reply}


@app.post("/reset/{session_id}")
async def reset(session_id: str):
    if session_id in sessions:
        sessions[session_id].reset()
    return {"status": "reset", "session_id": session_id}


@app.delete("/session/{session_id}")
async def delete_session(session_id: str):
    sessions.pop(session_id, None)
    return {"status": "deleted"}
"""
