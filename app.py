"""FastAPI wrapper — serves the chat UI + agent endpoints."""
import uuid
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from agent import DomoAppDBAgent
# Add these imports at the top
from fastapi.staticfiles import StaticFiles
from security_auditor.auditor_routes import auditor_router

app = FastAPI(title="Domo AppDB Agent API", version="1.0.0")

# Add these two lines after app = FastAPI()
app.include_router(auditor_router)
app.mount("/security-ui", StaticFiles(directory="security_auditor/static"), name="security-ui")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

sessions: dict[str, DomoAppDBAgent] = {}


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


class ChatResponse(BaseModel):
    session_id: str
    reply: str


@app.get("/")
def serve_ui():
    return FileResponse("static/index.html")


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="message cannot be empty")
    session_id = req.session_id or str(uuid.uuid4())
    agent = sessions.setdefault(session_id, DomoAppDBAgent())
    try:
        reply = agent.chat(req.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent error: {e}")
    return ChatResponse(session_id=session_id, reply=reply)


@app.post("/reset/{session_id}")
def reset(session_id: str):
    agent = sessions.get(session_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="session not found")
    agent.reset()
    return {"status": "reset", "session_id": session_id}


@app.delete("/session/{session_id}")
def delete_session(session_id: str):
    if sessions.pop(session_id, None) is None:
        raise HTTPException(status_code=404, detail="session not found")
    return {"status": "deleted", "session_id": session_id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)



