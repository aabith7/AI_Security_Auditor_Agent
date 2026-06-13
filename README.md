# 🛡️ Domo AppDB Agent — AI Security Auditor

> **An autonomous AI agent for querying Domo AppDB, with a built-in real-time security auditing engine that detects, visualizes, and auto-patches vulnerabilities in the codebase.**

<p align="center">
  <img src="GWC LOGO.jpg" alt="GWC Data.AI" height="60"/>
</p>

---

## 📌 Overview

The **Domo AppDB Agent** is a production-grade conversational AI agent that connects to [Domo AppDB](https://developer.domo.com/) and answers natural-language queries over your data. Powered by **Ollama (MiniMax M3)** and served via **FastAPI**, it enables non-technical users to list, search, query, and manage Domo documents through a chat interface.

Alongside the core agent, this project ships an integrated **AI Security Auditor** — a live vulnerability scanner that reads your actual codebase, identifies security threats across 7 domains, provides AI-powered analysis, and applies real code patches with one click.

---

## ✨ Features

### 🤖 Domo AppDB Chat Agent
- **Natural-language queries** over Domo AppDB collections (list, get, find, query documents)
- **Tool-calling agent loop** — model decides which Domo API tool to invoke, executes it, and returns a natural-language response
- **Persistent sessions** — each conversation maintains full message history
- **MongoDB-style advanced queries** via the `query_documents` tool

### 🔍 AI Security Auditor
- **Real-time streaming audit** via Server-Sent Events (SSE) — threats appear live as they are analysed
- **Static code analysis** — reads your actual `.py`, `.env`, and `.gitignore` files; no mock data
- **AI-powered deep analysis** — unresolved threats are sent to MiniMax M3 for CVSS scoring, exploit scenarios, and business impact
- **Side-by-side diff viewer** — before/after code comparison for every vulnerability
- **One-click auto-patch** — the agent applies the real code fix directly to your files
- **One-click Resolve All** — resolves every active threat at once, pushing the Production Readiness Score to **100/100**
- **One-click Revoke All** — rolls back all applied patches in one action
- **Production Readiness Score** (0–100) with live progress bar and verdict pill (🟢 Approved / 🔴 Not Approved)
- **Severity filtering** — Critical · High · Medium · Resolved filter tabs with live counts
- **Full activity log** with timestamps

---

## 🔒 Security Domains Audited

| Domain | Threats Checked |
|---|---|
| **Prompt Security** | Prompt injection via user message |
| **Tool Security** | Unguarded delete tool access |
| **Authentication** | No endpoint authentication, no rate limiting |
| **Credential Security** | Token / secret leakage, `.env` git commit risk |
| **Data Access** | MongoDB query injection, excessive data exposure |
| **Session Security** | User-supplied session IDs, in-memory session exposure |
| **Operational** | Unbounded tool loops, missing API timeouts, CORS misconfiguration |

---

## 🏗️ Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.11+, FastAPI 0.115, Uvicorn |
| **AI / LLM** | Ollama Cloud — MiniMax M3 (`minimax-m3:cloud`) |
| **Data** | Domo AppDB REST API |
| **Frontend** | Vanilla HTML/CSS/JS (zero frameworks) |
| **Streaming** | Server-Sent Events (SSE) |
| **Config** | python-dotenv |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- A [Domo Developer Token](https://developer.domo.com/)
- An [Ollama API Key](https://ollama.com/)

### 1. Clone the repository
```bash
git clone https://github.com/your-org/domo-appdb-agent.git
cd domo-appdb-agent
```

### 2. Create and activate a virtual environment
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables
Create a `.env` file in the project root:
```env
OLLAMA_API_KEY=your_ollama_api_key
DOMO_DEVELOPER_TOKEN=your_domo_developer_token
DOMO_BASE_URL=https://your-instance.domo.com
DOMO_COLLECTION_ID=your_default_collection_id
```

### 5. Run the server
```bash
python app.py
```

The application starts at **http://127.0.0.1:8000**

| URL | Description |
|---|---|
| `http://127.0.0.1:8000/` | Chat UI |
| `http://127.0.0.1:8000/security-ui/auditor.html` | AI Security Auditor |

---

## 🖥️ Usage

### Chat Agent
Navigate to `http://127.0.0.1:8000/` and ask questions like:
- *"List all documents in the collection"*
- *"Show me the document where name is John"*
- *"Find all records where status is active"*

### Security Auditor
Navigate to `http://127.0.0.1:8000/security-ui/auditor.html` and:
1. Click **🔍 Run full security audit** — threats stream in live
2. Expand any threat card to see the attack scenario, business impact, and before/after code diff
3. Click **🔧 Resolve** on individual threats, or **✅ Resolve All** to patch everything at once
4. Watch the **Production Readiness Score** climb to **100/100**
5. Click **↺ Revoke All** to roll back all patches if needed

---

## 📁 Project Structure

```
domo-appdb-agent/
├── app.py                          # FastAPI application entry point
├── agent.py                        # Ollama tool-calling agent loop
├── config.py                       # Environment config & system prompt
├── tools.py                        # Domo tool schemas & registry
├── domo_client.py                  # Domo AppDB REST API client
├── requirements.txt
├── .env                            # ⚠️ Never commit — secrets here
├── static/
│   └── index.html                  # Chat UI
└── security_auditor/
    ├── auditor_engine.py           # Static checks, AI analysis, patch engine
    ├── auditor_routes.py           # FastAPI router for /security/* endpoints
    ├── threats.py                  # Threat definitions
    └── static/
        └── auditor.html           # Security Auditor UI
```

---

## 🔌 API Endpoints

### Chat Agent
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/chat` | Send a message, get a reply |
| `POST` | `/reset/{session_id}` | Reset conversation history |
| `DELETE` | `/session/{session_id}` | Delete a session |

### Security Auditor
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/security/audit/stream` | SSE stream of live audit findings |
| `POST` | `/security/fix/{threat_id}` | Auto-patch a specific threat |
| `POST` | `/security/revoke/{threat_id}` | Revert a patch |
| `POST` | `/security/resolve/{threat_id}` | Mark a threat as resolved |
| `GET` | `/security/health` | Auditor health check |

---

## ⚙️ How the Auditor Works

```
1. Read project files (agent.py, app.py, tools.py, domo_client.py, config.py, .gitignore)
        │
        ▼
2. Run static checks — pattern matching against real code
   (Is _sanitize_input present? Is rate limiting configured? etc.)
        │
        ▼
3. For each UNRESOLVED threat → send code snippet to MiniMax M3
   → AI returns CVSS score, exploit scenario, business impact
        │
        ▼
4. Stream findings to the UI via SSE
        │
        ▼
5. On Resolve / Resolve All → apply real code patches to disk
6. On Revoke / Revoke All  → revert patches to original state
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📄 License

This project is proprietary software developed by **GWC Data.AI**. All rights reserved.

---

<p align="center">Built with ❤️ by <strong>GWC Data.AI</strong></p>
