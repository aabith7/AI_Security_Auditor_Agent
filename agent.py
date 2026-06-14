"""Ollama agent loop: model → tool calls → execute → respond."""
import json
import re
from ollama import Client
from config import OLLAMA_API_KEY, MODEL, DOMO_DEVELOPER_TOKEN, SYSTEM_PROMPT_SECURE, SYSTEM_PROMPT_INSECURE
from tools import TOOL_SCHEMAS, execute_tool


def get_system_prompt() -> str:
    # Check if tools.py contains the admin guard
    try:
        from pathlib import Path
        tools_path = Path(__file__).parent / "tools.py"
        if tools_path.exists():
            content = tools_path.read_text(encoding="utf-8")
            if "admin access" in content.lower():
                return SYSTEM_PROMPT_SECURE
    except Exception:
        pass
    return SYSTEM_PROMPT_INSECURE


def _sanitize_input(user_in: str) -> str:
    # Enforce MAX_INPUT_LENGTH to prevent prompt injection and resource exhaust attacks
    MAX_INPUT_LENGTH = 2000
    cleaned = user_in.strip()
    return cleaned[:MAX_INPUT_LENGTH]


def _sanitize_output(text: str) -> str:
    for secret in [DOMO_DEVELOPER_TOKEN, OLLAMA_API_KEY]:
        if secret and secret in text:
            text = text.replace(secret, "[REDACTED]")
    return re.sub(r'[A-Za-z0-9_\-]{40,}', '[REDACTED]', text)

class DomoAppDBAgent:
    def __init__(self):
        # Configure client for Ollama Cloud
        self.client = Client(
            host="https://ollama.com",
            headers={"Authorization": f"Bearer {OLLAMA_API_KEY}"}
        )
        self.messages = [{"role": "system", "content": get_system_prompt()}]

    def chat(self, user_message: str) -> str:
        if self.messages and self.messages[0]["role"] == "system":
            self.messages[0]["content"] = get_system_prompt()
        sanitized = _sanitize_input(user_message)
        self.messages.append({"role": "user", "content": sanitized})

        while True:
            response = self.client.chat(
                model=MODEL,
                messages=self.messages,
                tools=TOOL_SCHEMAS,
            )
            msg = response.message

            if not msg.tool_calls:
                reply = _sanitize_output(msg.content or "")
                self.messages.append({"role": "assistant", "content": reply})
                return reply

            # Reconstruct the assistant message to append to history
            assistant_msg = {
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [
                    {
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        }
                    }
                    for tc in msg.tool_calls
                ]
            }
            self.messages.append(assistant_msg)

            for tc in msg.tool_calls:
                # Handle dictionary or string arguments safely
                args = tc.function.arguments
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                print(f"→ calling {tc.function.name}({args})")
                result = execute_tool(tc.function.name, args)
                self.messages.append({
                    "role": "tool",
                    "tool_name": tc.function.name,
                    "content": result,
                })

    def reset(self):
        self.messages = [{"role": "system", "content": get_system_prompt()}]