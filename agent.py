"""Ollama agent loop: model → tool calls → execute → respond."""
import json
from ollama import Client
from config import OLLAMA_API_KEY, MODEL, SYSTEM_PROMPT
from tools import TOOL_SCHEMAS, execute_tool


def _sanitize_input(user_in: str) -> str:
    # Enforce MAX_INPUT_LENGTH to prevent prompt injection and resource exhaust attacks
    MAX_INPUT_LENGTH = 2000
    cleaned = user_in.strip()
    return cleaned[:MAX_INPUT_LENGTH]

class DomoAppDBAgent:
    def __init__(self):
        # Configure client for Ollama Cloud
        self.client = Client(
            host="https://ollama.com",
            headers={"Authorization": f"Bearer {OLLAMA_API_KEY}"}
        )
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    def chat(self, user_message: str) -> str:
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
                self.messages.append({"role": "assistant", "content": msg.content or ""})
                return msg.content or ""

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
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]