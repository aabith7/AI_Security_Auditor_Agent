from agent import DomoAppDBAgent
import sys

try:
    print("Initializing DomoAppDBAgent...")
    agent = DomoAppDBAgent()
    print("Agent initialized successfully.")

    print("\nSending message to agent: 'Hi, what tools do you have?'")
    reply = agent.chat("Hi, what tools do you have?")
    
    # Safe printing handling for Windows terminal
    encoding = sys.stdout.encoding or "utf-8"
    safe_reply = reply.encode(encoding, errors="replace").decode(encoding)
    
    print(f"\nAgent response:\n{safe_reply}")
    print("\nVerification successful!")
except Exception as e:
    print(f"\nVerification failed with error: {e}")
    sys.exit(1)
