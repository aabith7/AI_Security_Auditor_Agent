from agent import DomoAppDBAgent


def main():
    agent = DomoAppDBAgent()
    print("Domo AppDB Agent (type 'quit' to exit, 'reset' to clear history)")

    while True:
        user_in = input("\nYou: ").strip()
        if not user_in:
            continue
        if user_in.lower() in ("quit", "exit"):
            break
        if user_in.lower() == "reset":
            agent.reset()
            print("History cleared.")
            continue
        print(f"\nAgent: {agent.chat(user_in)}")


if __name__ == "__main__":
    main()