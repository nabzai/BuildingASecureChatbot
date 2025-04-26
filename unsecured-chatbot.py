from openai import OpenAI
import os
import certifi

# set OPENAI_API_KEY in host os with <export OPENAI_API_KEY="key">
def get_api_key():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("Environment variable OPENAI_API_KEYis not set")
    return api_key

def main():
    try:
        api_key = get_api_key()
    except ValueError as e:
        print(str(e))
        return

    # Use the new client interface
    client = OpenAI(api_key=api_key)

    messages = [
        {"role": "system", "content": "You are a helpful, concise assistant."}
    ]
    print("Chatbot is running. Type 'quit' or 'exit' to end.\n")

    while True:
        user_input = input("User: ").strip()
        if user_input.lower() in ["quit", "exit"]:
            print("Ending Chat.")
            break

        messages.append({"role": "user", "content": user_input})

        try:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=messages,
                temperature=0.7
            )
            assistant_reply = response.choices[0].message.content
            print(f"Assistant: {assistant_reply}\n")
            messages.append({"role": "assistant", "content": assistant_reply})
        except Exception as e:
            print("Error calling OpenAI:", e)
            break


if __name__ == "__main__":
    main()
