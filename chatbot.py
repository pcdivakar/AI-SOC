import os
from groq import Groq

def ask_ai(question, context, model="llama-3.3-70b-versatile", groq_api_key=None):
    """
    Send a question with context to Groq's API and return the answer.
    Uses the official Groq Python client.
    """
    if not groq_api_key:
        groq_api_key = os.environ.get("GROQ_API_KEY")
        if not groq_api_key:
            return "Error: Groq API key not configured."

    # Initialize the client
    client = Groq(api_key=groq_api_key)

    # Build the system and user messages
    system_msg = (
        "You are a cybersecurity assistant specialized in analyzing network traffic and vulnerabilities. "
        "Use the provided context to answer the user's question accurately and concisely. "
        "If you don't know, say so."
    )
    user_msg = f"Context:\n{context}\n\nQuestion: {question}\n\nAnswer:"

    try:
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg}
            ],
            model=model,
            temperature=0.7,
            max_tokens=500,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Exception: {str(e)}"
