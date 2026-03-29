import os
from groq import Groq

def ask_ai(question, context, model="llama-3.3-70b-versatile", groq_api_key=None):
    if not groq_api_key:
        groq_api_key = os.environ.get("GROQ_API_KEY")
        if not groq_api_key:
            return "Error: Groq API key not configured."

    client = Groq(api_key=groq_api_key)
    system_msg = (
        "You are a cybersecurity assistant specialized in analyzing network traffic and vulnerabilities. "
        "Use the provided context to answer the user's question accurately and concisely. "
        "The context may include asset details and associated vulnerabilities (CVE IDs with EPSS and KEV status). "
        "If the user asks about a specific CVE or asset, refer to the context if available; otherwise, suggest using the Vulnerability Lookup section."
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
