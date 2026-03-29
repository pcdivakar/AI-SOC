import requests

def ask_ai(question, context, model="llama3.2", ollama_url="http://localhost:11434"):
    """
    Send a question with context to Ollama and return the answer.
    """
    prompt = f"Context:\n{context}\n\nQuestion: {question}\n\nAnswer:"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.7}
    }
    try:
        response = requests.post(f"{ollama_url}/api/generate", json=payload, timeout=60)
        if response.status_code != 200:
            return f"Error: Ollama API returned {response.status_code}"
        data = response.json()
        return data.get("response", "No response")
    except Exception as e:
        return f"Exception: {str(e)}"