import requests

def ask_ai(question, context, model_id="google/flan-t5-base", hf_token=None):
    """
    Send a prompt to Hugging Face Inference API and return the response.
    """
    if not hf_token:
        return "Error: Hugging Face token not configured."

    # Build prompt
    system_msg = "You are a cybersecurity assistant specialized in analyzing network traffic and vulnerabilities. Use the provided context to answer the user's question accurately and concisely."
    user_msg = f"Context: {context}\n\nQuestion: {question}\n\nAnswer:"

    # For Flan-T5, a simple concatenated prompt works well
    prompt = f"{system_msg}\n{user_msg}"

    # Correct endpoint
    api_url = f"https://api-inference.huggingface.co/models/{model_id}"
    headers = {"Authorization": f"Bearer {hf_token}"}
    payload = {"inputs": prompt, "parameters": {"max_new_tokens": 300, "temperature": 0.7}}

    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        if response.status_code != 200:
            return f"Error: API returned {response.status_code} - {response.text}"
        result = response.json()
        if isinstance(result, list) and len(result) > 0:
            return result[0].get("generated_text", "").strip()
        else:
            return "No valid response from model."
    except Exception as e:
        return f"Exception: {str(e)}"
