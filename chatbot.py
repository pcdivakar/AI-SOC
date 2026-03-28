import requests

def ask_ai(question, context, model_id="mistralai/Mistral-7B-Instruct-v0.2", hf_token=None):
    """
    Send a prompt to Hugging Face Inference API (new router endpoint) and return the response.
    """
    if not hf_token:
        return "Error: Hugging Face token not configured."

    # Build prompt
    system_msg = "You are a cybersecurity assistant specialized in analyzing network traffic and vulnerabilities. Use the provided context to answer the user's question accurately and concisely."
    user_msg = f"Context: {context}\n\nQuestion: {question}\n\nAnswer:"

    # Prompt format for Mistral Instruct
    prompt = f"<s>[INST] {system_msg}\n{user_msg} [/INST]"

    # New endpoint
    api_url = f"https://router.huggingface.co/hf-inference/models/{model_id}"
    headers = {"Authorization": f"Bearer {hf_token}"}
    payload = {"inputs": prompt, "parameters": {"max_new_tokens": 300, "temperature": 0.7}}

    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        if response.status_code != 200:
            return f"Error: API returned {response.status_code} - {response.text}"
        result = response.json()
        # Response structure varies by model; usually a list of dicts
        if isinstance(result, list) and len(result) > 0:
            return result[0].get("generated_text", "").replace(prompt, "").strip()
        else:
            return "No valid response from model."
    except Exception as e:
        return f"Exception: {str(e)}"
