import os
from huggingface_hub import InferenceClient

def ask_ai(question, context, model="google/flan-t5-large", hf_token=None):
    """
    Send a question with context to Hugging Face Inference API and return the answer.
    Uses the official huggingface_hub client (automatically uses new router).
    """
    if not hf_token:
        hf_token = os.environ.get("HF_API_TOKEN")
        if not hf_token:
            return "Error: Hugging Face token not configured."

    client = InferenceClient(token=hf_token)

    # Build prompt
    system_msg = "You are a cybersecurity assistant specialized in analyzing network traffic and vulnerabilities. Use the provided context to answer the user's question accurately and concisely."
    user_msg = f"Context: {context}\n\nQuestion: {question}\n\nAnswer:"
    prompt = f"{system_msg}\n{user_msg}"

    try:
        response = client.text_generation(
            prompt,
            model=model,
            max_new_tokens=300,
            temperature=0.7,
            do_sample=True,
            return_full_text=False
        )
        return response.strip()
    except Exception as e:
        return f"Exception: {str(e)}"
