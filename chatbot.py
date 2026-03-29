import os
from huggingface_hub import InferenceClient

def ask_ai(question, context, model="mistralai/Mistral-7B-Instruct-v0.2", hf_token=None):
    """
    Send a question with context to Hugging Face Inference API and return the answer.
    Uses the official huggingface_hub client.
    """
    if not hf_token:
        hf_token = os.environ.get("HF_API_TOKEN")
        if not hf_token:
            return "Error: Hugging Face token not configured."

    client = InferenceClient(token=hf_token)

    # System instruction for chart/dashboard commands
    system_msg = (
        "You are a cybersecurity assistant specialized in analyzing network traffic and vulnerabilities. "
        "Use the provided context to answer the user's question accurately and concisely.\n\n"
        "If the user asks for a chart, respond with exactly:\n"
        "CHART: <type>|<x_axis>|<y_axis>|<title>\n"
        "Where <type> is one of: bar, pie, line, heatmap, scatter.\n"
        "For pie charts, only x_axis is needed; y_axis can be omitted.\n"
        "For heatmap, use: CHART: heatmap|<x_axis>|<y_axis>|<z_axis>|<title>\n\n"
        "If the user asks for a dashboard (e.g., 'create a dashboard'), respond with:\n"
        "DASHBOARD: <title>|<chart1>|<chart2>|...\n"
        "Each chart is defined as <type>|<param1>|<param2>|<param3>|<title> (no 'CHART:' prefix).\n"
        "Use semicolons to separate charts.\n\n"
        "If the request is not for a chart or dashboard, answer normally without the CHART/DASHBOARD prefix."
    )

    # Build chat prompt (for instruction‑tuned models)
    if "mistral" in model.lower():
        # Mistral format: [INST] ... [/INST]
        prompt = f"<s>[INST] {system_msg}\n\nContext:\n{context}\n\nQuestion: {question} [/INST]"
    else:
        # FLAN format
        prompt = f"{system_msg}\n\nContext:\n{context}\n\nQuestion: {question}\n\nAnswer:"

    try:
        response = client.text_generation(
            prompt,
            model=model,
            max_new_tokens=500,
            temperature=0.7,
            do_sample=True,
            return_full_text=False
        )
        return response.strip()
    except Exception as e:
        return f"Exception: {str(e)}"
