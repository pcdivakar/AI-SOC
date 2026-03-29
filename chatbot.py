import os
import google.generativeai as genai

def ask_ai(question, context, model=None, gemini_api_key=None):
    """
    Send a question with context to Google Gemini API and return the answer.
    Dynamically selects the first available model that supports generateContent.
    """
    if not gemini_api_key:
        gemini_api_key = os.environ.get("GEMINI_API_KEY")
        if not gemini_api_key:
            return "Error: Gemini API key not configured."

    genai.configure(api_key=gemini_api_key)

    # Get all models that support generateContent
    try:
        all_models = genai.list_models()
        candidates = [m.name for m in all_models if 'generateContent' in m.supported_generation_methods]
        if not candidates:
            return "Error: No Gemini models available for content generation. Check API key and enable Generative Language API."
    except Exception as e:
        return f"Error listing models: {str(e)}"

    # If a specific model was requested, try it first; otherwise find a Flash model
    if model:
        test_models = [model] + candidates
    else:
        # Prefer models with 'flash' in name (gemini-1.5-flash, etc.)
        flash_models = [m for m in candidates if 'flash' in m.lower()]
        test_models = flash_models + candidates  # fallback to any model

    model_obj = None
    last_error = None
    for candidate in test_models:
        try:
            # Create model instance and test with a minimal request
            model_obj = genai.GenerativeModel(candidate)
            _ = model_obj.generate_content("test", generation_config={"max_output_tokens": 1})
            # Success
            break
        except Exception as e:
            last_error = e
            continue

    if model_obj is None:
        return f"Error: No working Gemini model found. Last error: {last_error}"

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

    full_prompt = f"{system_msg}\n\nContext:\n{context}\n\nQuestion: {question}\n\nAnswer:"

    try:
        response = model_obj.generate_content(full_prompt)
        return response.text.strip()
    except Exception as e:
        return f"Exception: {str(e)}"
