import os
import google.generativeai as genai

def ask_ai(question, context, model="gemini-1.5-flash", gemini_api_key=None):
    """
    Send a question with context to Google Gemini API and return the answer.
    """
    if not gemini_api_key:
        gemini_api_key = os.environ.get("GEMINI_API_KEY")
        if not gemini_api_key:
            return "Error: Gemini API key not configured."

    genai.configure(api_key=gemini_api_key)

    # List of models to try (order by preference, based on India availability)
    model_candidates = [
        model,                     # user-provided or default
        "gemini-1.5-flash",
        "gemini-1.5-flash-lite",
        "gemini-1.5-pro",
        "gemini-2.0-flash-exp"
    ]
    model_obj = None
    last_error = None
    for candidate in model_candidates:
        try:
            model_obj = genai.GenerativeModel(candidate)
            # Test with a minimal request to verify the model exists
            _ = model_obj.generate_content("test", generation_config={"max_output_tokens": 1})
            break
        except Exception as e:
            last_error = e
            continue
    if model_obj is None:
        return f"Error: No valid Gemini model found. Last error: {last_error}"

    # System instruction for chart/dashboard commands (same as before)
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
