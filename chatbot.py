import os
import google.generativeai as genai

def ask_ai(question, context, model="gemini-1.5-flash", gemini_api_key=None):
    if not gemini_api_key:
        gemini_api_key = os.environ.get("GEMINI_API_KEY")
        if not gemini_api_key:
            return "Error: Gemini API key not configured."

    genai.configure(api_key=gemini_api_key)
    model = genai.GenerativeModel(model)

    # Build prompt with chart/dashboard instructions
    system_msg = (
        "You are a cybersecurity assistant specialized in analyzing network traffic and vulnerabilities. "
        "Use the provided context to answer the user's question accurately and concisely.\n\n"
        "If the user asks for a chart, respond with exactly:\n"
        "CHART: <type>|<x_axis>|<y_axis>|<title>\n"
        "Where <type> is one of: bar, pie, line, heatmap, scatter.\n\n"
        "If the user asks for a dashboard, respond with:\n"
        "DASHBOARD: <title>|<chart1>|<chart2>|...\n"
        "Use semicolons to separate charts.\n\n"
        "If the request is not for a chart or dashboard, answer normally."
    )
    full_prompt = f"{system_msg}\n\nContext:\n{context}\n\nQuestion: {question}\n\nAnswer:"

    try:
        response = model.generate_content(full_prompt)
        return response.text.strip()
    except Exception as e:
        return f"Exception: {str(e)}"
