import os
import re
from groq import Groq

def ask_ai(question, context, model="llama-3.3-70b-versatile", groq_api_key=None):
    """
    Sends a question with context to Groq and returns the answer.
    If the user asks for a chart, the response will start with "CHART: type|..."
    which the app will interpret to generate a plot.
    """
    if not groq_api_key:
        groq_api_key = os.environ.get("GROQ_API_KEY")
        if not groq_api_key:
            return "Error: Groq API key not configured."

    client = Groq(api_key=groq_api_key)

    system_msg = (
        "You are a cybersecurity assistant specialized in analyzing network traffic and vulnerabilities. "
        "Use the provided context to answer the user's question accurately and concisely. "
        "The context may include asset details and associated vulnerabilities (CVE IDs with EPSS and KEV status). "
        "If the user asks for a chart (e.g., 'Show me a bar chart of asset types'), respond with exactly:\n"
        "CHART: <type>|<x_axis>|<y_axis>|<title>\n"
        "Where <type> is one of: bar, pie, line, heatmap, scatter.\n"
        "For pie charts, only x_axis is needed; y_axis can be omitted.\n"
        "For heatmap, use format: CHART: heatmap|<x_axis>|<y_axis>|<z_axis>|<title>\n"
        "If the request is not for a chart, answer normally without the CHART prefix."
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
