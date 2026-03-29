import os
from groq import Groq

def ask_ai(question, context, model="llama-3.3-70b-versatile", groq_api_key=None):
    if not groq_api_key:
        groq_api_key = os.environ.get("GROQ_API_KEY")
        if not groq_api_key:
            return "Error: Groq API key not configured."

    client = Groq(api_key=groq_api_key)

    system_msg = (
        "You are a cybersecurity assistant. Use the provided context to answer questions.\n\n"
        "If the user asks for a chart, you MUST respond with exactly one line in the following format:\n"
        "CHART: <type>|<x_axis>|<y_axis>|<title>\n\n"
        "Valid types: bar, pie, line, heatmap, scatter.\n"
        "For pie charts, only x_axis is needed; y_axis can be empty.\n"
        "For heatmap, use: CHART: heatmap|<x_axis>|<y_axis>|<z_axis>|<title>\n\n"
        "Examples:\n"
        "- 'Show me a bar chart of asset types' → CHART: bar|asset_type||Asset Types Distribution\n"
        "- 'Create a pie chart of vendors' → CHART: pie|vendor||Vendor Distribution\n"
        "- 'Line chart of EPSS scores per CVE' → CHART: line|cve_id|epss|EPSS Scores\n"
        "- 'Heatmap of ports by IP' → CHART: heatmap|ip|port|cves|Port Activity Heatmap\n\n"
        "If the question is NOT about a chart, answer normally without the CHART prefix."
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
