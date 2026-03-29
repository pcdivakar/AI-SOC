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
        "If the user asks for a single chart, respond with:\n"
        "CHART: <type>|<param1>|<param2>|<param3>|<title>\n"
        "See the available chart types and parameters below.\n\n"
        "If the user asks for a dashboard (e.g., 'create a dashboard', 'show me a full dashboard'), "
        "respond with:\n"
        "DASHBOARD: <dashboard_title>|<chart1>|<chart2>|...\n"
        "Each chart is defined as <type>|<param1>|<param2>|<param3>|<title> (no 'CHART:' prefix).\n"
        "Use semicolons to separate charts.\n\n"
        "Valid chart types and parameters:\n"
        "- bar: bar|x_axis|y_axis|title  (y_axis optional)\n"
        "- pie: pie|names|values|title  (values optional)\n"
        "- line: line|x_axis|y_axis|title\n"
        "- scatter: scatter|x_axis|y_axis|color|title  (color optional)\n"
        "- histogram: histogram|column|bins|title  (bins optional)\n"
        "- box: box|column|group|title  (group optional)\n"
        "- violin: violin|column|group|title  (group optional)\n"
        "- heatmap: heatmap|x_axis|y_axis|z_axis|title\n"
        "- density_heatmap: density_heatmap|x_axis|y_axis|title\n"
        "- area: area|x_axis|y_axis|title\n"
        "- bubble: bubble|x_axis|y_axis|size|color|title\n"
        "- sunburst: sunburst|path1,path2,...|values|title  (path: comma‑separated)\n"
        "- treemap: treemap|path1,path2,...|values|title\n"
        "- scatter_map: scatter_map|lat|lon|color|size|title\n"
        "- choropleth: choropleth|locations|locationmode|color|title\n\n"
        "If the user asks for a dashboard, choose a reasonable set of 3–6 charts that give a good overview "
        "of the data (asset types, vendors, OS, protocol distribution, etc.).\n\n"
        "If the request is NOT for a chart or dashboard, answer normally without the CHART/DASHBOARD prefix."
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
