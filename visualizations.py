from flask import Blueprint, request, jsonify
import pandas as pd
import plotly.express as px
from utils import load_project_dataframe  # your helper that loads a file from storage or DB

visualizations_bp = Blueprint("visualizations", __name__)

@visualizations_bp.route("/api/visualizations", methods=["POST"])
def create_visualization():
    """
    Build a visualization from JSON instructions.
    Expected payload:
    {
      "fileId": 10,
      "instruction": {
        "chartType": "scatter",
        "x": "Revenue",
        "y": "Expenses",
        "color": "Region",
        "summary": "Example chart"
      }
    }
    """
    try:
        data = request.get_json()
        file_id = data.get("fileId")
        instruction = data.get("instruction", {})

        df = load_project_dataframe(file_id)
        chart_type = instruction.get("chartType")
        x = instruction.get("x")
        y = instruction.get("y")
        color = instruction.get("color")

        if not (chart_type and x and y):
            return jsonify({"type": "error", "message": "Missing chart parameters."})

        # === Chart builder ===
        if chart_type == "scatter":
            fig = px.scatter(df, x=x, y=y, color=color, title=instruction.get("summary", "Scatter Plot"))
        elif chart_type == "bar":
            fig = px.bar(df, x=x, y=y, color=color, title=instruction.get("summary", "Bar Chart"))
        elif chart_type == "line":
            fig = px.line(df, x=x, y=y, color=color, title=instruction.get("summary", "Line Chart"))
        elif chart_type == "box":
            fig = px.box(df, x=x, y=y, color=color, title=instruction.get("summary", "Box Plot"))
        else:
            return jsonify({"type": "error", "message": f"Unsupported chart type: {chart_type}"})

        # === Unified theme (Stochify dark mode) ===
        fig.update_layout(
            template="plotly_dark",
            font=dict(family="Inter", color="#e5e7eb"),
            paper_bgcolor="#0d0d0f",
            plot_bgcolor="#0d0d0f",
            margin=dict(l=40, r=40, t=60, b=40)
        )

        return jsonify({
            "type": "chart",
            "data": fig.data,
            "layout": fig.layout.to_plotly_json(),
            "summary": instruction.get("summary", "")
        })

    except Exception as e:
        return jsonify({"type": "error", "message": str(e)})
