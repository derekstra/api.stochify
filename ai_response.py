# ai_response.py
from flask import Blueprint, request, jsonify
import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor

# =====================================================
# 🔹 Setup Blueprint
# =====================================================
ai_bp = Blueprint("ai", __name__)

# =====================================================
# 🔹 Load Environment Variables
# =====================================================
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")  # Render or local PostgreSQL

# =====================================================
# 🔹 Helper: Fetch Project Content
# =====================================================
def get_project_content(project_id):
    """Fetch project content from PostgreSQL cards table."""
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode="require")
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT title, content FROM cards WHERE id = %s;", (project_id,))
        project = cur.fetchone()
        cur.close()
        conn.close()
        return project
    except Exception as e:
        print("DB error:", e)
        return None

# =====================================================
# 🔹 POST /airesponse
# =====================================================
@ai_bp.route("/airesponse", methods=["POST"])
def ai_response():
    """
    Takes JSON:
        { "prompt": "Explain the data", "project_id": "123" }

    Returns JSON:
        { "reply": "The dataset shows..." }
    """
    try:
        data = request.get_json()
        prompt = data.get("prompt", "").strip()
        project_id = data.get("project_id")

        if not prompt:
            return jsonify({"error": "Missing prompt"}), 400

        # Optionally retrieve file content
        project_context = ""
        if project_id:
            project = get_project_content(project_id)
            if project:
                project_context = (
                    f"Project Title: {project['title']}\n\n"
                    f"Project Content:\n{project['content'][:3000]}"  # limit context size
                )

        # Combine context with user question
        full_prompt = (
            f"You are Stochify, an AI analyst helping the user understand data projects.\n\n"
            f"{project_context}\n\n"
            f"User Question:\n{prompt}\n\n"
            f"Answer clearly, concisely, and use math/analytics reasoning where possible."
        )

        # =====================================================
        # 🔹 Call Groq API
        # =====================================================
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "llama-3.2-70b-versatile",
                "messages": [{"role": "user", "content": full_prompt}],
                "temperature": 0.7,
                "max_tokens": 600,
            },
        )

        if response.status_code != 200:
            print("Groq error:", response.text)
            return jsonify({"error": "AI request failed"}), 500

        reply = response.json()["choices"][0]["message"]["content"].strip()
        return jsonify({"reply": reply})

    except Exception as e:
        print("Server error:", e)
        return jsonify({"error": "Internal server error"}), 500
