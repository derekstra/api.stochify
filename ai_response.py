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
# 🔹 Helper: Fetch Project from Cards Table
# =====================================================
def fetch_card_by_id(card_id):
    """Fetch a project card (title + content) by its ID from PostgreSQL."""
    conn = None
    project = None
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode="require")
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, email, title, content, created_at, updated_at
                FROM cards
                WHERE id = %s;
                """,
                (card_id,),
            )
            project = cur.fetchone()
    except Exception as e:
        print("❌ Database error in fetch_card_by_id:", e)
    finally:
        if conn:
            conn.close()
    return project

# =====================================================
# 🔹 POST /airesponse
# =====================================================
@ai_bp.route("/airesponse", methods=["POST"])
def ai_response():
    """
    Expects JSON:
        { "prompt": "Explain the dataset", "project_id": "94" }

    Returns JSON:
        { "reply": "The dataset shows..." }
    """
    try:
        data = request.get_json(force=True)
        prompt = (data.get("prompt") or "").strip()
        project_id = data.get("project_id")

        if not prompt:
            return jsonify({"error": "Missing prompt"}), 400

        # =====================================================
        # 🔹 Get Project Context (same as /api/cards/:id)
        # =====================================================
        project_context = ""
        if project_id:
            card = fetch_card_by_id(project_id)
            if card:
                project_context = (
                    f"Project Title: {card['title']}\n"
                    f"Created At: {card['created_at']}\n\n"
                    f"Project Content (truncated):\n{(card['content'] or '')[:3000]}"
                )
            else:
                print(f"⚠️ No project found for ID {project_id}")

        # =====================================================
        # 🔹 Build Full Prompt
        # =====================================================
        full_prompt = (
            "You are Stochify, an AI data analyst. "
            "You help users interpret datasets and projects. "
            "Provide step-by-step reasoning and clear insights.\n\n"
            f"{project_context}\n\n"
            f"User Question:\n{prompt}"
        )

        # =====================================================
        # 🔹 Call Groq API (LLama-3.2)
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
            timeout=60,
        )

        # Handle non-200 Groq responses
        if response.status_code != 200:
            print("❌ Groq error:", response.text)
            return jsonify({"error": "Groq API request failed"}), 500

        groq_json = response.json()
        if "choices" not in groq_json:
            print("❌ Unexpected Groq response:", groq_json)
            return jsonify({"error": "Unexpected AI response"}), 500

        reply = groq_json["choices"][0]["message"]["content"].strip()
        return jsonify({"reply": reply})

    except Exception as e:
        import traceback
        print("❌ Server error in /airesponse:", e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
