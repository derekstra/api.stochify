# ai_response.py
from flask import Blueprint, request, jsonify
import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor

ai_bp = Blueprint("ai", __name__)

# === Env ===
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Normalize postgres URI if needed (Render sometimes gives postgres://)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# ---------- DB helper ----------
def get_project_content(card_id: int):
    """
    Fetch project content from the *card* table (singular),
    matching your SQLAlchemy model `class Card(db.Model)`.
    """
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode="require")
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # NOTE: table is `card` (singular), not `cards`
            cur.execute(
                """
                SELECT id, title, content, created_at
                FROM card
                WHERE id = %s;
                """,
                (card_id,),
            )
            row = cur.fetchone()
        conn.close()
        return row
    except Exception as e:
        print("❌ DB error in get_project_content:", e)
        return None

@ai_bp.route("/airesponse", methods=["POST"])
def ai_response():
    """
    Expects JSON:
      { "prompt": "...", "project_id": 94 }

    Returns:
      { "reply": "..." }
    """
    try:
        data = request.get_json(force=True) or {}
        prompt = (data.get("prompt") or "").strip()
        project_id = data.get("project_id")

        if not prompt:
            return jsonify({"error": "Missing prompt"}), 400

        # ---------- Build context from DB (if provided) ----------
        project_context = ""
        if project_id is not None:
            project = get_project_content(project_id)
            if project:
                title = project.get("title") or "Untitled"
                created_at = project.get("created_at")
                created_str = str(created_at) if created_at is not None else "N/A"
                content = (project.get("content") or "")[:3000]  # keep prompt tight

                project_context = (
                    f"Project Title: {title}\n"
                    f"Created At: {created_str}\n\n"
                    f"Project Content (truncated):\n{content}\n"
                )
            else:
                print(f"⚠️ No project found for ID {project_id}; proceeding without DB context.")

        # ---------- Compose final prompt ----------
        full_prompt = (
            "You are Stochify, an AI data analyst. "
            "Interpret datasets and projects with clear, concise, math-savvy explanations. "
            "If relevant, list quick bullet insights.\n\n"
            f"{project_context}"
            f"User Question:\n{prompt}"
        )

        # ---------- Call Groq ----------
        groq_req = {
            "model": "llama-3.3-70b-versatile",  # supported & fast
            "messages": [{"role": "user", "content": full_prompt}],
            "temperature": 0.7,
            "max_tokens": 700,
        }

        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json=groq_req,
            timeout=60,
        )

        if resp.status_code != 200:
            print("❌ Groq error:", resp.text)
            return jsonify({"error": "Groq API request failed"}), 500

        j = resp.json()
        if "choices" not in j or not j["choices"]:
            print("❌ Unexpected Groq response:", j)
            return jsonify({"error": "Unexpected AI response"}), 500

        reply = (j["choices"][0]["message"]["content"] or "").strip()
        return jsonify({"reply": reply})

    except Exception as e:
        import traceback
        print("❌ Server error in /airesponse:", e)
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500
