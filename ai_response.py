from flask import Blueprint, request, jsonify
import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor

ai_bp = Blueprint("ai", __name__)

# === Env ===
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Normalize postgres URI (Render sometimes gives postgres://)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# ---------- DB helper ----------
def get_project_content(card_id: int):
    """Fetch project content from the card table."""
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode="require")
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
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


# ---------- Model Handlers ----------

def call_groq(full_prompt, temperature, max_words=300):
    """Send a chat request to Groq."""
    try:
        groq_payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": full_prompt}],
            "temperature": temperature,
            "max_tokens": max_words * 2,  # safe fixed limit
        }

        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json=groq_payload,
            timeout=60,
        )

        if resp.status_code != 200:
            print("❌ Groq API error:", resp.text)
            return "Groq API request failed."

        j = resp.json()
        return (j.get("choices", [{}])[0].get("message", {}).get("content", "") or "").strip()

    except Exception as e:
        print("❌ Exception in call_groq:", e)
        return "Error calling Groq."


def call_gemini(full_prompt, temperature, max_words):
    """Send a chat request to Google Gemini (AI Studio v1beta)."""
    try:
        if not GEMINI_API_KEY:
            return "Gemini API key missing."

        # ✅ Correct endpoint
        gemini_url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-1.5-flash-latest:generateContent?key={GEMINI_API_KEY}"
        )

        gemini_payload = {
            "contents": [{"parts": [{"text": full_prompt}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_words * 2,
            },
        }

        resp = requests.post(
            gemini_url,
            headers={"Content-Type": "application/json"},
            json=gemini_payload,
            timeout=60,
        )

        if resp.status_code != 200:
            print("❌ Gemini API error:", resp.status_code, resp.text)
            return f"Gemini API request failed ({resp.status_code})."

        j = resp.json()
        return (
            j.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
            .strip()
        )

    except Exception as e:
        print("❌ Exception in call_gemini:", e)
        return "Error calling Gemini."



# ---------- Main Route ----------

@ai_bp.route("/airesponse", methods=["POST"])
def ai_response():
    """
    Expects JSON:
      {
        "prompt": "...",
        "project_id": 94,
        "model": "groq" or "gemini",
        "temperature": 0.5
      }
    """
    try:
        data = request.get_json(force=True) or {}

        prompt = (data.get("prompt") or "").strip()
        if not prompt:
            return jsonify({"error": "Missing prompt"}), 400

        project_id = data.get("project_id")
        model_choice = (data.get("model") or "groq").lower()
        temperature = float(data.get("temperature", 0.3))
        max_words = 300  # ✅ fixed predefined max length

        # ---------- Build context ----------
        project_context = ""
        if project_id is not None:
            project = get_project_content(project_id)
            if project:
                title = project.get("title") or "Untitled"
                content = (project.get("content") or "")[:3000]
                project_context = f"Project Title: {title}\nContext:\n{content}\n"
            else:
                print(f"⚠️ No project found for ID {project_id}; proceeding without DB context.")

        # ---------- Compose final prompt ----------
        full_prompt = (
            f"Context:\n{project_context}\n\n"
            "Instruction:\n"
            "Analyze the context and answer accurately, clearly, and conversationally. "
            "Keep replies polite, direct, and factual. If no valid question is found, "
            "encourage the user to ask a clear one related to the data.\n\n"
            f"Question:\n{prompt}"
        )

        # ---------- Model Routing ----------
        if model_choice == "gemini":
            reply = call_gemini(full_prompt, temperature, max_words)
        elif model_choice == "groq":
            reply = call_groq(full_prompt, temperature, max_words)
        else:
            return jsonify({"error": f"Unsupported model: {model_choice}"}), 400

        return jsonify({"reply": reply or "No response."})

    except Exception as e:
        import traceback
        print("❌ Server error in /airesponse:", e)
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500
