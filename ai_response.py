from flask import Blueprint, request, jsonify
import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
import io
import pandas as pd

ai_bp = Blueprint("ai", __name__)

# === Env ===
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Normalize Postgres URL
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# ---------- DB helper ----------
def get_project_text(card_id: int):
    """
    Fetches the text representation of a project.
    - Prefers Asset.text_content
    - If only blob_content exists (Excel), converts to CSV text using pandas
    - Falls back to Card.content if neither found
    """
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode="require")
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT 
                    c.title,
                    c.content,
                    a.text_content,
                    a.blob_content,
                    a.mime_type
                FROM card c
                LEFT JOIN asset a ON a.card_id = c.id
                WHERE c.id = %s
                ORDER BY a.created_at DESC
                LIMIT 1;
                """,
                (card_id,),
            )
            row = cur.fetchone()
        conn.close()

        if not row:
            return "No data found for this project."

        # 1️⃣ Prefer stored text version
        if row.get("text_content"):
            return row["text_content"]

        # 2️⃣ Otherwise, try to extract from Excel blob
        if row.get("blob_content"):
            try:
                excel_bytes = io.BytesIO(row["blob_content"])
                sheets = pd.read_excel(excel_bytes, sheet_name=None)
                parts = []
                for name, df in sheets.items():
                    parts.append(f"--- Sheet: {name} ---\n")
                    parts.append(df.to_csv(index=False))
                    parts.append("\n\n")
                return "".join(parts)
            except Exception as e:
                print("⚠️ Failed to extract Excel text:", e)
                return "Unable to extract readable text from Excel file."

        # 3️⃣ Fallback: old-style Card.content
        return row.get("content") or "No text content available."

    except Exception as e:
        print("❌ DB error in get_project_text:", e)
        return "Error fetching project text."


# ---------- Model Handlers ----------

def call_groq(full_prompt, temperature, max_words=300):
    """Send a chat request to Groq."""
    try:
        groq_payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": full_prompt}],
            "temperature": temperature,
            "max_tokens": max_words * 2,
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
        return (
            j.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )

    except Exception as e:
        print("❌ Exception in call_groq:", e)
        return "Error calling Groq."


def call_gemini(full_prompt, temperature=0.3, max_words=300):
    """Send a chat request to Gemini 2.5 Flash-Lite."""
    try:
        if not GEMINI_API_KEY:
            return "Gemini API key missing."

        gemini_url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-2.5-flash-lite:generateContent?key={GEMINI_API_KEY}"
        )

        payload = {
            "contents": [{"parts": [{"text": full_prompt}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_words * 2,
                "topP": 0.95,
                "topK": 64,
            },
        }

        resp = requests.post(
            gemini_url,
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=60,
        )

        if resp.status_code != 200:
            print("❌ Gemini API error:", resp.status_code, resp.text)
            return f"Gemini API request failed ({resp.status_code})."

        j = resp.json()
        text = (
            j.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
            .strip()
        )

        return text or "No response from Gemini."

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
        "project_id": 123,
        "model": "groq" or "gemini",
        "temperature": 0.5
      }
    Combines user question with project text (from asset or content).
    """
    try:
        data = request.get_json(force=True) or {}

        prompt = (data.get("prompt") or "").strip()
        if not prompt:
            return jsonify({"error": "Missing prompt"}), 400

        project_id = data.get("project_id")
        model_choice = (data.get("model") or "groq").lower()
        temperature = float(data.get("temperature", 0.3))
        max_words = 300

        # ---------- Get full project text ----------
        project_text = ""
        if project_id is not None:
            project_text = get_project_text(project_id)
        else:
            project_text = "No project context provided."

        # ---------- Compose final AI prompt ----------
        full_prompt = (
            f"Project data:\n{project_text}\n\n"
            "Instruction:\n"
            "You are Stochify, an AI data assistant. Use the dataset above to answer questions, "
            "analyze trends, or summarize findings. Be precise, factual, and concise.\n\n"
            f"User question:\n{prompt}"
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
