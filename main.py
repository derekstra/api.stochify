import os
import io
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, quote
from mimetypes import guess_type
from io import BytesIO

import jwt
import pandas as pd
from charset_normalizer import from_bytes as detect_encoding
from flask import (
    Flask, redirect, url_for, jsonify, request, session, send_file
)
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# OAuth Blueprints
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github  # Optional: GitHub OAuth

# Local Blueprints
from ai_response import ai_bp


ALLOWED_TEXT_EXT = {'.csv', '.json', '.txt'}
ALLOWED_EXCEL_EXT = {'.xlsx', '.xls'}


# =========================================
# App & Config
# =========================================
app = Flask(__name__)
app.register_blueprint(ai_bp)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
CORS(app, resources={
    r"/*": {
        "origins": [
            "https://stochify.com",
            "https://www.stochify.com",
            "http://localhost:5173"
        ],
        "supports_credentials": True,
        "allow_headers": ["Content-Type", "Authorization"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    }
})

# JWT secret
JWT_SECRET = os.environ.get("JWT_SECRET", "jwt-secret-key")

# Normalize Postgres URL (Render compatibility)
db_url = os.environ.get("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# =========================================
# Models
# =========================================
class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False, index=True)   # ties card to user
    title = db.Column(db.String(100), nullable=False)          # card title
    content = db.Column(db.Text, nullable=True)                # the text user writes
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=True)
    picture = db.Column(db.String(255), nullable=True)

class Asset(db.Model):
    """Backs a Card with the original uploaded file or text."""
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.Integer, db.ForeignKey('card.id', ondelete="CASCADE"), index=True)
    file_name = db.Column(db.String(255), nullable=True)
    mime_type = db.Column(db.String(100), nullable=True)
    encoding = db.Column(db.String(40), nullable=True)    # for text files
    size_bytes = db.Column(db.Integer, nullable=True)
    text_content = db.Column(db.Text, nullable=True)      # csv/json/txt stored as text
    blob_content = db.Column(db.LargeBinary, nullable=True)  # excel or any binary
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    card = db.relationship('Card', backref=db.backref('assets', lazy=True))

# =========================================
# OAuth Blueprints
# =========================================
google_bp = make_google_blueprint(
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    scope=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
    redirect_url="/oauth_callback",
)
google_bp.authorization_url_params["prompt"] = "select_account"
app.register_blueprint(google_bp, url_prefix="/login")

# Optional GitHub OAuth (safe addition; does not change existing behavior)
github_bp = make_github_blueprint(
    client_id=os.environ.get("GITHUB_CLIENT_ID"),
    client_secret=os.environ.get("GITHUB_CLIENT_SECRET"),
    redirect_url="/github_callback",
)
github_bp.authorization_url_params["prompt"] = "login"
app.register_blueprint(github_bp, url_prefix="/login")

# =========================================
# Helpers
# =========================================
def get_current_user():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, jsonify({"error": "Missing or invalid token"}), 401

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload.get("email"), None, None
    except jwt.ExpiredSignatureError:
        return None, jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return None, jsonify({"error": "Invalid token"}), 401

ALLOWED_REDIRECT_HOSTS = ("stochify.com", "localhost")

def is_safe_redirect_url(target: str) -> bool:
    if not target:
        return False
    try:
        parsed = urlparse(target)
    except Exception:
        return False
    # allow relative paths (no host), or absolute with allowed host
    if parsed.netloc == "":
        return True
    host = parsed.hostname
    return host in ALLOWED_REDIRECT_HOSTS

# =========================================
# Routes
# =========================================
@app.route("/")
def home():
    # keep original message
    return "Backend running. Go to /login/google to sign in with Google."

# ---- Google OAuth callback (unchanged behavior) ----
@app.route("/oauth_callback")
def oauth_callback():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return jsonify({"error": "Failed to fetch user info"}), 500

    user_info = resp.json()
    payload = {
        "email":   user_info.get("email"),
        "name":    user_info.get("name"),
        "picture": user_info.get("picture"),
        "exp":     datetime.utcnow() + timedelta(days=7),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    next_page = request.args.get("next", "/dashboard")
    if not next_page.startswith("/"):
        next_page = "/dashboard"

    return redirect(f"https://stochify.com{next_page}?token={token}")


@app.route("/login/github_with_redirect")
def github_with_redirect():
    next_url = request.args.get("next", "/dashboard")
    if not next_url.startswith("/"):
        next_url = "/dashboard"

    callback_with_next = f"https://api.stochify.com/github_callback?next={next_url}"
    github_bp.redirect_url = callback_with_next
    return redirect(url_for("github.login"))


@app.route("/github_callback")
def github_callback():
    if not github.authorized:
        return redirect(url_for("github.login"))

    resp = github.get("/user")
    if not resp.ok:
        return jsonify({"error": "Failed to fetch GitHub user"}), 500

    user_info = resp.json()

    email = user_info.get("email")
    if not email:
        emails_resp = github.get("/user/emails")
        if emails_resp.ok:
            emails = emails_resp.json()
            primary = next((e.get("email") for e in emails if e.get("primary")), None)
            email = primary or (emails[0].get("email") if emails else None)
    if not email:
        email = f"{user_info.get('login')}@github"

    payload = {
        "email":   email,
        "name":    user_info.get("name") or user_info.get("login"),
        "picture": user_info.get("avatar_url") or "",
        "exp":     datetime.utcnow() + timedelta(days=7),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    next_page = request.args.get("next", "/dashboard")
    if not next_page.startswith("/"):
        next_page = "/dashboard"

    return redirect(f"https://stochify.com{next_page}?token={token}")


@app.route("/login_with_redirect")
def login_with_redirect():
    next_url = request.args.get("next", "/dashboard")
    if not next_url.startswith("/"):
        next_url = "/dashboard"

    encoded_next = urllib.parse.quote(next_url, safe="")
    callback_with_next = f"https://api.stochify.com/oauth_callback?next={encoded_next}"

    google_bp.redirect_url = callback_with_next
    return redirect(url_for("google.login"))

# ---- Authenticated user info (unchanged) ----
@app.route("/api/user")
def get_user():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid token"}), 401

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return jsonify(
            {
                "email": payload.get("email"),
                "name": payload.get("name"),
                "picture": payload.get("picture"),
            }
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

# ---- Logout note (unchanged) ----
@app.route("/logout")
def logout():
    # JWT is client-side, so logout is just a frontend action
    return jsonify({"message": "Client should remove token"})

# ---- Cards CRUD (unchanged) ----
@app.route("/api/cards", methods=["POST"])
def create_card():
    email, error, code = get_current_user()
    if not email:
        return error, code

    data = request.json
    title = data.get("title")
    content = data.get("content", "")

    if not title:
        return jsonify({"error": "Title is required"}), 400

    card = Card(email=email, title=title, content=content)
    db.session.add(card)
    db.session.commit()

    return jsonify({"id": card.id, "title": card.title, "content": card.content}), 201

@app.route("/api/cards", methods=["GET"])
def get_cards():
    email, error, code = get_current_user()
    if not email:
        return error, code

    cards = Card.query.filter_by(email=email).order_by(Card.created_at.desc()).all()
    result = []

    for c in cards:
        # Find the latest asset linked to this card
        asset = (
            Asset.query.filter_by(card_id=c.id)
            .order_by(Asset.created_at.desc())
            .first()
        )

        text_preview = None
        if asset and asset.text_content:
            # limit preview size to keep response light
            text_preview = asset.text_content[:500]

        result.append({
            "id": c.id,
            "title": c.title,
            "content": c.content,  # still keep for notes or manual projects
            "preview": text_preview,  # <-- 🔥 text version for your card
            "created_at": c.created_at.isoformat(),
            "updated_at": c.updated_at.isoformat(),
        })

    return jsonify(result)

@app.route("/api/cards/<int:card_id>", methods=["GET"])
def get_card(card_id):
    email, error, code = get_current_user()
    if not email:
        return error, code

    card = Card.query.filter_by(id=card_id, email=email).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404

    asset = Asset.query.filter_by(card_id=card.id).order_by(Asset.created_at.desc()).first()

    card_json = {
        "id": card.id,
        "title": card.title,
        "content": card.content,
        "created_at": card.created_at.isoformat(),
        "updated_at": card.updated_at.isoformat(),
    }

    if asset:
        card_json["asset"] = {
            "id": asset.id,
            "card_id": asset.card_id,
            "file_name": asset.file_name,
            "mime_type": asset.mime_type,
            "size_bytes": asset.size_bytes,
            "encoding": asset.encoding,
        }

    return jsonify(card_json)


@app.route("/api/cards/<int:card_id>", methods=["PUT"])
def update_card(card_id):
    email, error, code = get_current_user()
    if not email:
        return error, code

    card = Card.query.filter_by(id=card_id, email=email).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404

    data = request.json
    card.title = data.get("title", card.title)
    card.content = data.get("content", card.content)
    db.session.commit()

    return jsonify({"id": card.id, "title": card.title, "content": card.content})

@app.route("/api/cards/<int:card_id>", methods=["DELETE"])
def delete_card(card_id):
    email, error, code = get_current_user()
    if not email:
        return error, code

    card = Card.query.filter_by(id=card_id, email=email).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404

    db.session.delete(card)
    db.session.commit()
    return jsonify({"message": "Card deleted"})

# ---- Sample creation (unchanged) ----
@app.route("/api/create-sample", methods=["POST"])
def create_sample():
    email, error, code = get_current_user()
    if not email:
        return error, code

    data = request.json
    title = data.get("title")
    content = data.get("content")  # CSV/text content from frontend

    if not title:
        return jsonify({"error": "Title required"}), 400
    if not content:
        return jsonify({"error": "CSV content required"}), 400

    card = Card(email=email, title=title, content=content)
    db.session.add(card)
    db.session.commit()

    return jsonify({"id": card.id, "title": card.title, "content": card.content}), 201

# ---- Email/password auth (new; additive only) ----
@app.route("/api/register", methods=["POST"])
def register_user():
    data = request.json or {}
    email = data.get("email")
    password = data.get("password")
    name = data.get("name", "")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 400

    hashed_pw = generate_password_hash(password)
    user = User(email=email, password_hash=hashed_pw, name=name)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@app.route("/api/projects", methods=["POST"])
def create_project():
    """
    Accepts:
      - JSON body: {title, content, [filename?, mimetype?]}
      - multipart/form-data: fields: title, file
    Stores:
      - CSV/JSON/TXT as text_content (decoded)
      - Excel as blob_content (raw bytes)
    Also creates a Card row for the project.
    """
    email, error, code = get_current_user()
    if not email:
        return error, code

    title = None
    file_obj = None
    text_payload = None
    filename = None
    mimetype = None
    encoding = None
    size_bytes = None

    ct = (request.content_type or "").lower()

    if ct.startswith("application/json"):
        data = request.get_json(silent=True) or {}
        title = (data.get("title") or "").strip()
        text_payload = data.get("content")  # raw text (csv/json/txt)
        filename = data.get("filename")
        mimetype = data.get("mimetype") or (guess_type(filename or "")[0] if filename else None)
        # assume UTF-8 for JSON body
        encoding = "utf-8" if text_payload is not None else None
        if text_payload is not None:
            size_bytes = len(text_payload.encode("utf-8"))
    else:
        title = (request.form.get("title") or "").strip()
        file_obj = request.files.get("file")

        if file_obj:
            filename = file_obj.filename
            mimetype = file_obj.mimetype or guess_type(filename or "")[0]
            raw = file_obj.read()
            size_bytes = len(raw)

            # Choose by extension
            ext = (os.path.splitext(filename or "")[1] or "").lower()

            if ext in ALLOWED_TEXT_EXT:
                # Try UTF-8 first; fallback to detected encoding
                try:
                    text_payload = raw.decode("utf-8")
                    encoding = "utf-8"
                except UnicodeDecodeError:
                    probe = detect_encoding(raw).best()
                    if not probe or not probe.encoding:
                        return jsonify({"error": "Unable to detect text encoding; please upload UTF-8"}), 400
                    encoding = probe.encoding
                    text_payload = raw.decode(encoding, errors="replace")
            elif ext in ALLOWED_EXCEL_EXT:
                # Store as binary (don’t attempt to parse)
                encoding = None
                blob_bytes = raw
            else:
                return jsonify({"error": "Unsupported file type. Allowed: .csv, .json, .txt, .xlsx, .xls"}), 400
        else:
            return jsonify({"error": "Missing content or file"}), 400

    if not title:
        return jsonify({"error": "Missing project title"}), 400

    # Create the Card (project)
    card = Card(email=email, title=title, content=None)  # keep content optional/for notes
    db.session.add(card)
    db.session.flush()  # get card.id

    # Create Asset depending on source
    asset = Asset(
        card_id=card.id,
        file_name=filename,
        mime_type=mimetype,
        encoding=encoding,
        size_bytes=size_bytes
    )

    # ---- Store text and/or binary versions ----
    if text_payload is not None:
        # ✅ Text-based files (CSV, JSON, TXT)
        asset.text_content = text_payload

        # Keep binary too (optional safety copy)
        asset.blob_content = text_payload.encode(encoding or "utf-8")

    elif blob_bytes:
        # ✅ Excel or other binary files
        asset.blob_content = blob_bytes

        # Always attempt to create a readable text version
        text_version = ""
        try:
            excel_buf = io.BytesIO(blob_bytes)
            sheets = pd.read_excel(excel_buf, sheet_name=None, engine="openpyxl")

            text_parts = []
            for sheet_name, df in sheets.items():
                text_parts.append(f"--- Sheet: {sheet_name} ---\n")
                # Limit rows to avoid massive output
                preview_df = df.head(50)
                text_parts.append(preview_df.to_csv(index=False))
                text_parts.append("\n\n")

            text_version = "".join(text_parts)
        except Exception as e:
            print(f"[Excel preview warning] Could not parse Excel with pandas: {e}")
            try:
                # Fallback: basic binary-to-text dump of the first few KB
                decoded = blob_bytes[:8192].decode("utf-8", errors="ignore")
                text_version = "--- Raw Excel bytes preview (partial) ---\n" + decoded
            except Exception as e2:
                print(f"[Excel fallback failed] {e2}")
                text_version = ""

        if text_version:
            asset.text_content = text_version
            asset.encoding = "utf-8"
            asset.size_bytes = len(text_version.encode("utf-8"))

    db.session.add(asset)
    db.session.commit()

    return jsonify({
        "message": "Project created",
        "card_id": card.id,
        "asset_id": asset.id,
        "title": card.title,
        "filename": asset.file_name,
        "mimetype": asset.mime_type,
        "encoding": asset.encoding,
        "size_bytes": asset.size_bytes,
        "created_at": card.created_at.isoformat(),
    }), 201

@app.route("/api/login", methods=["POST"])
def login_user():
    data = request.json or {}
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    payload = {
        "email": user.email,
        "name": user.name or user.email.split("@")[0],
        "picture": user.picture or "",
        "exp": datetime.utcnow() + timedelta(days=7),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})

@app.route("/api/projects/<int:card_id>/assets/<int:asset_id>/download", methods=["GET"])
def download_asset(card_id, asset_id):
    email, error, code = get_current_user()
    if not email:
        return error, code

    asset = Asset.query.join(Card, Asset.card_id == Card.id)\
        .filter(Asset.id == asset_id, Card.id == card_id, Card.email == email).first()
    if not asset:
        return jsonify({"error": "Not found"}), 404

    filename = asset.file_name or f"asset-{asset.id}"
    mime = asset.mime_type or "application/octet-stream"

    if asset.blob_content:
        return send_file(BytesIO(asset.blob_content), mimetype=mime,
                         as_attachment=True, download_name=filename)

    # text → send as bytes (UTF-8)
    data = (asset.text_content or "").encode(asset.encoding or "utf-8", errors="replace")
    return send_file(BytesIO(data), mimetype=mime or "text/plain; charset=utf-8",
                     as_attachment=True, download_name=filename)

@app.route("/debug/excel_text/<int:card_id>")
def debug_excel_text(card_id):
    asset = (
        Asset.query.filter_by(card_id=card_id)
        .order_by(Asset.created_at.desc())
        .first()
    )
    if not asset:
        return jsonify({"error": "No asset found"}), 404

    return jsonify({
        "file_name": asset.file_name,
        "mime_type": asset.mime_type,
        "has_text_content": bool(asset.text_content),
        "text_preview": asset.text_content[:500] if asset.text_content else None,
    })


# =========================================
# Main
# =========================================
if __name__ == "__main__":
    # Ensure tables exist (safe if already created)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
