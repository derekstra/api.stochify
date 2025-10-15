import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import Flask, redirect, url_for, jsonify, request, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

# OAuth blueprints
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github  # <- optional GitHub OAuth

# =========================================
# App & Config
# =========================================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
CORS(app, supports_credentials=True)

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
    email = user_info.get("email")
    name = user_info.get("name")
    picture = user_info.get("picture")

    payload = {
        "email": email,
        "name": name,
        "picture": picture,
        "exp": datetime.utcnow() + timedelta(days=7),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # Use session-saved redirect, fallback to dashboard
    next_url = session.pop("oauth_next", None) or "https://stochify.com/dashboard"
    sep = "&" if "?" in next_url else "?"
    final_redirect = f"{next_url}{sep}token={token}"

    return redirect(final_redirect)

# ---- Optional GitHub OAuth callback (additive only) ----
@app.route("/github_callback")
def github_callback():
    if not github.authorized:
        return redirect(url_for("github.login"))

    resp = github.get("/user")
    if not resp.ok:
        return jsonify({"error": "Failed to fetch GitHub user"}), 500

    user_info = resp.json()
    # Try to get email; GitHub may not include it here unless scope includes emails
    email = user_info.get("email")
    if not email:
        # Fallback: try /user/emails if permitted
        emails_resp = github.get("/user/emails")
        if emails_resp.ok:
            emails = emails_resp.json()
            primary = next((e["email"] for e in emails if e.get("primary")), None)
            email = primary or (emails[0]["email"] if emails else None)
    # last resort (keeps flow working even without public email)
    if not email:
        email = f"{user_info.get('login')}@github"

    name = user_info.get("name") or user_info.get("login")
    picture = user_info.get("avatar_url") or ""

    payload = {
        "email": email,
        "name": name,
        "picture": picture,
        "exp": datetime.utcnow() + timedelta(days=7),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # mirror Google flow
    next_url = session.pop("oauth_next", None) or "https://stochify.com/dashboard"
    sep = "&" if "?" in next_url else "?"
    final_redirect = f"{next_url}{sep}token={token}"
    return redirect(final_redirect)

# ---- Login with redirect helper (unchanged) ----
@app.route("/login_with_redirect")
def login_with_redirect():
    # Accept either 'next' or 'redirect' for compatibility
    next_url = request.args.get("next") or request.args.get("redirect") or request.referrer or "/"
    # Make it absolute if it's relative
    if not urlparse(next_url).scheme:
        next_url = f"https://stochify.com{next_url}" if next_url.startswith("/") else f"https://stochify.com/{next_url}"

    # Security: allow only safe redirect targets
    if not is_safe_redirect_url(next_url):
        next_url = "https://stochify.com/dashboard.html"

    # Save target in server-side session and start OAuth flow
    session["oauth_next"] = next_url
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
    return jsonify(
        [
            {
                "id": c.id,
                "title": c.title,
                "content": c.content,
                "created_at": c.created_at.isoformat(),
                "updated_at": c.updated_at.isoformat(),
            }
            for c in cards
        ]
    )

@app.route("/api/cards/<int:card_id>", methods=["GET"])
def get_card(card_id):
    email, error, code = get_current_user()
    if not email:
        return error, code

    card = Card.query.filter_by(id=card_id, email=email).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404

    return jsonify(
        {
            "id": card.id,
            "title": card.title,
            "content": card.content,
            "created_at": card.created_at.isoformat(),
            "updated_at": card.updated_at.isoformat(),
        }
    )

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
    """Accept uploaded CSV/JSON text OR uploaded file, store as a Card."""
    email, error, code = get_current_user()
    if not email:
        return error, code

    # Check content type to handle both JSON and multipart/form-data
    if request.content_type.startswith("application/json"):
        data = request.get_json(silent=True) or {}
        title = data.get("title")
        content = data.get("content")
    else:
        title = request.form.get("title")
        uploaded_file = request.files.get("file")
        content = None
        if uploaded_file:
            try:
                content = uploaded_file.read().decode("utf-8")
            except UnicodeDecodeError:
                return jsonify({"error": "File must be UTF-8 encoded"}), 400

    if not title:
        return jsonify({"error": "Missing project title"}), 400
    if not content:
        return jsonify({"error": "Missing content or file"}), 400

    # ---- Save as Card ----
    new_card = Card(email=email, title=title, content=content)
    db.session.add(new_card)
    db.session.commit()

    return jsonify({
        "message": "Project created successfully",
        "id": new_card.id,
        "title": new_card.title,
        "created_at": new_card.created_at.isoformat(),
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

# =========================================
# Main
# =========================================
if __name__ == "__main__":
    # Ensure tables exist (safe if already created)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
