import os
from flask import Flask, redirect, url_for, jsonify, request
from flask_dance.contrib.google import make_google_blueprint, google
import jwt
from datetime import datetime, timedelta, timezone
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, redirect, url_for, jsonify, request, session
from urllib.parse import urlparse


# Initialize Flask
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
CORS(app, supports_credentials=True)

# JWT secret
JWT_SECRET = os.environ.get("JWT_SECRET", "jwt-secret-key")

google_bp = make_google_blueprint(
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    scope=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
    redirect_url="/oauth_callback"
)

# 👇 Add this line after creating the blueprint
google_bp.authorization_url_params["prompt"] = "select_account"

app.register_blueprint(google_bp, url_prefix="/login")


db_url = os.environ.get("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False, index=True)  # ties card to user
    title = db.Column(db.String(100), nullable=False)         # card title
    content = db.Column(db.Text, nullable=True)               # the text user writes
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

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
    return jsonify([
        {"id": c.id, "title": c.title, "content": c.content,
         "created_at": c.created_at.isoformat(),
         "updated_at": c.updated_at.isoformat()}
        for c in cards
    ])

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

# Routes
@app.route("/")
def home():
    return "Backend running. Go to /login/google to sign in with Google."

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
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # Use session-saved redirect, fallback to dashboard
    next_url = session.pop('oauth_next', None) or "https://stochify.com/dashboard"

    # Append token properly whether next_url already has query params or not
    sep = "&" if "?" in next_url else "?"
    final_redirect = f"{next_url}{sep}token={token}"

    return redirect(final_redirect)

ALLOWED_REDIRECT_HOSTS = ("stochify.com", "localhost")

@app.route("/login_with_redirect")
def login_with_redirect():
    # Accept either 'next' or 'redirect' for compatibility
    next_url = request.args.get("next") or request.args.get("redirect") or request.referrer or "/"
    # Make it absolute if it's relative
    if not urlparse(next_url).scheme:
        # If user provided a relative path, build full URL for stochify domain
        next_url = f"https://stochify.com{next_url}" if next_url.startswith("/") else f"https://stochify.com/{next_url}"

    # Security: allow only safe redirect targets
    if not is_safe_redirect_url(next_url):
        next_url = "https://stochify.com/dashboard.html"

    # Save the target in server-side session
    session['oauth_next'] = next_url

    # Start OAuth flow (Flask-Dance blueprint)
    return redirect(url_for("google.login"))


def is_safe_redirect_url(target: str) -> bool:
    if not target:
        return False
    try:
        parsed = urlparse(target)
    except Exception:
        return False
    # must be absolute URL with allowed host, or allow relative paths
    if parsed.netloc == "":
        return True
    host = parsed.hostname
    return host in ALLOWED_REDIRECT_HOSTS

@app.route("/api/user")
def get_user():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid token"}), 401

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return jsonify({
            "email": payload.get("email"),
            "name": payload.get("name"),
            "picture": payload.get("picture")
        })
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


# Logout (optional for JWT)
@app.route("/logout")
def logout():
    # JWT is client-side, so logout is just a frontend action
    return jsonify({"message": "Client should remove token"})

@app.route("/api/cards/<int:card_id>", methods=["GET"])
def get_card(card_id):
    email, error, code = get_current_user()
    if not email:
        return error, code

    card = Card.query.filter_by(id=card_id, email=email).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404

    return jsonify({
        "id": card.id,
        "title": card.title,
        "content": card.content,
        "created_at": card.created_at.isoformat(),
        "updated_at": card.updated_at.isoformat()
    })

@app.route("/api/create-sample", methods=["POST"])
def create_sample():
    email, error, code = get_current_user()
    if not email:
        return error, code

    # Read data sent from frontend
    data = request.json
    title = data.get("title")
    content = data.get("content")  # <-- CSV content sent from frontend

    if not title:
        return jsonify({"error": "Title required"}), 400
    if not content:
        return jsonify({"error": "CSV content required"}), 400

    # Create card using frontend-provided CSV content
    card = Card(email=email, title=title, content=content)
    db.session.add(card)
    db.session.commit()

    return jsonify({
        "id": card.id,
        "title": card.title,
        "content": card.content
    }), 201




if __name__ == "__main__":
    app.run(debug=True)
