import os
import sqlite3
import datetime
import json
import traceback
from functools import wraps
from urllib.parse import urlparse
from collections import Counter

import jwt
import pandas as pd
import joblib
from flask import Flask, request, g, jsonify, send_from_directory, render_template
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash  # NEW: password hashing

# -------------------------
# Import analysis modules
# -------------------------
from modules.homoglyph import analyze_homoglyph, fuzzy_confusable_score
from modules.behavior import analyze_behavior  # per-request human behavior (typing, mouse, etc.)
from modules.behavior_profile import compute_behavior_profile  # session history profile
from modules.features import extract_features_from_url, FEATURE_VERSION, FEATURE_DEFAULTS
from modules.blacklist import (
    is_blacklisted as file_blacklist_contains,
    add_to_blacklist as add_domain_to_file_blacklist,
    remove_from_blacklist as remove_domain_from_file_blacklist,
)

# -------------------------
# Paths, async mode, app setup
# -------------------------
async_mode = os.environ.get("ASYNC_MODE", "gevent")

ROOT_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(ROOT_DIR, "phishing_logs.db")
MODEL_PATH = os.path.join(ROOT_DIR, "rf_model.joblib")

# Serve static frontend from 'web' directory
app = Flask(__name__, static_folder="web", static_url_path="")
allowed_origins = os.environ.get("CORS_ALLOW_ORIGINS", "*")
cors_origins = [o.strip() for o in allowed_origins.split(",")] if allowed_origins != "*" else "*"

CORS(
    app,
    resources={r"/api/*": {"origins": cors_origins}},
    supports_credentials=True,
    expose_headers=["Authorization"],
)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "phishguard-final-secret")

socketio = SocketIO(
    app,
    cors_allowed_origins=cors_origins if isinstance(cors_origins, list) else "*",
    async_mode=async_mode,
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[os.environ.get("DEFAULT_RATE_LIMIT", "120 per minute")],
    storage_uri=os.environ.get("RATE_LIMIT_STORAGE_URI", "memory://"),
)

CHECK_RATE_LIMIT = os.environ.get("CHECK_RATE_LIMIT", "40/minute")
ADMIN_RATE_LIMIT = os.environ.get("ADMIN_RATE_LIMIT", "20/minute")
API_JWT_SECRET = os.environ.get("API_JWT_SECRET")
API_JWT_AUDIENCE = os.environ.get("API_JWT_AUDIENCE", "phishguard-api")
API_JWT_ALGO = os.environ.get("API_JWT_ALGO", "HS256")


# -------------------------
# DB helpers & migrations
# -------------------------
def init_db():
    """
    Ensure DB exists with the schema expected by api_check() inserts
    and the new 'users' table for auth.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Logs table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            url TEXT,
            homoglyph_score REAL,
            behavior_score REAL,
            phishing_score REAL,
            risk_level TEXT,
            features_json TEXT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Alerts table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            url TEXT,
            level TEXT,
            message TEXT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Blacklist table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            reason TEXT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # NEW: Users table for authentication
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password_hash TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.commit()
    conn.close()
    print("✔ DB & tables ensured at", DB_PATH)


def ensure_migrations():
    """
    If you ever add extra columns later, you can extend this.
    For now, logs schema is already correct in init_db().
    """
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.execute("PRAGMA table_info(logs)")
    cols = [r[1] for r in cur.fetchall()]
    # Example: if we ever need to add features_json for old DBs:
    if "features_json" not in cols:
        try:
            cur.execute("ALTER TABLE logs ADD COLUMN features_json TEXT")
            db.commit()
            print("✅ Added features_json column to logs table")
        except Exception as e:
            print("⚠️ Could not add features_json column:", e)
    cur.close()
    db.close()


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, check_same_thread=False)
    return db


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


# Initialize DB on startup
init_db()
ensure_migrations()

# -------------------------
# Load model (support dict {'model','columns','feature_version'})
# -------------------------
model = None
model_columns = None
model_feature_version = None

if os.path.exists(MODEL_PATH):
    try:
        saved = joblib.load(MODEL_PATH)
        if isinstance(saved, dict) and "model" in saved and "columns" in saved:
            model = saved["model"]
            model_columns = saved["columns"]
            model_feature_version = saved.get("feature_version")
            print("✅ AI Model Loaded Successfully (with columns)!")
            if model_feature_version is not None:
                print(f"ℹ️ Model feature version: {model_feature_version}")
        else:
            model = saved
            model_columns = None
            print("⚠️ Model loaded (no column list).")
    except Exception as e:
        print("❌ Error loading model:", e)
        traceback.print_exc()
else:
    print("⚠️ Model file not found. Run train_model.py to create rf_model.joblib")

# Warn on feature version mismatch
if model_feature_version is not None and model_feature_version != FEATURE_VERSION:
    print(
        f"⚠️ Feature version mismatch detected (model={model_feature_version}, runtime={FEATURE_VERSION}). "
        "Please retrain the model to avoid column drift."
    )

# -------------------------
# Serve frontend
# -------------------------
@app.route("/")
def serve_index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/<path:path>")
def serve_static(path):
    # allow loading assets, css, js from web/ root
    return send_from_directory(app.static_folder, path)


@app.route("/assets/<path:filename>")
def serve_assets(filename):
    return send_from_directory(os.path.join(app.static_folder, "assets"), filename)


# -------------------------
# Helpers
# -------------------------
def normalize_domain(url: str) -> str:
    if not url:
        return ""
    candidate = url.strip()
    if not candidate.startswith(("http://", "https://")):
        candidate = "http://" + candidate
    try:
        parsed = urlparse(candidate)
        domain = (parsed.hostname or "").lower()
        return domain
    except Exception:
        return candidate.split("/")[0].split(":")[0].lower()


def _get_jwt_secret():
    # Use explicit API_JWT_SECRET if set, else fall back to Flask SECRET_KEY
    return API_JWT_SECRET or app.config["SECRET_KEY"]


def require_jwt(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        secret = _get_jwt_secret()
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return jsonify({"ok": False, "error": "missing bearer token"}), 401
        token = auth_header.split(" ", 1)[1].strip()
        try:
            payload = jwt.decode(
                token,
                secret,
                algorithms=[API_JWT_ALGO],
                audience=API_JWT_AUDIENCE,
            )
            g.jwt_payload = payload
        except jwt.PyJWTError as exc:
            return jsonify({"ok": False, "error": f"invalid token: {exc}"}), 401
        return fn(*args, **kwargs)

    return wrapper


def maybe_get_jwt_user_id() -> str | None:
    """
    Optional helper: if Authorization: Bearer <token> is present,
    decode it and return the user id (sub). If anything fails,
    return None and let other mechanisms handle user_id.
    """
    secret = _get_jwt_secret()
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[API_JWT_ALGO],
            audience=API_JWT_AUDIENCE,
        )
        return str(payload.get("sub") or "")
    except jwt.PyJWTError:
        return None


def get_user_id_from_request(data: dict) -> str:
    """
    Fallback: client sends its own user_id / session_id.

    We support:
      - JSON body: data["user_id"]
      - JSON body: data["session_id"]
      - Header:    X-User-Id
      - Fallback:  remote_addr
    """
    user_id = (
        data.get("user_id")
        or data.get("session_id")
        or request.headers.get("X-User-Id")
        or request.remote_addr
        or "anonymous"
    )
    return str(user_id)


# -------------------------
# Auth: Register / Login / My Logs
# -------------------------
@app.route("/api/register", methods=["POST"])
def api_register():
    """
    Register a new user account.
    Request JSON: { "email": "...", "password": "..." }
    """
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"ok": False, "error": "email and password are required"}), 400

    if len(password) < 6:
        return jsonify({"ok": False, "error": "password must be at least 6 characters"}), 400

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing = cur.fetchone()
        if existing:
            return jsonify({"ok": False, "error": "email already registered"}), 400

        pwd_hash = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email, pwd_hash, datetime.datetime.utcnow().isoformat()),
        )
        db.commit()
        user_id = cur.lastrowid
    except Exception as e:
        print("register error:", e)
        return jsonify({"ok": False, "error": "internal error"}), 500

    # Optionally issue token on register
    secret = _get_jwt_secret()
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": "user",
        "aud": API_JWT_AUDIENCE,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
    }
    token = jwt.encode(payload, secret, algorithm=API_JWT_ALGO)

    return jsonify({"ok": True, "token": token, "user_id": user_id, "email": email})


@app.route("/api/login", methods=["POST"])
def api_login():
    """
    Log in a user.
    Request JSON: { "email": "...", "password": "..." }
    Returns JWT token.
    """
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"ok": False, "error": "email and password are required"}), 400

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        if not row:
            return jsonify({"ok": False, "error": "invalid credentials"}), 401

        user_id, pwd_hash = row
        if not check_password_hash(pwd_hash, password):
            return jsonify({"ok": False, "error": "invalid credentials"}), 401
    except Exception as e:
        print("login error:", e)
        return jsonify({"ok": False, "error": "internal error"}), 500

    secret = _get_jwt_secret()
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": "user",
        "aud": API_JWT_AUDIENCE,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
    }
    token = jwt.encode(payload, secret, algorithm=API_JWT_ALGO)

    return jsonify({"ok": True, "token": token, "user_id": user_id, "email": email})


@app.route("/api/my_logs", methods=["GET"])
@require_jwt
def api_my_logs():
    """
    Return last N logs for the currently authenticated user.
    Uses session_id == user_id from JWT (sub).
    """
    payload = getattr(g, "jwt_payload", None)
    if not payload:
        return jsonify({"ok": False, "error": "no auth payload"}), 401

    user_id = str(payload.get("sub") or "")
    if not user_id:
        return jsonify({"ok": False, "error": "invalid token (no sub)"}), 401

    db = get_db()
    cur = db.execute(
        """
        SELECT url, phishing_score, risk_level, ts
        FROM logs
        WHERE session_id = ?
        ORDER BY id DESC
        LIMIT 200
        """,
        (user_id,),
    )
    rows = cur.fetchall()
    logs = [
        {
            "url": r[0],
            "phishing_score": float(r[1] or 0.0),
            "risk_level": r[2] or "Unknown",
            "ts": r[3],
        }
        for r in rows
    ]
    return jsonify({"ok": True, "logs": logs})


# Optional: pretty login page (HTML)
@app.route("/login")
def login_page():
    return render_template("login.html")


# -------------------------
# API: Check URL
# -------------------------
@app.route("/api/check", methods=["POST"])
@limiter.limit(CHECK_RATE_LIMIT)
def api_check():
    data = request.json or {}
    url = data.get("url", "")
    behavior_raw = data.get("behavior", {}) or {}

    # Prefer JWT user id (if Authorization header provided), else fallback
    jwt_user_id = maybe_get_jwt_user_id()
    if jwt_user_id:
        user_id = jwt_user_id
    else:
        user_id = get_user_id_from_request(data)

    # load trusted domains
    trusted = []
    trusted_path = os.path.join(ROOT_DIR, "trusted_domains.txt")
    try:
        with open(trusted_path, "r", encoding="utf-8") as f:
            trusted = [x.strip() for x in f if x.strip()]
    except Exception:
        trusted = []

    # DB connection (for behavior profile + logging)
    db = get_db()

    # --- Homoglyph and fuzzy confusable scores ---
    try:
        homoglyph_score = analyze_homoglyph(url, trusted)
    except Exception:
        homoglyph_score = 0.0

    try:
        fuzzy_score = fuzzy_confusable_score(url, trusted)
    except Exception:
        fuzzy_score = 0.0

    glyph_score = min(100.0, max(0.0, homoglyph_score))
    fuzzy_pct = min(100.0, max(0.0, fuzzy_score))

    # --- Per-request human behavior score (typing, mouse, scroll, etc.) ---
    try:
        micro_behavior_score = analyze_behavior(behavior_raw)
    except Exception:
        micro_behavior_score = 0.0
    micro_behavior_pct = min(100.0, max(0.0, micro_behavior_score))

    # --- Session-based behavior profile (history of this user_id) ---
    behavior_history_pct = 0.0
    behavior_profile_info = {}
    try:
        behavior_profile_info = compute_behavior_profile(db, user_id, lookback_minutes=60)
        behavior_risk = float(behavior_profile_info.get("behavior_risk", 0.0))
        behavior_history_pct = min(100.0, max(0.0, behavior_risk * 100.0))
    except Exception as e:
        print("[WARN] behavior_profile error:", e)
        behavior_history_pct = 0.0

    # Combine micro + history into one behavior_pct
    # Now: 80% micro, 20% history (less aggressive)
    behavior_pct = 0.8 * micro_behavior_pct + 0.2 * behavior_history_pct
    behavior_pct = min(100.0, max(0.0, behavior_pct))

    # --- Feature extraction for ML ---
    try:
        base_features = extract_features_from_url(
            url,
            trusted_domains=trusted,
            enable_network_enrichment=True,
        )
    except Exception as exc:
        print("[WARN] feature extraction error:", exc)
        base_features = dict(FEATURE_DEFAULTS)

    features = dict(base_features)

    phishing_score = None
    prediction = None

    # --- ML model inference & blending ---
    if model:
        try:
            X_df = pd.DataFrame([base_features]).fillna(0)

            # Align to training columns if available
            if model_columns:
                for c in model_columns:
                    if c not in X_df.columns:
                        X_df[c] = 0.0
                X_df = X_df[model_columns]

            proba = model.predict_proba(X_df)[0]
            if len(proba) == 1:
                single_class = model.classes_[0]
                probability = float(proba[0]) if single_class == 1 else 1.0 - float(proba[0])
            else:
                probability = float(proba[1])

            ml_score = probability * 100.0

            # Blend ML probability with heuristic signals
            # Now: ML stronger, behavior softer
            phishing_score = round(
                (ml_score * 0.7)
                + (glyph_score * 0.15)
                + (fuzzy_pct * 0.1)
                + (behavior_pct * 0.05),
                2,
            )
            prediction = int(model.predict(X_df)[0])

            print(
                f"[DEBUG] user_id={user_id} | ML prob={probability:.4f} | glyph={glyph_score:.2f} | "
                f"fuzzy={fuzzy_pct:.2f} | behavior={behavior_pct:.2f} | blended={phishing_score}%"
            )
            features["model_raw_probability"] = float(probability)
        except Exception as e:
            print("[WARN] model inference error:", e)
            traceback.print_exc()
            phishing_score = round(
                0.5 * glyph_score + 0.35 * fuzzy_pct + 0.15 * behavior_pct,
                2,
            )
            prediction = 1 if phishing_score >= 50 else 0
    else:
        # No model: fall back to heuristic blend
        phishing_score = round(
            0.5 * glyph_score + 0.35 * fuzzy_pct + 0.15 * behavior_pct,
            2,
        )
        prediction = 1 if phishing_score >= 50 else 0

    # Extra logic using model probability + brand mismatch
    prob = features.get("model_raw_probability", 0.0)
    brand_mismatch = features.get("brand_in_subdomain_not_domain", 0.0)

    # 1) Very strong model confidence but blended score too low → bump it
    if prob >= 0.95 and phishing_score < 70:
        phishing_score = max(phishing_score, 80.0)

    # 2) Brand misused in subdomain with decent model prob → bump to High
    if brand_mismatch >= 1.0 and prob >= 0.6:
        phishing_score = max(phishing_score, 85.0)

    # --- Classification into risk levels (relaxed thresholds) ---
    if phishing_score < 40:
        risk, action = "Low", "Allow"
    elif phishing_score < 75:
        risk, action = "Medium", "Warn"
    else:
        risk, action = "High", "Block"

    # --- Blacklist enforcement ---
    normalized_domain = normalize_domain(url)
    blacklisted = False
    if normalized_domain:
        try:
            cur = db.execute("SELECT 1 FROM blacklist WHERE url = ? LIMIT 1", (normalized_domain,))
            blacklisted = cur.fetchone() is not None
        except Exception:
            blacklisted = False
        try:
            blacklisted = blacklisted or file_blacklist_contains(normalized_domain)
        except Exception:
            pass

    if blacklisted:
        phishing_score = max(phishing_score, 98.0)
        risk, action = "High", "Block"
        prediction = 1

    # --- Save to DB (store features JSON for retraining + behavior history) ---
    try:
        db.execute(
            """
            INSERT INTO logs (
                session_id, url, homoglyph_score, behavior_score,
                phishing_score, risk_level, features_json, ts
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                url,
                float(homoglyph_score),
                float(behavior_pct),
                float(phishing_score),
                risk,
                json.dumps(features),
                datetime.datetime.utcnow().isoformat(),
            ),
        )
        db.commit()
    except Exception as e:
        print("DB insert error:", e)

    if risk in ("Medium", "High"):
        try:
            db.execute(
                """
                INSERT INTO alerts (session_id, url, level, message, ts)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    url,
                    risk,
                    f"{risk} risk detected for {url}",
                    datetime.datetime.utcnow().isoformat(),
                ),
            )
            db.commit()
        except Exception as e:
            print("DB alert insert error:", e)

    return jsonify(
        {
            "url": url,
            "user_id": user_id,
            "homoglyph_score": round(homoglyph_score, 2),
            "behavior_score_micro": round(micro_behavior_pct, 2),
            "behavior_score_history": round(behavior_history_pct, 2),
            "behavior_score_combined": round(behavior_pct, 2),
            "phishing_score": phishing_score,
            "risk_level": risk,
            "action": action,
            "features": features,
            "behavior_profile": behavior_profile_info,
        }
    )


# -------------------------
# API: Block / Unblock URL (blacklist)
# -------------------------
@app.route("/api/block", methods=["POST"])
@require_jwt
@limiter.limit(ADMIN_RATE_LIMIT)
def api_block():
    data = request.json or {}
    url = data.get("url", "")
    reason = data.get("reason", "blocked by admin")
    norm = normalize_domain(url)
    if not norm:
        return jsonify({"ok": False, "error": "no url"}), 400
    db = get_db()
    try:
        db.execute(
            "INSERT OR IGNORE INTO blacklist (url, reason, ts) VALUES (?, ?, ?)",
            (norm, reason, datetime.datetime.utcnow().isoformat()),
        )
        db.commit()
        add_domain_to_file_blacklist(norm)
        return jsonify({"ok": True, "url": norm})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/unblock", methods=["POST"])
@require_jwt
@limiter.limit(ADMIN_RATE_LIMIT)
def api_unblock():
    data = request.json or {}
    url = data.get("url", "")
    norm = normalize_domain(url)
    if not norm:
        return jsonify({"ok": False, "error": "no url"}), 400
    db = get_db()
    try:
        db.execute("DELETE FROM blacklist WHERE url = ?", (norm,))
        db.commit()
        remove_domain_from_file_blacklist(norm)
        return jsonify({"ok": True, "url": norm})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/blacklist")
@require_jwt
@limiter.limit(ADMIN_RATE_LIMIT)
def api_blacklist():
    db = get_db()
    cur = db.execute("SELECT url, reason, ts FROM blacklist ORDER BY id DESC")
    rows = cur.fetchall()
    return jsonify({"blacklist": [list(r) for r in rows]})


# -------------------------
# Optional debug endpoint to inspect features
# -------------------------
@app.route("/api/debug_features", methods=["POST"])
@require_jwt
@limiter.limit(ADMIN_RATE_LIMIT)
def api_debug_features():
    data = request.json or {}
    url = data.get("url", "")
    include_network = bool(data.get("include_network_signals", True))
    trusted = []
    trusted_path = os.path.join(ROOT_DIR, "trusted_domains.txt")
    try:
        with open(trusted_path, "r", encoding="utf-8") as f:
            trusted = [x.strip() for x in f if x.strip()]
    except Exception:
        trusted = []
    features = extract_features_from_url(
        url,
        trusted_domains=trusted,
        enable_network_enrichment=include_network,
    )
    proba = None
    prob_class1 = None
    try:
        if model:
            X_df = pd.DataFrame([features]).fillna(0)
            if model_columns:
                for c in model_columns:
                    if c not in X_df.columns:
                        X_df[c] = 0.0
                X_df = X_df[model_columns]
            proba_arr = model.predict_proba(X_df)[0]
            proba = proba_arr.tolist()
            prob_class1 = float(proba_arr[1]) if len(proba_arr) > 1 else None
    except Exception as e:
        proba = str(e)
    return jsonify(
        {
            "url": url,
            "features": features,
            "model_loaded": bool(model),
            "model_columns_present": bool(model_columns),
            "runtime_feature_version": FEATURE_VERSION,
            "model_feature_version": model_feature_version,
            "predict_proba": proba,
            "probability_class1": prob_class1,
        }
    )


# -------------------------
# Admin dashboard views (logs + blacklist)
# -------------------------
@app.route("/admin/logs")
def admin_logs():
    """
    Simple admin dashboard:
      - Show last 200 scans (logs table)
      - Show a bar chart of counts by risk level (Low/Medium/High)
    """
    db = get_db()
    cur = db.execute(
        "SELECT session_id, url, phishing_score, risk_level, ts "
        "FROM logs ORDER BY id DESC LIMIT 200"
    )
    rows = cur.fetchall()

    logs = [
        {
            "session_id": r[0],
            "url": r[1],
            "phishing_score": round(r[2] or 0.0, 2),
            "risk_level": r[3] or "Unknown",
            "ts": r[4],
        }
        for r in rows
    ]

    total_logs = len(logs)
    risk_counts = Counter(log["risk_level"] for log in logs)
    risk_labels = list(risk_counts.keys())
    risk_values = [risk_counts[label] for label in risk_labels]

    return render_template(
        "admin_logs.html",
        logs=logs,
        total_logs=total_logs,
        risk_labels=json.dumps(risk_labels),
        risk_values=json.dumps(risk_values),
    )


@app.route("/admin/blacklist")
def admin_blacklist():
    """
    Show all blocked/blacklisted domains from the blacklist table.
    """
    db = get_db()
    cur = db.execute("SELECT url, reason, ts FROM blacklist ORDER BY id DESC")
    rows = cur.fetchall()
    entries = [
        {
            "url": r[0],
            "reason": r[1] or "",
            "ts": r[2],
        }
        for r in rows
    ]
    return render_template("admin_blacklist.html", entries=entries)


# -------------------------
# SocketIO (kept minimal)
# -------------------------
@socketio.on("connect")
def on_connect():
    emit("connected", {"msg": "connected", "session_id": request.sid})


@socketio.on("join")
def on_join(data):
    room = data.get("room") or request.sid
    join_room(room)
    emit("joined", {"room": room}, room=request.sid)


# -------------------------
# Run app
# -------------------------
if __name__ == "__main__":
    print("⚙️ Using async mode:", async_mode)
    port = int(os.environ.get("PORT", 5001))
    socketio.run(app, host="0.0.0.0", port=port)
