import os

# 🔥 TEMP FIX: Delete old DB on Render
db_path = "/opt/render/project/src/phishing_logs.db"

if os.path.exists(db_path):
    os.remove(db_path)
    print("🔥 Deleted old Render DB at:", db_path)
else:
    print("ℹ No existing DB found at startup")

import sqlite3
import datetime
import json
import traceback
from functools import wraps
from urllib.parse import urlparse

import jwt
import pandas as pd
import joblib
from flask import Flask, request, g, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

def init_db():
    conn = sqlite3.connect("phishing_logs.db")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        prediction INTEGER,
        probability REAL,
        homoglyph_score REAL,
        model_raw_probability REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        features_json TEXT
    );
    """)
    conn.commit()
    conn.close()
    print("✔ logs table ensured")

init_db()


# Async mode: prefer gevent (Render / Linux). If unavailable fallback.
async_mode = os.environ.get("ASYNC_MODE", "gevent")

DB_PATH = os.path.join(os.path.dirname(__file__), "phishing_logs.db")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "rf_model.joblib")

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
# Load model if present (support model saved as dict{'model','columns'})
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

if model_feature_version and model_feature_version != FEATURE_VERSION:
    print(
        f"⚠️ Feature version mismatch detected (model={model_feature_version}, runtime={FEATURE_VERSION}). "
        "Please retrain the model to avoid column drift."
    )

# -------------------------
# DB helpers & migrations
# -------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, check_same_thread=False)
        # enable row factory if needed
        db.execute(
            """CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                url TEXT,
                homoglyph_score REAL,
                behavior_score REAL,
                phishing_score REAL,
                risk_level TEXT,
                features_json TEXT,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                url TEXT,
                level TEXT,
                message TEXT,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                reason TEXT,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        db.commit()
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# small helper to add missing column (sqlite supports ADD COLUMN)
def ensure_migrations():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    # add features_json if not exists (sqlite doesn't offer IF NOT EXISTS for columns)
    cur.execute("PRAGMA table_info(logs)")
    cols = [r[1] for r in cur.fetchall()]
    if "features_json" not in cols:
        try:
            cur.execute("ALTER TABLE logs ADD COLUMN features_json TEXT")
            db.commit()
            print("✅ Added features_json column to logs table")
        except Exception as e:
            print("⚠️ Could not add features_json column:", e)
    cur.close()
    db.close()

# run migrations on startup
ensure_migrations()

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
# Import analysis modules (lazy import to avoid startup errors)
# -------------------------
from modules.homoglyph import analyze_homoglyph, fuzzy_confusable_score
from modules.behavior import analyze_behavior  # keep your existing behavior analyzer
from modules.features import extract_features_from_url, FEATURE_VERSION, FEATURE_DEFAULTS
from modules.blacklist import (
    is_blacklisted as file_blacklist_contains,
    add_to_blacklist as add_domain_to_file_blacklist,
    remove_from_blacklist as remove_domain_from_file_blacklist,
)


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


def require_jwt(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not API_JWT_SECRET:
            return fn(*args, **kwargs)
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return jsonify({"ok": False, "error": "missing bearer token"}), 401
        token = auth_header.split(" ", 1)[1].strip()
        try:
            payload = jwt.decode(token, API_JWT_SECRET, algorithms=[API_JWT_ALGO], audience=API_JWT_AUDIENCE)
            g.jwt_payload = payload
        except jwt.PyJWTError as exc:
            return jsonify({"ok": False, "error": f"invalid token: {exc}"}), 401
        return fn(*args, **kwargs)

    return wrapper

# -------------------------
# API: Check URL
# -------------------------
@app.route("/api/check", methods=["POST"])
@limiter.limit(CHECK_RATE_LIMIT)
def api_check():
    data = request.json or {}
    url = data.get("url", "")
    behavior = data.get("behavior", {})

    # load trusted domains
    trusted = []
    trusted_path = os.path.join(os.path.dirname(__file__), "trusted_domains.txt")
    try:
        with open(trusted_path, "r", encoding="utf-8") as f:
            trusted = [x.strip() for x in f if x.strip()]
    except Exception:
        trusted = []

    try:
        homoglyph_score = analyze_homoglyph(url, trusted)
    except Exception:
        homoglyph_score = 0.0

    try:
        behavior_score = analyze_behavior(behavior)
    except Exception:
        behavior_score = 0.0

    try:
        fuzzy_score = fuzzy_confusable_score(url, trusted)
    except Exception:
        fuzzy_score = 0.0

    glyph_score = min(100.0, max(0.0, homoglyph_score))
    behavior_pct = min(100.0, max(0.0, behavior_score))
    fuzzy_pct = min(100.0, max(0.0, fuzzy_score))

    try:
        base_features = extract_features_from_url(url, trusted_domains=trusted, enable_network_enrichment=True)
    except Exception as exc:
        print("[WARN] feature extraction error:", exc)
        base_features = dict(FEATURE_DEFAULTS)

    features = dict(base_features)
    phishing_score = None
    prediction = None

    if model:
        try:
            X_df = pd.DataFrame([base_features]).fillna(0)

            # align to training columns if available
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
            phishing_score = round(
                (ml_score * 0.6)
                + (glyph_score * 0.2)
                + (fuzzy_pct * 0.15)
                + (behavior_pct * 0.05),
                2,
            )
            prediction = int(model.predict(X_df)[0])
            # include debug log
            print(
                f"[DEBUG] ML prob={probability:.4f} | glyph={glyph_score:.2f} | fuzzy={fuzzy_pct:.2f} | behavior={behavior_pct:.2f} | blended={phishing_score}%"
            )
            features["model_raw_probability"] = probability
        except Exception as e:
            print("[WARN] model inference error:", e)
            traceback.print_exc()
            phishing_score = round(0.5 * glyph_score + 0.35 * fuzzy_pct + 0.15 * behavior_pct, 2)
            prediction = 1 if phishing_score >= 50 else 0
    else:
        phishing_score = round(0.5 * glyph_score + 0.35 * fuzzy_pct + 0.15 * behavior_pct, 2)
        prediction = 1 if phishing_score >= 50 else 0

    # classification
    if phishing_score < 30:
        risk, action = "Low", "Allow"
    elif phishing_score < 70:
        risk, action = "Medium", "Warn"
    else:
        risk, action = "High", "Block"

    normalized_domain = normalize_domain(url)
    db = get_db()
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

    # Save to DB (store features JSON for retraining)
    try:
        db.execute(
            "INSERT INTO logs (session_id, url, homoglyph_score, behavior_score, phishing_score, risk_level, features_json, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "static",
                url,
                homoglyph_score,
                behavior_score,
                phishing_score,
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
                "INSERT INTO alerts (session_id, url, level, message, ts) VALUES (?, ?, ?, ?, ?)",
                ("static", url, risk, f"{risk} risk detected for {url}", datetime.datetime.utcnow().isoformat()),
            )
            db.commit()
        except Exception:
            pass

    return jsonify(
        {
            "url": url,
            "homoglyph_score": round(homoglyph_score, 2),
            "behavior_score": round(behavior_score, 2),
            "phishing_score": phishing_score,
            "risk_level": risk,
            "action": action,
            "features": features,
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
# Optional debug endpoint to inspect features (helps debugging on Render)
# -------------------------
@app.route("/api/debug_features", methods=["POST"])
@require_jwt
@limiter.limit(ADMIN_RATE_LIMIT)
def api_debug_features():
    data = request.json or {}
    url = data.get("url", "")
    include_network = bool(data.get("include_network_signals", True))
    trusted = []
    trusted_path = os.path.join(os.path.dirname(__file__), "trusted_domains.txt")
    try:
        with open(trusted_path, "r", encoding="utf-8") as f:
            trusted = [x.strip() for x in f if x.strip()]
    except Exception:
        trusted = []
    features = extract_features_from_url(url, trusted_domains=trusted, enable_network_enrichment=include_network)
    model_present = model is not None
    model_cols_present = model_columns is not None
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
            proba = model.predict_proba(X_df)[0].tolist()
            prob_class1 = float(proba[1]) if len(proba) > 1 else None
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