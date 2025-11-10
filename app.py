import os, sqlite3, datetime, json
from flask import Flask, request, g, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
import pandas as pd
import joblib

# -------------------------
# Flask & SocketIO setup
# -------------------------
async_mode = "gevent"  # Use gevent instead of eventlet

DB_PATH = os.path.join(os.path.dirname(__file__), "phishing_logs.db")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "rf_model.joblib")

# ✅ Serve your web folder as static frontend
app = Flask(__name__, static_folder="web", static_url_path="")
CORS(app)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "phishguard-final-secret")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=async_mode)

# -------------------------
# Load trained model
# -------------------------
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
    print("✅ AI Model Loaded Successfully!")
else:
    model = None
    print("⚠️ Model file not found! Run train_model.py first.")

# -------------------------
# Database functions
# -------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.execute(
            """CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                url TEXT,
                homoglyph_score REAL,
                behavior_score REAL,
                phishing_score REAL,
                risk_level TEXT,
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
        db.commit()
    return db


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# -------------------------
# Frontend Routes
# -------------------------
@app.route("/")
def serve_index():
    """Serve the main web UI"""
    return send_from_directory(app.static_folder, "index.html")


@app.route("/<path:path>")
def serve_static_files(path):
    """Serve other static assets (JS, CSS, etc.)"""
    return send_from_directory(app.static_folder, path)


# -------------------------
# AI-Powered Phishing Detection API
# -------------------------
@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.json or {}
    url = data.get("url", "")
    behavior = data.get("behavior", {})

    trusted_path = os.path.join(os.path.dirname(__file__), "trusted_domains.txt")
    try:
        with open(trusted_path, "r", encoding="utf-8") as f:
            trusted = [x.strip() for x in f if x.strip()]
    except Exception:
        trusted = []

    from modules.homoglyph import analyze_homoglyph
    from modules.behavior import analyze_behavior

    homoglyph_score = analyze_homoglyph(url, trusted)
    behavior_score = analyze_behavior(behavior)

    if model:
        from modules.features import extract_features_from_url

        try:
            features = extract_features_from_url(url, trusted_domains=trusted)
            feature_df = pd.DataFrame([features])
            proba = model.predict_proba(feature_df)[0]

            # ✅ Handle both binary and single-class outputs
            if len(proba) == 1:
                single_class = model.classes_[0]
                probability = float(proba[0]) if single_class == 1 else 1 - float(proba[0])
            else:
                probability = float(proba[1])

            phishing_score = round(probability * 100, 2)
            prediction = int(model.predict(feature_df)[0])
            print(f"[DEBUG] ML prediction for {url}: {phishing_score}% (label={prediction})")

        except Exception as e:
            print(f"[WARN] Model error: {e}")
            phishing_score = 50.0
            prediction = 0
    else:
        phishing_score = round(0.7 * homoglyph_score + 0.3 * behavior_score, 2)
        prediction = 1 if phishing_score >= 50 else 0

    if phishing_score < 30:
        risk, action = "Low", "Allow"
    elif phishing_score < 70:
        risk, action = "Medium", "Warn"
    else:
        risk, action = "High", "Block"

    db = get_db()
    db.execute(
        "INSERT INTO logs (session_id, url, homoglyph_score, behavior_score, phishing_score, risk_level, ts) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "static",
            url,
            homoglyph_score,
            behavior_score,
            phishing_score,
            risk,
            datetime.datetime.utcnow().isoformat(),
        ),
    )
    db.commit()

    if risk in ("Medium", "High"):
        db.execute(
            "INSERT INTO alerts (session_id, url, level, message, ts) VALUES (?, ?, ?, ?, ?)",
            (
                "static",
                url,
                risk,
                f"{risk} risk detected for {url}",
                datetime.datetime.utcnow().isoformat(),
            ),
        )
        db.commit()

    return jsonify(
        {
            "url": url,
            "homoglyph_score": round(homoglyph_score, 2),
            "behavior_score": round(behavior_score, 2),
            "phishing_score": phishing_score,
            "risk_level": risk,
            "action": action,
        }
    )


# -------------------------
# SocketIO Events
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
# Run App (local & Render)
# -------------------------
if __name__ == "__main__":
    print("⚙️ Using gevent async mode")
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)
