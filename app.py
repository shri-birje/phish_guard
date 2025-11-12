# # app.py — full corrected version
# import os
# import sqlite3
# import datetime
# from flask import Flask, request, g, jsonify, send_from_directory
# from flask_socketio import SocketIO, emit, join_room
# from flask_cors import CORS
# import pandas as pd
# import joblib

# # -------------------------
# # Config
# # -------------------------
# async_mode = "gevent"
# DB_PATH = os.path.join(os.path.dirname(__file__), "phishing_logs.db")
# MODEL_PATH = os.path.join(os.path.dirname(__file__), "rf_model.joblib")
# WEB_DIR = "web"

# app = Flask(__name__, static_folder=WEB_DIR, static_url_path="")
# CORS(app)
# app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "phishguard-final-secret")
# socketio = SocketIO(app, cors_allowed_origins="*", async_mode=async_mode)

# # -------------------------
# # Load model
# # -------------------------
# model = None
# model_columns = None
# if os.path.exists(MODEL_PATH):
#     try:
#         loaded = joblib.load(MODEL_PATH)
#         if isinstance(loaded, dict) and "model" in loaded and "columns" in loaded:
#             model = loaded["model"]
#             model_columns = loaded["columns"]
#             print("✅ AI Model Loaded Successfully (with columns)!")
#         else:
#             model = loaded
#             print("⚠️ Model loaded without columns metadata.")
#     except Exception as e:
#         print("❌ Error loading model:", e)
# else:
#     print("⚠️ Model not found! Run train_model.py first.")

# # -------------------------
# # Database helpers
# # -------------------------
# def get_db():
#     db = getattr(g, "_database", None)
#     if db is None:
#         db = g._database = sqlite3.connect(DB_PATH, check_same_thread=False)
#         db.execute("""
#             CREATE TABLE IF NOT EXISTS logs (
#                 id INTEGER PRIMARY KEY AUTOINCREMENT,
#                 session_id TEXT,
#                 url TEXT,
#                 homoglyph_score REAL,
#                 behavior_score REAL,
#                 phishing_score REAL,
#                 risk_level TEXT,
#                 ts DATETIME DEFAULT CURRENT_TIMESTAMP
#             )""")
#         db.execute("""
#             CREATE TABLE IF NOT EXISTS alerts (
#                 id INTEGER PRIMARY KEY AUTOINCREMENT,
#                 session_id TEXT,
#                 url TEXT,
#                 level TEXT,
#                 message TEXT,
#                 ts DATETIME DEFAULT CURRENT_TIMESTAMP
#             )""")
#         db.commit()
#     return db

# @app.teardown_appcontext
# def close_db(exc):
#     db = getattr(g, "_database", None)
#     if db is not None:
#         db.close()

# # -------------------------
# # Frontend routes
# # -------------------------
# @app.route("/")
# def serve_index():
#     return send_from_directory(app.static_folder, "index.html")

# @app.route("/<path:path>")
# def serve_static_files(path):
#     return send_from_directory(app.static_folder, path)

# @app.route("/assets/<path:filename>")
# def serve_assets(filename):
#     return send_from_directory(os.path.join(app.static_folder, "assets"), filename)

# # -------------------------
# # Core API
# # -------------------------
# @app.route("/api/check", methods=["POST"])
# def api_check():
#     data = request.json or {}
#     url = data.get("url", "")
#     behavior = data.get("behavior", {})

#     trusted_path = os.path.join(os.path.dirname(__file__), "trusted_domains.txt")
#     try:
#         with open(trusted_path, "r", encoding="utf-8") as f:
#             trusted = [x.strip() for x in f if x.strip()]
#     except Exception:
#         trusted = []

#     from modules.homoglyph import analyze_homoglyph
#     from modules.behavior import analyze_behavior
#     from modules.features import extract_features_from_url

#     homoglyph_score = analyze_homoglyph(url, trusted)
#     behavior_score = analyze_behavior(behavior)

#     phishing_score = 0.0
#     prediction = 0

#     if model:
#         try:
#             features = extract_features_from_url(url, trusted_domains=trusted)
#             X_df = pd.DataFrame([features]).fillna(0)

#             # ensure all expected cols exist
#             if model_columns:
#                 for c in model_columns:
#                     if c not in X_df.columns:
#                         X_df[c] = 0.0
#                 X_df = X_df[model_columns]

#             proba = model.predict_proba(X_df)[0]
#             classes = model.classes_.tolist() if hasattr(model, "classes_") else []
#             if len(proba) == 1:
#                 if classes and classes[0] == 1:
#                     probability = float(proba[0])
#                 else:
#                     probability = 1.0 - float(proba[0])
#             else:
#                 probability = float(proba[1])

#             # normalize homoglyph score to 0–1 range if needed
#             if homoglyph_score > 1:
#                 homoglyph_score = homoglyph_score / 100.0

#             # blend scores — 90% model + 10% homoglyph
#             phishing_score = round(((probability * 0.9) + (homoglyph_score * 0.1)) * 100, 2)

#             prediction = int(model.predict(X_df)[0])
#             print(f"[DEBUG] ML prob={probability:.3f}, homoglyph_score={homoglyph_score}, blended={phishing_score}%")
#         except Exception as e:
#             print("[WARN] Model error:", e)
#             phishing_score = round(0.7 * homoglyph_score + 0.3 * behavior_score, 2)
#             prediction = 1 if phishing_score >= 50 else 0
#     else:
#         phishing_score = round(0.7 * homoglyph_score + 0.3 * behavior_score, 2)
#         prediction = 1 if phishing_score >= 50 else 0

#     # risk classification
#     if phishing_score < 20:
#         risk, action = "Low", "Allow"
#     elif phishing_score < 60:
#         risk, action = "Medium", "Warn"
#     else:
#         risk, action = "High", "Block"

#     # log results
#     db = get_db()
#     db.execute(
#         "INSERT INTO logs (session_id, url, homoglyph_score, behavior_score, phishing_score, risk_level, ts)"
#         "VALUES (?, ?, ?, ?, ?, ?, ?)",
#         ("static", url, homoglyph_score, behavior_score, phishing_score, risk, datetime.datetime.utcnow().isoformat()))
#     db.commit()

#     if risk in ("Medium", "High"):
#         db.execute(
#             "INSERT INTO alerts (session_id, url, level, message, ts)"
#             "VALUES (?, ?, ?, ?, ?)",
#             ("static", url, risk, f"{risk} risk detected for {url}", datetime.datetime.utcnow().isoformat()))
#         db.commit()

#     return jsonify({
#         "url": url,
#         "homoglyph_score": round(homoglyph_score * 100, 2),
#         "behavior_score": round(behavior_score, 2),
#         "phishing_score": phishing_score,
#         "risk_level": risk,
#         "action": action
#     })

# # -------------------------
# # SocketIO (optional)
# # -------------------------
# @socketio.on("connect")
# def on_connect():
#     emit("connected", {"msg": "connected", "session_id": request.sid})

# @socketio.on("join")
# def on_join(data):
#     room = data.get("room") or request.sid
#     join_room(room)
#     emit("joined", {"room": room}, room=request.sid)

# # -------------------------
# # Run
# # -------------------------
# if __name__ == "__main__":
#     print("⚙️ Using gevent async mode")
#     port = int(os.environ.get("PORT", 5000))
#     socketio.run(app, host="0.0.0.0", port=port)




# app.py
import os
import sqlite3
import datetime
import json
import traceback
from flask import Flask, request, g, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
import pandas as pd
import joblib

# Async mode: prefer gevent (Render / Linux). If unavailable fallback.
async_mode = os.environ.get("ASYNC_MODE", "gevent")

DB_PATH = os.path.join(os.path.dirname(__file__), "phishing_logs.db")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "rf_model.joblib")

# Serve static frontend from 'web' directory
app = Flask(__name__, static_folder="web", static_url_path="")
CORS(app)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "phishguard-final-secret")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=async_mode)

# -------------------------
# Load model if present (support model saved as dict{'model','columns'})
# -------------------------
model = None
model_columns = None

if os.path.exists(MODEL_PATH):
    try:
        saved = joblib.load(MODEL_PATH)
        if isinstance(saved, dict) and "model" in saved and "columns" in saved:
            model = saved["model"]
            model_columns = saved["columns"]
            print("✅ AI Model Loaded Successfully (with columns)!")
        else:
            model = saved
            model_columns = None
            print("⚠️ Model loaded (no column list).")
    except Exception as e:
        print("❌ Error loading model:", e)
        traceback.print_exc()
else:
    print("⚠️ Model file not found. Run train_model.py to create rf_model.joblib")

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
from modules.homoglyph import analyze_homoglyph
from modules.behavior import analyze_behavior  # keep your existing behavior analyzer
from modules.features import extract_features_from_url, domain_age_days

# -------------------------
# API: Check URL
# -------------------------
@app.route("/api/check", methods=["POST"])
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

    features = {}
    phishing_score = None
    prediction = None

    if model:
        try:
            features = extract_features_from_url(url, trusted_domains=trusted)
            X_df = pd.DataFrame([features]).fillna(0)

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

            # Blend ML probability with homoglyph_score (heuristic)
            phishing_score = round((probability * 0.75) + (homoglyph_score * 0.25), 2)
            prediction = int(model.predict(X_df)[0])
            # include debug log
            print(f"[DEBUG] ML raw probability for {url}: {probability:.6f}, homoglyph_score: {homoglyph_score}, blended_percent: {phishing_score}%, label_pred: {prediction}")
            features["model_raw_probability"] = probability
        except Exception as e:
            print("[WARN] model inference error:", e)
            traceback.print_exc()
            phishing_score = round(0.7 * homoglyph_score + 0.3 * behavior_score, 2)
            prediction = 1 if phishing_score >= 50 else 0
    else:
        phishing_score = round(0.7 * homoglyph_score + 0.3 * behavior_score, 2)
        prediction = 1 if phishing_score >= 50 else 0

    # classification
    if phishing_score < 30:
        risk, action = "Low", "Allow"
    elif phishing_score < 70:
        risk, action = "Medium", "Warn"
    else:
        risk, action = "High", "Block"

    # Save to DB (store features JSON for retraining)
    db = get_db()
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
def api_block():
    data = request.json or {}
    url = data.get("url", "")
    reason = data.get("reason", "blocked by admin")
    if not url:
        return jsonify({"ok": False, "error": "no url"}), 400
    db = get_db()
    try:
        db.execute("INSERT OR IGNORE INTO blacklist (url, reason, ts) VALUES (?, ?, ?)", (url, reason, datetime.datetime.utcnow().isoformat()))
        db.commit()
        return jsonify({"ok": True, "url": url})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.json or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"ok": False, "error": "no url"}), 400
    db = get_db()
    try:
        db.execute("DELETE FROM blacklist WHERE url = ?", (url,))
        db.commit()
        return jsonify({"ok": True, "url": url})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/blacklist")
def api_blacklist():
    db = get_db()
    cur = db.execute("SELECT url, reason, ts FROM blacklist ORDER BY id DESC")
    rows = cur.fetchall()
    return jsonify({"blacklist": [list(r) for r in rows]})

# -------------------------
# Optional debug endpoint to inspect features (helps debugging on Render)
# -------------------------
@app.route("/api/debug_features", methods=["POST"])
def api_debug_features():
    data = request.json or {}
    url = data.get("url", "")
    trusted = []
    trusted_path = os.path.join(os.path.dirname(__file__), "trusted_domains.txt")
    try:
        with open(trusted_path, "r", encoding="utf-8") as f:
            trusted = [x.strip() for x in f if x.strip()]
    except Exception:
        trusted = []
    features = extract_features_from_url(url, trusted_domains=trusted)
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
    return jsonify({"url": url, "features": features, "model_loaded": bool(model), "model_columns_present": bool(model_columns), "predict_proba": proba, "probability_class1": prob_class1})

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
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)
