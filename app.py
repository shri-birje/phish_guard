import os, sqlite3, datetime
from flask import Flask, render_template, request, g, jsonify
from flask_socketio import SocketIO, emit, join_room
import pandas as pd
import joblib

# -------------------------
# Flask & SocketIO setup
# -------------------------
async_mode = 'threading'
try:
    import eventlet
    async_mode = 'eventlet'
except Exception:
    async_mode = 'threading'

DB_PATH = os.path.join(os.path.dirname(__file__), 'phishing_logs.db')
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = 'phishguard-final-secret'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode=async_mode)

# -------------------------
# Load trained model
# -------------------------
MODEL_PATH = os.path.join(os.path.dirname(__file__), "rf_model.joblib")
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
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.execute('''CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            url TEXT,
            homoglyph_score REAL,
            behavior_score REAL,
            phishing_score REAL,
            risk_level TEXT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            url TEXT,
            level TEXT,
            message TEXT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        db.commit()
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# -------------------------
# Routes
# -------------------------
@app.route('/')
def index():
    return render_template('index.html', async_mode=async_mode)

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/admin_data')
def admin_data():
    db = get_db()
    cur = db.execute("SELECT id, session_id, url, homoglyph_score, behavior_score, phishing_score, risk_level, ts FROM logs ORDER BY id DESC LIMIT 500")
    rows = cur.fetchall()
    cur2 = db.execute("SELECT id, session_id, url, level, message, ts FROM alerts ORDER BY id DESC LIMIT 500")
    alerts = cur2.fetchall()
    return jsonify({"logs": [list(r) for r in rows], "alerts": [list(a) for a in alerts]})

# -------------------------
# AI-Powered Phishing Detection API
# -------------------------
@app.route('/api/check', methods=['POST'])
def api_check():
    data = request.json or {}
    url = data.get('url', '')
    behavior = data.get('behavior', {})

    trusted_path = os.path.join(os.path.dirname(__file__), 'trusted_domains.txt')
    with open(trusted_path, 'r', encoding='utf-8') as f:
        trusted = [x.strip() for x in f if x.strip()]

    from modules.homoglyph import analyze_homoglyph
    from modules.behavior import analyze_behavior

    homoglyph_score = analyze_homoglyph(url, trusted)
    behavior_score = analyze_behavior(behavior)

    # ✅ Use trained Random Forest model for prediction
    if model:
        from modules.homoglyph import extract_features_from_url
        features = extract_features_from_url(url)
        feature_df = pd.DataFrame([features])
        prediction = model.predict(feature_df)[0]
        probability = model.predict_proba(feature_df)[0][1]
        phishing_score = round(probability * 100, 2)
    else:
        phishing_score = round(0.7 * homoglyph_score + 0.3 * behavior_score, 2)
        prediction = 1 if phishing_score >= 50 else 0

    if phishing_score < 30:
        risk = 'Low'; action = 'Allow'
    elif phishing_score < 70:
        risk = 'Medium'; action = 'Warn'
    else:
        risk = 'High'; action = 'Block'

    db = get_db()
    db.execute("INSERT INTO logs (session_id, url, homoglyph_score, behavior_score, phishing_score, risk_level, ts) VALUES (?, ?, ?, ?, ?, ?, ?)",
               ('static', url, homoglyph_score, behavior_score, phishing_score, risk, datetime.datetime.utcnow().isoformat()))
    db.commit()

    if risk in ('Medium', 'High'):
        db.execute("INSERT INTO alerts (session_id, url, level, message, ts) VALUES (?, ?, ?, ?, ?)",
                   ('static', url, risk, f'{risk} risk detected for {url}', datetime.datetime.utcnow().isoformat()))
        db.commit()

    return jsonify({
        'url': url,
        'homoglyph_score': round(homoglyph_score, 2),
        'behavior_score': round(behavior_score, 2),
        'phishing_score': phishing_score,
        'risk_level': risk,
        'action': action
    })

# -------------------------
# SocketIO Events
# -------------------------
@socketio.on('connect')
def on_connect():
    emit('connected', {'msg': 'connected', 'session_id': request.sid})

@socketio.on('join')
def on_join(data):
    room = data.get('room') or request.sid
    join_room(room)
    emit('joined', {'room': room}, room=request.sid)

@socketio.on('metrics')
def on_metrics(data):
    session_id = data.get('session_id') or request.sid
    url = data.get('url', '')
    behavior = data.get('behavior', {})

    trusted_path = os.path.join(os.path.dirname(__file__), 'trusted_domains.txt')
    with open(trusted_path, 'r', encoding='utf-8') as f:
        trusted = [x.strip() for x in f if x.strip()]

    from modules.homoglyph import analyze_homoglyph
    from modules.behavior import analyze_behavior

    homoglyph_score = analyze_homoglyph(url, trusted)
    behavior_score = analyze_behavior(behavior)

    # ✅ Use model for prediction in real-time
    if model:
        from modules.homoglyph import extract_features_from_url
        features = extract_features_from_url(url)
        feature_df = pd.DataFrame([features])
        probability = model.predict_proba(feature_df)[0][1]
        phishing_score = round(probability * 100, 2)
    else:
        phishing_score = round(0.7 * homoglyph_score + 0.3 * behavior_score, 2)

    if phishing_score < 30:
        risk = 'Low'
    elif phishing_score < 70:
        risk = 'Medium'
    else:
        risk = 'High'

    db = get_db()
    db.execute("INSERT INTO logs (session_id, url, homoglyph_score, behavior_score, phishing_score, risk_level, ts) VALUES (?, ?, ?, ?, ?, ?, ?)",
               (session_id, url, homoglyph_score, behavior_score, phishing_score, risk, datetime.datetime.utcnow().isoformat()))
    db.commit()

    if risk in ('Medium', 'High'):
        db.execute("INSERT INTO alerts (session_id, url, level, message, ts) VALUES (?, ?, ?, ?, ?)",
                   (session_id, url, risk, f'{risk} risk detected for {url}', datetime.datetime.utcnow().isoformat()))
        db.commit()

    emit('update', {
        'session_id': session_id,
        'url': url,
        'homoglyph_score': round(homoglyph_score, 2),
        'behavior_score': round(behavior_score, 2),
        'phishing_score': phishing_score,
        'risk_level': risk
    }, room=session_id)

# -------------------------
# Run App
# -------------------------
if __name__ == '__main__':
    print('Async mode selected:', async_mode)
    socketio.run(app, host='0.0.0.0', port=5000)
ss
