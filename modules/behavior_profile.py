# modules/behavior_profile.py

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta


def compute_behavior_profile(
    conn: sqlite3.Connection,
    session_id: str,
    lookback_minutes: int = 60,
) -> dict:
    """
    Compute a simple behavior profile for a given session based on recent logs.

    - Count how many URLs this session has checked.
    - Count how many of them were high risk.

    Returns:
        {
            "total_events": int,
            "high_risk_events": int,
            "high_risk_ratio": float in [0,1],
            "behavior_risk": float in [0,1]
        }
    """
    if not session_id:
        return {
            "total_events": 0,
            "high_risk_events": 0,
            "high_risk_ratio": 0.0,
            "behavior_risk": 0.0,
        }

    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Filter to recent events to avoid ancient history driving behavior
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=lookback_minutes)

    try:
        cur.execute(
            """
            SELECT phishing_score, risk_level, ts
            FROM logs
            WHERE session_id = ?
            """,
            (session_id,),
        )
        rows = cur.fetchall()
    except Exception:
        # If logs table is missing or query fails, return neutral
        return {
            "total_events": 0,
            "high_risk_events": 0,
            "high_risk_ratio": 0.0,
            "behavior_risk": 0.0,
        }

    total = 0
    high_risk = 0

    for r in rows:
        ts_raw = r["ts"]
        try:
            # assume ts stored as ISO string or something convertible
            ts = datetime.fromisoformat(ts_raw)
        except Exception:
            # if bad ts, we just accept it
            ts = None

        if ts is not None and ts < cutoff:
            continue

        total += 1
        score = r["phishing_score"]
        risk_level = r["risk_level"]

        # high-risk heuristic: explicit label OR high score
        if risk_level in ("high", "critical") or (score is not None and score >= 70):
            high_risk += 1

    if total == 0:
        return {
            "total_events": 0,
            "high_risk_events": 0,
            "high_risk_ratio": 0.0,
            "behavior_risk": 0.0,
        }

    ratio = high_risk / total

    # map 0..1 ratio into a softer risk, you can tune this
    behavior_risk = min(1.0, max(0.0, ratio))

    return {
        "total_events": total,
        "high_risk_events": high_risk,
        "high_risk_ratio": float(round(ratio, 3)),
        "behavior_risk": float(round(behavior_risk, 3)),
    }
