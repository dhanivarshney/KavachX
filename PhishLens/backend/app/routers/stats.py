import sqlite3
from pathlib import Path
from fastapi import APIRouter
from app.core.config import get_settings

router = APIRouter(tags=["stats"])


@router.get("/stats")
def get_stats() -> dict:
    settings = get_settings()
    db_path = settings.feedback_db_path
    if not Path(db_path).exists():
        return {
            "total_reports": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "top_reported_domains": [],
            "daily_reports_last_30_days": [],
        }

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        total = cur.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
        false_positives = cur.execute(
            "SELECT COUNT(*) FROM feedback WHERE observed='dangerous' AND expected='safe'"
        ).fetchone()[0]
        false_negatives = cur.execute(
            "SELECT COUNT(*) FROM feedback WHERE observed='safe' AND expected='dangerous'"
        ).fetchone()[0]
        top_domains = cur.execute(
            "SELECT url_host, COUNT(*) as cnt FROM feedback GROUP BY url_host ORDER BY cnt DESC LIMIT 5"
        ).fetchall()
        daily = cur.execute(
            """SELECT date(created_at) as day, COUNT(*) as cnt
               FROM feedback
               WHERE datetime(created_at) >= datetime('now', '-30 days')
               GROUP BY day ORDER BY day"""
        ).fetchall()
        conn.close()
        return {
            "total_reports": total,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "top_reported_domains": [{"host": r["url_host"], "count": r["cnt"]} for r in top_domains],
            "daily_reports_last_30_days": [{"day": r["day"], "count": r["cnt"]} for r in daily],
        }
    except Exception as e:
        return {"error": str(e), "total_reports": 0, "false_positives": 0, "false_negatives": 0, "top_reported_domains": [], "daily_reports_last_30_days": []}
