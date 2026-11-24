
import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "scan_history.db"
)


def initialize_database():

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT,
                sender TEXT,
                subject TEXT,
                risk_level TEXT,
                risk_score INTEGER,
                urls_found INTEGER,
                attachments_found INTEGER,
                spoofing_detected INTEGER
            )
        """)


def save_scan(
    sender="Unknown",
    subject="No Subject",
    risk_level="LOW",
    risk_score=0,
    urls_found=0,
    attachments_found=0,
    spoofing_detected=False
):

    initialize_database()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO scan_history (
                scan_time, sender, subject, risk_level,
                risk_score, urls_found, attachments_found,
                spoofing_detected
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            sender,
            subject,
            risk_level,
            risk_score,
            urls_found,
            attachments_found,
            int(spoofing_detected)
        ))


def get_scan_history():

    initialize_database()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("""
            SELECT * FROM scan_history
            ORDER BY id DESC
        """)

        columns = [description[0] for description in cursor.description]
        rows = cursor.fetchall()

    return [dict(zip(columns, row)) for row in rows]


def clear_scan_history():

    initialize_database()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM scan_history")