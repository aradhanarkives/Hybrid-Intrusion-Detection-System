import sqlite3
import pandas as pd
from datetime import datetime

DB_PATH = "ids_events.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            attack_type TEXT,
            rule_detection INTEGER,
            ml_detection INTEGER,
            confidence REAL,
            risk_level TEXT,
            evidence TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_event(event):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO events (
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            attack_type,
            rule_detection,
            ml_detection,
            confidence,
            risk_level,
            evidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("timestamp", datetime.now().isoformat()),
        event.get("source_ip"),
        event.get("destination_ip"),
        event.get("protocol"),
        event.get("source_port", 0),
        event.get("destination_port", 0),
        event.get("attack_type"),
        int(event.get("rule_detection", False)),
        int(event.get("ml_detection", False)),
        float(event.get("confidence", 0)),
        event.get("risk_level"),
        event.get("evidence")
    ))

    conn.commit()
    conn.close()


def get_events(limit=500):
    conn = get_connection()

    query = f"""
        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT {int(limit)}
    """

    df = pd.read_sql_query(query, conn)

    conn.close()

    return df