import sqlite3

DB_NAME = "dnsentinel.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            domain TEXT,
            query_type TEXT,
            entropy REAL,
            query_frequency INTEGER,
            score INTEGER,
            severity TEXT,
            reasons TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_incident(timestamp, source_ip, domain, query_type, entropy, query_frequency, score, severity, reasons):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO incidents (timestamp, source_ip, domain, query_type, entropy, query_frequency, score, severity, reasons)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, source_ip, domain, query_type, entropy, query_frequency, score, severity, ", ".join(reasons)))
    conn.commit()
    conn.close()

def get_all_incidents():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY incident_id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

if __name__ == "__main__":
    init_db()
    print("Database initialized.")