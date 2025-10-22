import sqlite3

def save_certificates(certificates: list[dict], conn: sqlite3.Connection) -> int | None:
    """
    Write discovered certificates to the database.
    Returns the last inserted row ID or None if no rows were inserted.
    """
    cursor = conn.cursor()
    last_row_id = None
    for cert in certificates:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                path TEXT,
                subject TEXT,
                issuer TEXT,
                not_before TEXT,
                not_after TEXT,
                days_left INTEGER,
                sans TEXT
            )
        """)
        cursor.execute("""
            INSERT INTO certificates (source, path, subject, issuer, not_before, not_after, days_left, sans)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cert["source"],
            cert["path"],
            cert["subject"],
            cert["issuer"],
            cert["not_before"],
            cert["not_after"],
            cert["days_left"],
            ",".join(cert["sans"]) if cert["sans"] else None,
        ))
        last_row_id = cursor.lastrowid
    conn.commit()
    return last_row_id