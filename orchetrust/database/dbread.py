import sqlite3

def read_certificates(conn: sqlite3.Connection) -> list[dict]:
    """Read all certificates saved in the database."""
    cursor = conn.cursor()
    cursor.execute("SELECT source, path, subject, issuer, not_before, not_after, days_left, sans FROM certificates")
    rows = cursor.fetchall()
    certificates = []
    for row in rows:
        certificates.append({
            "source": row[0],
            "path": row[1],
            "subject": row[2],
            "issuer": row[3],
            "not_before": row[4],
            "not_after": row[5],
            "days_left": row[6],
            "sans": row[7].split(",") if row[7] else [],
        })
    return certificates