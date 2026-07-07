import sqlite3

DB_PATH = "database/malguard.db"


def save_scan(
    filename,
    filesize,
    filetype,
    extension,
    prediction,
    confidence,
    risk,
    threat_score,
    scan_time,
    sha256
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO scan_history
        (
            filename,
            filesize,
            filetype,
            extension,
            prediction,
            confidence,
            risk,
            threat_score,
            scan_time,
            sha256
        )

        VALUES (?,?,?,?,?,?,?,?,?,?)
    """,
    (
        filename,
        filesize,
        filetype,
        extension,
        prediction,
        confidence,
        risk,
        threat_score,
        scan_time,
        sha256
    ))

    conn.commit()
    conn.close()


def get_all_scans():

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM scan_history
    ORDER BY id DESC
""")
    rows = cursor.fetchall()

    conn.close()

    return rows
def delete_scan(scan_id):

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM scan_history WHERE id=?",
        (scan_id,)
    )

    conn.commit()
    conn.close()
def get_dashboard_stats():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE prediction='MALWARE'
    """)
    malware = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE prediction='SAFE'
    """)
    safe = cursor.fetchone()[0]

    conn.close()

    return total, malware, safe