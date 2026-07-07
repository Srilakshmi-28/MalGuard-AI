import sqlite3

conn = sqlite3.connect("database/malguard.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scan_history(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    filename TEXT,

    filesize TEXT,

    filetype TEXT,

    extension TEXT,

    prediction TEXT,

    confidence TEXT,

    risk TEXT,

    threat_score INTEGER,

    scan_time TEXT,

    sha256 TEXT

)
""")

conn.commit()
conn.close()

print("Database Created Successfully!")