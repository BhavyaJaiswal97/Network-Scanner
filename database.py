import sqlite3

conn = sqlite3.connect("scans.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    port INTEGER,
    service TEXT
)
""")

conn.commit()

print("Database created successfully")

conn.close()
