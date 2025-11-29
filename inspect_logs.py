import sqlite3
import csv
from datetime import datetime
import sys

DB = "phishing_logs.db"   # path to your DB
TABLE = None              # set to table name if you know it, else leave None
LIMIT = 25                # how many recent rows to print

def get_tables(conn):
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
    return [r[0] for r in cur.fetchall()]

def print_recent_rows(conn, table, limit=25):
    cur = conn.execute(f"PRAGMA table_info({table})")
    cols = [c[1] for c in cur.fetchall()]
    q = f"SELECT * FROM {table} ORDER BY rowid DESC LIMIT {limit}"
    rows = conn.execute(q).fetchall()
    print(f"\n--- Recent {len(rows)} rows from {table} (most recent first) ---")
    print(", ".join(cols))
    for r in rows:
        print(r)

def export_table_csv(conn, table, out_file):
    cur = conn.execute(f"SELECT * FROM {table}")
    cols = [d[0] for d in cur.description]
    with open(out_file, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        writer.writerows(cur.fetchall())
    print(f"Exported {table} -> {out_file}")

def main():
    conn = sqlite3.connect(DB)
    tables = get_tables(conn)
    print("Tables found:", tables)
    table = TABLE or (tables[0] if tables else None)
    if not table:
        print("No tables found in DB.")
        return

    print_recent_rows(conn, table, LIMIT)
    # Optionally export for faculty
    export_table_csv(conn, table, f"{table}_export.csv")
    conn.close()

if __name__ == "__main__":
    main()
