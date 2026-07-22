import mysql.connector
import os
import sys

HOST = "sakura.proxy.rlwy.net"
PORT = 15473
USER = "root"
DATABASE = "railway"
SCHEMA_FILE = "backend/schema_production.sql"

def main():
    password = os.environ.get("RAILWAY_DB_PASSWORD")
    if not password:
        print("ERROR: RAILWAY_DB_PASSWORD environment variable is not set.")
        print('Run this first:  $env:RAILWAY_DB_PASSWORD = "your_password_here"')
        sys.exit(1)

    print(f"Password length read: {len(password)}")

    conn = mysql.connector.connect(
        host=HOST,
        port=PORT,
        user=USER,
        password=password,
        database=DATABASE,
        use_pure=True
    )
    cursor = conn.cursor()

    with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
        sql_script = f.read()

    statements = []
    current = ""
    delimiter = ";"
    for line in sql_script.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("DELIMITER"):
            parts = stripped.split()
            delimiter = parts[1] if len(parts) > 1 else ";"
            continue
        current += line + "\n"
        if current.rstrip().endswith(delimiter):
            stmt = current.rstrip()[: -len(delimiter)].strip()
            if stmt:
                statements.append(stmt)
            current = ""

    if current.strip():
        statements.append(current.strip())

    print(f"Found {len(statements)} statements to run.\n")

    for i, stmt in enumerate(statements, 1):
        try:
            cursor.execute(stmt)
            conn.commit()
            preview = stmt.strip().splitlines()[0][:80]
            print(f"[{i}/{len(statements)}] OK: {preview}")
        except mysql.connector.Error as e:
            preview = stmt.strip().splitlines()[0][:80]
            print(f"[{i}/{len(statements)}] FAILED: {preview}")
            print(f"    -> {e}")

    cursor.close()
    conn.close()
    print("\nDone.")

if __name__ == "__main__":
    main()