import sqlite3
import os

DB_PATH = '/app/instance/app.db'

def list_columns():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(user)")
    columns = [row[1] for row in cursor.fetchall()]
    conn.close()
    return columns

def migrate():
    if not os.path.exists(DB_PATH):
        print("DB does not exist, nothing to migrate.")
        return

    cols = list_columns()
    print(f"Current columns: {cols}")
    
    if 'encrypted_totp_secret' not in cols:
        print("Adding column encrypted_totp_secret...")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN encrypted_totp_secret VARCHAR(300)")
            conn.commit()
            print("Migration successful.")
        except Exception as e:
            print(f"Migration failed: {e}")
        finally:
            conn.close()
    else:
        print("Column already exists.")

if __name__ == "__main__":
    migrate()
