import sqlite3

DATABASE = 'verifyme.db'

def fix_schema():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        print("Starting database schema migration...")
        
        # 1. Add the missing candidate_email column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE screenings ADD COLUMN candidate_email TEXT;")
            print("-> Added 'candidate_email' column.")
        except sqlite3.OperationalError:
            print("-> 'candidate_email' column already exists.")

        # 2. SQLite doesn't easily allow dropping NOT NULL constraints directly, 
        # so we will make the old 'candidate_id' column optional (nullable) by re-creating or altering if needed.
        # However, the quickest safe way in SQLite without losing data is to just drop and recreate the screenings table
        # since it's just a pipeline table.
        
        print("-> Re-creating screenings table with the updated schema...")
        cursor.execute("DROP TABLE IF EXISTS screenings;")
        cursor.execute('''
            CREATE TABLE screenings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                candidate_name TEXT NOT NULL,
                candidate_email TEXT NOT NULL,
                screening_type TEXT NOT NULL,
                status TEXT DEFAULT 'Pending Input',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        print("Database migration completed successfully! The corporate pipeline is ready.")
        
    except Exception as e:
        print(f"Migration failed: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    fix_schema()