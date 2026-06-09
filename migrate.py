import sqlite3

DATABASE = 'verifyme.db'

def run_migration():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        print("Attempting to inject 'candidate_email' into screenings ledger...")
        # 1. Add the candidate_email column safely
        cursor.execute("ALTER TABLE screenings ADD COLUMN candidate_email TEXT;")
        
        # 2. (Optional) Migrate any legacy candidate_id text entries to the new email column to prevent null values
        cursor.execute("UPDATE screenings SET candidate_email = candidate_id WHERE candidate_email IS NULL;")
        
        conn.commit()
        print("Migration successful! Column 'candidate_email' injected flawlessly.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("System Note: Column already existed in the structure matrix.")
        else:
            print(f"Migration operational failure: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    run_migration()