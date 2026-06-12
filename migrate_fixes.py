import sqlite3

DATABASE = 'verifyme.db'

def run_migrations():
    print("🚀 Initializing Operational Database Patch Schema...")
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # ─── PATCH 1: UPGRADE SCREENINGS TABLE ──────────────────────────────────
    # Check if payment columns already exist to prevent duplicate crash errors
    cursor.execute("PRAGMA table_info(screenings)")
    screenings_columns = [col[1] for col in cursor.fetchall()]
    
    columns_to_add_to_screenings = {
        "payment_method": "TEXT",
        "payment_status": "TEXT DEFAULT 'Pending'",
        "payment_ref": "TEXT",
        "pop_file_path": "TEXT"
    }
    
    for col_name, col_type in columns_to_add_to_screenings.items():
        if col_name not in screenings_columns:
            print(f"➕ Adding missing structural column [{col_name}] to table [screenings]...")
            cursor.execute(f"ALTER TABLE screenings ADD COLUMN {col_name} {col_type}")
        else:
            print(f"✅ Column [{col_name}] already verified in [screenings]. Skipping.")

    # ─── PATCH 2: UPGRADE INDIVIDUAL AUDITS TABLE ─────────────────────────────
    cursor.execute("PRAGMA table_info(individual_audits)")
    individual_columns = [col[1] for col in cursor.fetchall()]
    
    columns_to_add_to_individual = {
        "payment_method": "TEXT DEFAULT 'manual_eft'",
        "payment_status": "TEXT DEFAULT 'Pending'",
        "payment_ref": "TEXT",
        "pop_file_path": "TEXT"
    }
    
    for col_name, col_type in columns_to_add_to_individual.items():
        if col_name not in individual_columns:
            print(f"➕ Adding missing structural column [{col_name}] to table [individual_audits]...")
            cursor.execute(f"ALTER TABLE individual_audits ADD COLUMN {col_name} {col_type}")
        else:
            print(f"✅ Column [{col_name}] already verified in [individual_audits]. Skipping.")

    # ─── PATCH 3: ENSURE SEED ADMIN ARCHETYPE PRIVILEGES EXIST ───────────────
    # In case init_db skipped it due to lock state errors
    cursor.execute("SELECT id FROM users WHERE applicant_type = 'admin'")
    admin_exists = cursor.fetchone()
    
    if not admin_exists:
        print("👤 Admin identity missing from ledger. Injecting seed administrator records...")
        from werkzeug.security import generate_password_hash
        hashed_pass = generate_password_hash("adminsecret", method='pbkdf2:sha256')
        cursor.execute('''
            INSERT INTO users (email, password_hash, applicant_type, individual_name)
            VALUES (?, ?, ?, ?)
        ''', ('admin@insphiredops.co.za', hashed_pass, 'admin', 'SecOps Specialist'))
    else:
        print("✅ Core Admin identity verified in user ledger.")

    # Commit all changes securely and close connection context
    conn.commit()
    conn.close()
    print("🎉 Structural database synchronization complete! Run 'python app.py' to boot safely.")

if __name__ == '__main__':
    run_migrations()