# migrate_vault.py
import sqlite3

def run_migration():
    conn = sqlite3.connect('verifyme.db')
    cursor = conn.cursor()
    
    alterations = [
        # Upgrades to Corporate Candidates pipeline table
        ("ALTER TABLE screenings ADD COLUMN id_file_path TEXT;", "id_file_path to screenings"),
        ("ALTER TABLE screenings ADD COLUMN qualification_file_path TEXT;", "qualification_file_path to screenings"),
        ("ALTER TABLE screenings ADD COLUMN rejection_reason TEXT;", "rejection_reason to screenings"),
        
        # Upgrades to Individual Self-Verification ledger
        ("ALTER TABLE individual_audits ADD COLUMN id_file_path TEXT;", "id_file_path to individual_audits"),
        ("ALTER TABLE individual_audits ADD COLUMN qualification_file_path TEXT;", "qualification_file_path to individual_audits"),
        ("ALTER TABLE individual_audits ADD COLUMN rejection_reason TEXT;", "rejection_reason to individual_audits"),
    ]
    
    for query, label in alterations:
        try:
            cursor.execute(query)
            print(f"[SUCCESS] Migrated column: {label}")
        except sqlite3.OperationalError:
            print(f"[SKIPPED] Column already exists: {label}")
            
    conn.commit()
    conn.close()

if __name__ == '__main__':
    run_migration()