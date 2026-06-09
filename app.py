import os
import sqlite3
import csv
import io
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'super_secure_verifyme_key'
DATABASE = 'verifyme.db'

# --- DATABASE MANAGEMENT ARCHITECTURE ---

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Returns query rows as clean dictionary structures
    return conn

def init_db():
    """Initializes the verification data vault structures inside SQLite."""
    with get_db_connection() as conn:
        # 1. Main Accounts Ledger (Handles both corporate and individual profiles)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                applicant_type TEXT NOT NULL,       -- 'individual' or 'company'
                individual_name TEXT,               -- Nullable if corporate
                individual_id TEXT,                 -- Nullable if corporate
                company_name TEXT,                  -- Nullable if individual
                company_contact TEXT,               -- Nullable if individual
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 2. Corporate Screenings Pipeline Table (Updated for Name + Email Bulk Entry Strategy)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS screenings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,            -- Links to the corporate creator
                candidate_name TEXT NOT NULL,
                candidate_email TEXT NOT NULL,       -- Captured from bulk registry CSV upload
                screening_type TEXT NOT NULL,        -- 'Identity Verification', 'Academic Credentials Audit', etc.
                status TEXT DEFAULT 'Pending Input', -- Default waiting state for candidate forms
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # 3. Individual Self-Verification Audit Ledger
        conn.execute('''
            CREATE TABLE IF NOT EXISTS individual_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,            -- Links to individual applicant
                verification_type TEXT NOT NULL,     -- 'National ID Card Audit', 'Tertiary Qualification Audit'
                status TEXT DEFAULT 'Pending',       -- 'Pending', 'Cleared', etc.
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()

# Always safe to run on startup. SQLite handles tables gracefully if they already exist.
init_db()


# --- PUBLIC & AUTH ROUTING CHANNELS ---

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        applicant_type = request.form.get('applicant_type')  # 'individual' or 'company'

        individual_name = request.form.get('individual_name')
        individual_id = request.form.get('individual_id')
        company_name = request.form.get('company_name')
        company_contact = request.form.get('company_contact')

        if applicant_type == 'individual':
            company_name = None
            company_contact = None
            if not individual_name or not individual_id:
                flash('Please complete your Full Legal Name and National ID field metrics.', 'error')
                return redirect(url_for('register'))
        else:
            individual_name = None
            individual_id = None
            if not company_name or not company_contact:
                flash('Please complete your Registered Entity and Representative field metrics.', 'error')
                return redirect(url_for('register'))

        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

        with get_db_connection() as conn:
            try:
                conn.execute('''
                    INSERT INTO users (
                        email, password_hash, applicant_type, 
                        individual_name, individual_id, 
                        company_name, company_contact
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    email, password_hash, applicant_type, 
                    individual_name, individual_id, 
                    company_name, company_contact
                ))
                conn.commit()

                flash('Workspace profile structured successfully! Please sign in.', 'success')
                return redirect(url_for('login'))

            except sqlite3.IntegrityError:
                flash('This exact email workspace slot is already registered.', 'error')
                return redirect(url_for('register'))

    return render_template('auth/register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')

        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            session['applicant_type'] = user['applicant_type']
            session['display_name'] = user['company_name'] if user['applicant_type'] == 'company' else user['individual_name']

            flash('Authentication verified successfully!', 'success')
            
            if user['applicant_type'] == 'company':
                return redirect(url_for('dashboard_corporate'))
            else:
                return redirect(url_for('dashboard_individual'))
        
        flash('Invalid credentials validation parameters provided.', 'error')
        return redirect(url_for('login'))

    return render_template('auth/login.html')


# --- SECURED ENTERPRISE DASHBOARD CHANNELS (COMPANIES) ---

@app.route('/dashboard/corporate')
def dashboard_corporate():
    if 'user_id' not in session or session.get('applicant_type') != 'company':
        flash('Access denied. Corporate clearance required.', 'error')
        return redirect(url_for('login'))

    # Query real candidate rows belonging strictly to this corporate entity
    with get_db_connection() as conn:
        candidates = conn.execute('''
            SELECT id,
                   candidate_name AS name, 
                   candidate_email AS email, 
                   screening_type AS type, 
                   status, 
                   DATE(created_at) AS date 
            FROM screenings 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        ''', (session['user_id'],)).fetchall()

    return render_template('dashboard_corporate.html', candidates=candidates, hide_navbar=True, hide_footer=True)


@app.route('/initiate-screening', methods=['POST'])
def initiate_screening():
    if 'user_id' not in session or session.get('applicant_type') != 'company':
        return redirect(url_for('login'))

    screening_type = request.form.get('screening_type')
    candidate_count = request.form.get('candidate_count')

    # File and Verification checking validation routines
    if 'candidate_csv' not in request.files or 'pop_receipt' not in request.files:
        flash('All screening profile metrics are required. Please upload both candidate registry and proof of payment files.', 'error')
        return redirect(url_for('dashboard_corporate'))

    csv_file = request.files['candidate_csv']
    pop_file = request.files['pop_receipt']

    if csv_file.filename == '' or pop_file.filename == '':
        flash('All screening profile metrics are required. Invalid file options chosen.', 'error')
        return redirect(url_for('dashboard_corporate'))

    try:
        # 1. Read file bytes directly out of memory stream
        file_bytes = csv_file.read()
        
        # 'utf-8-sig' cleanly unmasks hidden BOM headers added by tools like MS Excel
        file_data = file_bytes.decode("utf-8-sig")
        
        # 2. Dynamic Delimiter Evaluation Matrix
        try:
            # Inspect sample boundary to auto-discover standard commas or regional semicolons (;)
            dialect = csv.Sniffer().sniff(file_data[:2048], delimiters=',;\t|')
            detected_delimiter = dialect.delimiter
        except Exception:
            detected_delimiter = ','  # Defensible standard fallback execution

        # 3. Stream data loop iterations
        csv_input = csv.reader(io.StringIO(file_data), delimiter=detected_delimiter)
        
        # Pull or skip file table headers securely (e.g. Name,Email)
        header = next(csv_input, None)
        
        inserted_count = 0

        with get_db_connection() as conn:
            for row in csv_input:
                if not row or len(row) < 2:
                    continue  # Protect database from clean formatting rows or trace gaps
                
                c_name = row[0].strip()
                c_email = row[1].strip()

                if not c_name or not c_email:
                    continue

                conn.execute('''
                    INSERT INTO screenings (user_id, candidate_name, candidate_email, screening_type, status)
                    VALUES (?, ?, ?, ?, 'Pending Input')
                ''', (session['user_id'], c_name, c_email, screening_type))
                inserted_count += 1
            
            conn.commit()

        flash(f'Successfully initialized tracking. Staged {inserted_count} batch candidates onto pipeline matrix.', 'success')
        
    except Exception as e:
        flash(f'Bulk operation failed. Integrity checks details: {str(e)}', 'error')

    return redirect(url_for('dashboard_corporate'))


# --- SECURED PERSONAL DASHBOARD CHANNELS (INDIVIDUALS) ---

@app.route('/dashboard/individual')
def dashboard_individual():
    if 'user_id' not in session or session.get('applicant_type') != 'individual':
        flash('Access denied. Individual validation profile required.', 'error')
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        checks = conn.execute('''
            SELECT verification_type AS type, status, DATE(created_at) AS date 
            FROM individual_audits 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        ''', (session['user_id'],)).fetchall()

    return render_template('dashboard_individual.html', checks=checks, hide_navbar=True, hide_footer=True)


@app.route('/submit-individual-verification', methods=['POST'])
def submit_individual_verification():
    if 'user_id' not in session or session.get('applicant_type') != 'individual':
        return redirect(url_for('login'))

    verification_type = request.form.get('verification_type')
    uploaded_docs = request.files.getlist('documents')
    proof_of_payment = request.files.get('proof_of_payment')

    if not verification_type or not uploaded_docs or not proof_of_payment:
        flash('All verification credentials and your proof of payment are required.', 'error')
        return redirect(url_for('dashboard_individual'))

    with get_db_connection() as conn:
        conn.execute('''
            INSERT INTO individual_audits (user_id, verification_type)
            VALUES (?, ?)
        ''', (session['user_id'], verification_type))
        conn.commit()

    flash(f'Successfully initialized {verification_type} audit pipeline.', 'success')
    return redirect(url_for('dashboard_individual'))


@app.route('/logout')
def logout():
    session.clear()
    flash('Security session decoupled safely. Workspace locked.', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)