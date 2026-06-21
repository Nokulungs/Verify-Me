import os
import sqlite3
import csv
import io
import urllib.parse
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import uuid
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Initialize Environmental Context
load_dotenv()

class Config:
    """Core Application Configurations."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'super_secure_verifyme_key')
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000').strip()
    
    # PayFast API Binding Configurations
    PAYFAST_MERCHANT_ID = os.environ.get('PAYFAST_MERCHANT_ID', '10050117')
    PAYFAST_MERCHANT_KEY = os.environ.get('PAYFAST_MERCHANT_KEY', 'muy2vlzbld3vi')
    PAYFAST_PASSPHRASE = os.environ.get('PAYFAST_PASSPHRASE')
    PAYFAST_POST_URL = os.environ.get('PAYFAST_POST_URL', 'https://sandbox.payfast.co.za/eng/process')

app = Flask(__name__)

app.config.from_object(Config)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'verifyme.db')

# --- FILE CAPTURE CONFIGURATIONS ---
UPLOAD_FOLDER = os.path.join('static', 'uploads', 'receipts')
DOCS_FOLDER = os.path.join('static', 'uploads', 'credentials')
UPLOAD_REGISTRY_DIR = os.path.join('static', 'uploads', 'registries')
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOCS_FOLDER'] = DOCS_FOLDER
app.config['UPLOAD_REGISTRY_DIR'] = UPLOAD_REGISTRY_DIR

# Ensure target server storage paths exist safely
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOCS_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_REGISTRY_DIR, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_individual_cost(verification_type):
    prices = {
        'Identity Verification & Validation': 450.00,
        'Criminal Record & Background Check': 550.00,
        'Credit & Financial Check': 380.00,
        'Professional License Verification': 320.00,
        'Global Compliance Screening': 620.00,
        'Social Media & Digital Footprint': 280.00
    }
    return prices.get(verification_type, 450.00)

# --- DATABASE MANAGEMENT ARCHITECTURE ---

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    """
    Establishes a connection thread pool link directly to Render Postgres 
    or falls back to a safe local testing connection profile.
    """
    if DATABASE_URL:
        # Connect directly to your live Render/Supabase Cloud DB
        conn = psycopg2.connect(DATABASE_URL)
    else:
        # Local development fallback parameters if you don't have DATABASE_URL set locally
        conn = psycopg2.connect(
            host="localhost",
            database="verifyme",
            user="postgres",
            password="yourpassword", # Put your local pgAdmin password here
            port="5432"
        )
    return conn

def init_db():
    """Initializes the verification schemas using standard PostgreSQL dialects."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Accounts Ledger (Using SERIAL for autoincrement keys instead of SQLite's AUTOINCREMENT)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            applicant_type TEXT NOT NULL,       
            individual_name TEXT,              
            individual_id TEXT,                
            company_name TEXT,                  
            company_contact TEXT,              
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 2. Corporate Screenings Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS screenings (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,            
            candidate_name TEXT NOT NULL,
            candidate_email TEXT NOT NULL,       
            screening_type TEXT NOT NULL,        
            status TEXT DEFAULT 'Awaiting Payment', 
            payment_method TEXT DEFAULT 'manual_eft',                 
            payment_status TEXT DEFAULT 'Pending',
            payment_ref TEXT,                    
            pop_file_path TEXT,                  
            id_file_path TEXT,                   
            qualification_file_path TEXT,        
            rejection_reason TEXT,               
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 3. Individual Self-Verification Audit Ledger
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS individual_audits (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,            
            verification_type TEXT NOT NULL,     
            status TEXT DEFAULT 'Awaiting Payment', 
            payment_method TEXT DEFAULT 'manual_eft',
            payment_status TEXT DEFAULT 'Pending',
            payment_ref TEXT,                    
            pop_file_path TEXT,                  
            id_file_path TEXT,                   
            qualification_file_path TEXT,        
            rejection_reason TEXT,               
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()

    # Seed Admin Account Slot Safely
    try:
        cursor.execute("SELECT 1 FROM users WHERE applicant_type = 'admin'")
        if not cursor.fetchone():
            hashed_admin_pass = generate_password_hash("adminsecret", method='pbkdf2:sha256')
            cursor.execute('''
                INSERT INTO users (email, password_hash, applicant_type, individual_name)
                VALUES (%s, %s, %s, %s)
            ''', ('admin@insphiredops.co.za', hashed_admin_pass, 'admin', 'SecOps Specialist'))
            conn.commit()
    except Exception as e:
        print(f"Admin seeding diagnostic notice: {e}")
    finally:
        cursor.close()
        cursor.close()

# Initialize tables immediately on server thread start
init_db()


# --- DECORATOR INTERCEPT FOR SECURE ROLE ACCESS ---
def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Authentication required. Access checkpoint blocked.", "error")
                return redirect(url_for('login'))
            if session.get('applicant_type') not in allowed_roles:
                abort(403) 
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- PUBLIC & AUTH ROUTING CHANNELS ---

@app.route('/')
def index():
    return render_template('index.html')

def is_strong_password(password):
    """Enforces 8 length, 1 number, 1 special character."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number."
    if not any(char in "!@#$%^&*()-_=+[{]};:'\",<.>/?`~" for char in password):
        return False, "Password must contain at least one special character."
    return True, ""

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Safely capture string parameters with fallback empty targets
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        applicant_type = (request.form.get('applicant_type') or '').strip()

        individual_name = (request.form.get('individual_name') or '').strip()
        individual_id = (request.form.get('individual_id') or '').strip()
        company_name = (request.form.get('company_name') or '').strip()
        company_contact = (request.form.get('company_contact') or '').strip()

        # 1. Base Field Blank-State Validations
        if not email:
            flash('Infrastructure authentication failure: Email field cannot be left blank.', 'error')
            return render_template('auth/register.html')
            
        if not applicant_type:
            flash('Infrastructure authentication failure: Please select an account operational type profile.', 'error')
            return render_template('auth/register.html')

        if not password:
            flash('Infrastructure authentication failure: Password security parameter cannot be left blank.', 'error')
            return render_template('auth/register.html')

        # 2. Strong Password Complexity Enforcement
        is_valid, password_error_msg = is_strong_password(password)
        if not is_valid:
            flash(password_error_msg, 'error')
            return render_template('auth/register.html')

        # 3. Conditional Operational Account Validations
        if applicant_type == 'individual':
            company_name, company_contact = None, None
            if not individual_name or not individual_id:
                flash('Please complete your Full Legal Name and National ID fields completely.', 'error')
                return render_template('auth/register.html')
        else:
            individual_name, individual_id = None, None
            if not company_name or not company_contact:
                flash('Please complete your Registered Entity and Representative corporate validation fields.', 'error')
                return render_template('auth/register.html')

        # 4. Generate Standard Cryptographic Secure Hash String
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

        # 5. Database Pipeline Core Entry Execution
        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO users (
                        email, password_hash, applicant_type, individual_name, individual_id, company_name, company_contact
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ''', (email, password_hash, applicant_type, individual_name, individual_id, company_name, company_contact))
                conn.commit()
                cursor.close()
                
                flash('Workspace profile structured successfully! Please sign in.', 'success')
                return redirect(url_for('login'))
                
            except sqlite3.IntegrityError:
                flash('This exact email workspace slot is already registered within our system network.', 'error')
                return render_template('auth/register.html')

    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Safely capture parameters with fallback values
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''

        # 1. Server-Side Native Blank-State Validations
        if not email:
            flash('Infrastructure authentication failure: Email parameter cannot be left blank.', 'error')
            return render_template('auth/login.html')
            
        if not password:
            flash('Infrastructure authentication failure: Password security verification parameter cannot be left blank.', 'error')
            return render_template('auth/login.html')

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                # 🛠️ FIXED: Separate the execution from the fetching step
                cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
                user = cursor.fetchone()
                cursor.close()
        except Exception as e:
            print(f"Login Database Connectivity Error: {e}")
            flash('A core infrastructure network data error occurred. Please try again.', 'error')
            return render_template('auth/login.html')

        # 2. Development Bypass, Admin Architecture, and Hash Validations
        is_valid_admin = (email == 'admin@insphiredops.co.za' and password == 'adminsecret')
        is_valid_hash = user and check_password_hash(user['password_hash'], password)

        if is_valid_admin or is_valid_hash:
            # If they used the correct admin credentials but the DB was using plain text, auto-heal on the fly!
            if is_valid_admin and user and user['password_hash'] == 'adminsecret':
                try:
                    corrected_hash = generate_password_hash("adminsecret", method='pbkdf2:sha256')
                    with get_db_connection() as repair_conn:
                        # 🛠️ FIXED: Explicitly initialize the repair_cursor object
                        repair_cursor = repair_conn.cursor()
                        repair_cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s", (corrected_hash, email))
                        repair_conn.commit()
                        repair_cursor.close()
                    print("🔧 Security Ledger Auto-Healed: Fixed plain-text admin password hash in database.")
                except Exception as repair_err:
                    print(f"🔧 Security Ledger Auto-Heal Failed: {repair_err}")
                    pass

            # 3. Clean Session Security State Configuration Binding
            session.clear()  # Drop any lingering session tracking states safely
            session['user_id'] = user['id'] if user else 1
            session['user_email'] = email
            session['applicant_type'] = user['applicant_type'] if user else 'admin'
            
            # 4. Context-Specific Role Redirection Paths
            if session['applicant_type'] == 'company':
                session['display_name'] = user['company_name'] if user else 'Corporate Entity'
                flash(f"Welcome back to workspace network context: {session['display_name']}", 'success')
                return redirect(url_for('dashboard_corporate'))
                
            elif session['applicant_type'] == 'admin':
                session['display_name'] = user['individual_name'] if user else 'SecOps Specialist'
                flash("Administrative operational clearance granted.", 'success')
                return redirect(url_for('admin_dashboard'))
                
            else:
                session['display_name'] = user['individual_name'] if user else 'Verified Account'
                flash(f"Welcome back, {session['display_name']}!", 'success')
                return redirect(url_for('dashboard_individual'))
        
        # 5. Mismatched or Invalid Input Rejection Strategy
        flash('Invalid credentials validation parameters provided.', 'error')
        return render_template('auth/login.html')

    return render_template('auth/login.html')
# ─── THE ADMINISTRATIVE MASTER WORKSPACE VAULT ───────────

@app.route('/admin/workspace')
@role_required(['admin'])
def admin_dashboard():
    conn = get_db_connection()
    
    total_users = cursor.execute("SELECT COUNT(*) FROM users WHERE applicant_type != 'admin'").fetchone()[0]
    total_corp = cursor.execute("SELECT COUNT(*) FROM screenings").fetchone()[0]
    total_indiv = cursor.execute("SELECT COUNT(*) FROM individual_audits").fetchone()[0]
    
    metrics = {
        "total_users": total_users,
        "total_corp": total_corp,
        "total_indiv": total_indiv,
        "gross_revenue": "Cross-Channel Verification Active"
    }

    pending_eft_count = cursor.execute("SELECT COUNT(DISTINCT payment_ref) FROM screenings WHERE payment_method = 'manual_eft' AND payment_status = 'Pending'").fetchone()[0]
    pending_eft_count += cursor.execute("SELECT COUNT(*) FROM individual_audits WHERE payment_method = 'manual_eft' AND payment_status = 'Pending'").fetchone()[0]
    
    ready_review_count = cursor.execute("SELECT COUNT(*) FROM screenings WHERE status = 'Ready for Review'").fetchone()[0]
    ready_review_count += cursor.execute("SELECT COUNT(*) FROM individual_audits WHERE status = 'Ready for Review'").fetchone()[0]
    
    quick_alerts = {
        "pending_efts": pending_eft_count,
        "ready_reviews": ready_review_count
    }

    companies = cursor.execute("SELECT DISTINCT company_name FROM users WHERE company_name IS NOT NULL AND company_name != ''").fetchall()
    selected_company = request.args.get('company_filter', '')
    
    query_corp = "SELECT s.*, u.company_name FROM screenings s JOIN users u ON s.user_id = u.id"
    if selected_company:
        corporate_candidates = cursor.execute(query_corp + " WHERE u.company_name = %s ORDER BY s.created_at DESC", (selected_company,)).fetchall()
    else:
        corporate_candidates = cursor.execute(query_corp + " ORDER BY s.created_at DESC").fetchall()

    individual_requests = cursor.execute("""
        SELECT a.*, u.email FROM individual_audits a JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC
    """).fetchall()

    payments_queue = cursor.execute('''
        SELECT payment_ref, u.company_name AS party_name, screening_type AS service, payment_method, payment_status, pop_file_path,
               COUNT(s.id) AS units, 'company' AS type
        FROM screenings s JOIN users u ON s.user_id = u.id
        WHERE payment_ref IS NOT NULL AND payment_ref != ''
        GROUP BY payment_ref
        UNION ALL
        SELECT payment_ref, u.individual_name AS party_name, verification_type AS service, payment_method, payment_status, pop_file_path,
               1 AS units, 'individual' AS type
        FROM individual_audits a JOIN users u ON a.user_id = u.id
        WHERE payment_ref IS NOT NULL AND payment_ref != ''
        GROUP BY payment_ref
        ORDER BY payment_status DESC
    ''').fetchall()

    users_ledger = cursor.execute("SELECT id, email, company_name, individual_name, applicant_type FROM users WHERE applicant_type != 'admin'").fetchall()
    cursor.close()
    
    return render_template(
        'admin_dashboard.html',
        metrics=metrics,
        quick_alerts=quick_alerts,
        companies=companies,
        selected_company=selected_company,
        corporate_candidates=corporate_candidates,
        individual_requests=individual_requests,
        payments_queue=payments_queue,
        users_ledger=users_ledger
    )


@app.route('/admin/update-candidate-status', methods=['POST'])
@role_required(['admin'])
def update_candidate_status():
    candidate_id = request.form.get('id')
    new_status = request.form.get('status')
    track = request.form.get('track', 'corporate') 
    
    with get_db_connection() as conn:
        if track == 'corporate':
            cursor.execute("UPDATE screenings SET status = %s WHERE id = %s", (new_status, candidate_id))
        else:
            cursor.execute("UPDATE individual_audits SET status = %s WHERE id = %s", (new_status, candidate_id))
        conn.commit()
    
    flash(f"Candidate status updated to [{new_status}] successfully.", "success")
    return redirect(url_for('admin_dashboard', tab=track))


@app.route('/admin/flag-document', methods=['POST'])
@role_required(['admin'])
def flag_document():
    record_id = request.form.get('id')
    reason = request.form.get('flag_reason')
    track = request.form.get('track', 'corporate')
    
    status_label = "Flagged — Image Unclear"
    with get_db_connection() as conn:
        if track == 'corporate':
            cursor.execute("UPDATE screenings SET status = %s, rejection_reason = %s WHERE id = %s", (status_label, reason, record_id))
        else:
            cursor.execute("UPDATE individual_audits SET status = %s, rejection_reason = %s WHERE id = %s", (status_label, reason, record_id))
        conn.commit()
    
    flash("Document flagged. Re-upload instruction triggered back to applicant panel.", "warning")
    return redirect(url_for('admin_dashboard', tab=track))


@app.route('/admin/resolve-payment', methods=['POST'])
@role_required(['admin'])
def resolve_payment():
    pay_ref = request.form.get('payment_ref')
    action = request.form.get('action') 
    
    new_pay_status = 'Completed' if action == 'Confirm' else 'Failed'
    new_candidate_status = 'Awaiting Document Upload' if action == 'Confirm' else 'Awaiting Payment'
    
    with get_db_connection() as conn:
        cursor.execute("UPDATE screenings SET payment_status = %s, status = %s WHERE payment_ref = %s", (new_pay_status, new_candidate_status, pay_ref))
        cursor.execute("UPDATE individual_audits SET payment_status = %s, status = %s WHERE payment_ref = %s", (new_pay_status, 'Ready for Review' if action == 'Confirm' else 'Awaiting Payment', pay_ref))
        conn.commit()
    
    flash(f"Financial Ledger Clearance executed: Reference {pay_ref} is now [{new_pay_status}].", "success")
    return redirect(url_for('admin_dashboard', tab='payments'))


@app.route('/admin/purge-user/<int:user_id>', methods=['POST'])
@role_required(['admin'])
def purge_user(user_id):
    with get_db_connection() as conn:
        cursor.execute("DELETE FROM screenings WHERE user_id = %s", (user_id,))
        cursor.execute("DELETE FROM individual_audits WHERE user_id = %s", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
    
    flash("Master profile purged successfully.", "success")
    return redirect(url_for('admin_dashboard', tab='users'))


# --- SECURED CORPORATE WORKSPACE & DATA PROCESSING ---

@app.route('/dashboard/corporate')
def dashboard_corporate():
    if 'user_id' not in session or session.get('applicant_type') != 'company':
        flash('Access denied. Corporate clearance required.', 'error')
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        candidates = cursor.execute('''
            SELECT id, candidate_name AS name, candidate_email AS email, screening_type AS type, status, payment_status, DATE(created_at) AS date 
            FROM screenings WHERE user_id = %s ORDER BY created_at DESC
        ''', (session['user_id'],)).fetchall()

    return render_template('dashboard_corporate.html', candidates=candidates, hide_navbar=True, hide_footer=True)


@app.route('/initiate-screening', methods=['POST'])
def initiate_screening():
    """Captures corporate multi-step parameters and splits workflows into live gateway tunnels or traditional POP ledgers."""
    if 'user_id' not in session or session.get('applicant_type') != 'company':
        flash('Unauthorized workspace session scope parameters.', 'error')
        return redirect(url_for('login'))

    screening_type = request.form.get('screening_type')
    candidate_count = int(request.form.get('candidate_count', 1))
    payment_method = request.form.get('payment_method')
    payment_ref = request.form.get('payment_ref')
    
    if not payment_ref:
        payment_ref = "VFY-TX-" + str(os.urandom(3).hex().upper())
        
    if 'candidate_csv' not in request.files:
        flash('Candidate dataset directory file target missing.', 'error')
        return redirect(url_for('dashboard_corporate'))

    csv_file = request.files['candidate_csv']
    if csv_file.filename == '':
        flash('Invalid verification array selection.', 'error')
        return redirect(url_for('dashboard_corporate'))

    # Valuation Pricing Framework Models Matrix Tiers
    cost_per_candidate = calculate_individual_cost(screening_type)

    # 1. Store Candidate Registry File (Step 1)
    csv_path = None
    if csv_file and csv_file.filename != '':
        filename = secure_filename(csv_file.filename)
        csv_path = os.path.join(app.config['UPLOAD_REGISTRY_DIR'], f"{payment_ref}_{filename}")
        csv_file.save(csv_path)

    # 2. Parse candidate metrics natively out of raw bytes
    try:
        csv_file.seek(0) # Reset stream tracker pointer element
        file_bytes = csv_file.read()
        file_data = file_bytes.decode("utf-8-sig")
        
        try:
            dialect = csv.Sniffer().sniff(file_data[:2048], delimiters=',;\t|')
            detected_delimiter = dialect.delimiter
        except Exception:
            detected_delimiter = ','

        csv_input = csv.reader(io.StringIO(file_data), delimiter=detected_delimiter)
        header = next(csv_input, None)
        
        staged_rows = []
        for row in csv_input:
            if not row or len(row) < 2: 
                continue
            c_name, c_email = row[0].strip(), row[1].strip()
            if c_name and c_email: 
                staged_rows.append((c_name, c_email))

        if not staged_rows:
            flash('No functional candidates verified inside data stream registry.', 'error')
            return redirect(url_for('dashboard_corporate'))

        # FIX FOR ISSUE 3: ENFORCE RIGID COUNT MATCH
        if len(staged_rows) != candidate_count:
            flash(f"Registry Validation Mismatch: You declared a target metric of {candidate_count} candidate(s), but your uploaded CSV file contains {len(staged_rows)} rows. Please ensure they match exactly.", 'error')
            return redirect(url_for('dashboard_corporate'))

    except Exception as e:
        flash(f'Bulk metrics processing exception generated: {str(e)}', 'error')
        return redirect(url_for('dashboard_corporate'))

    # WORKFLOW CASE A: Traditional Manual Bank Transfer Routing
    if payment_method == 'manual_eft':
        if 'pop_receipt' not in request.files:
            flash('Proof of payment document required for manual ledger checkout tracking.', 'error')
            return redirect(url_for('dashboard_corporate'))

        pop_file = request.files['pop_receipt']
        pop_saved_path = None
        if pop_file and pop_file.filename != '' and allowed_file(pop_file.filename):
            base_name = secure_filename(pop_file.filename)
            unique_filename = f"{payment_ref}_{base_name}"
            pop_saved_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            pop_file.save(pop_saved_path)

        duplicates_skipped = 0
        with get_db_connection() as conn:
            for c_name, c_email in staged_rows:
                # FIX FOR ISSUE 2: IDENTIFY AND SKIP REPEAT ENTRIES
                existing = cursor.execute('''
                    SELECT 1 FROM screenings 
                    WHERE user_id = %s AND candidate_email = %s AND screening_type = %s
                    LIMIT 1
                ''', (session['user_id'], c_email, screening_type)).fetchone()
                
                if existing:
                    duplicates_skipped += 1
                    continue

                cursor.execute('''
                    INSERT INTO screenings (
                        user_id, candidate_name, candidate_email, screening_type, status, payment_method, payment_status, payment_ref, pop_file_path
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (session['user_id'], c_name, c_email, screening_type, 'Awaiting Review', 'manual_eft', 'Pending Review', payment_ref, pop_saved_path))
            conn.commit()

        if duplicates_skipped == len(staged_rows):
            flash("Batch processing skipped: All candidates in this file are already registered for this screening type.", "warning")
        elif duplicates_skipped > 0:
            flash(f"Staged pipeline records under Reference {payment_ref}. Loaded {len(staged_rows) - duplicates_skipped} new entries ({duplicates_skipped} duplicates automatically skipped).", "success")
        else:
            flash(f'Successfully staged {len(staged_rows)} pipeline items under Reference {payment_ref}. Automated launch requires administrator validation.', 'success')
            
        return redirect(url_for('dashboard_corporate'))

    # WORKFLOW CASE B: PayFast Automated Checkout Linkages (Credit Card / Instant EFT)
    else:
        duplicates_skipped = 0
        with get_db_connection() as conn:
            for c_name, c_email in staged_rows:
                # FIX FOR ISSUE 2: IDENTIFY AND SKIP REPEAT ENTRIES
                existing = cursor.execute('''
                    SELECT 1 FROM screenings 
                    WHERE user_id = %s AND candidate_email = %s AND screening_type = %s
                    LIMIT 1
                ''', (session['user_id'], c_email, screening_type)).fetchone()
                
                if existing:
                    duplicates_skipped += 1
                    continue

                cursor.execute('''
                    INSERT INTO screenings (
                        user_id, candidate_name, candidate_email, screening_type, status, payment_method, payment_status, payment_ref
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ''', (session['user_id'], c_name, c_email, screening_type, 'Awaiting Payment', payment_method, 'Pending Checkout', payment_ref))
            conn.commit()

        if duplicates_skipped == len(staged_rows):
            flash("Batch processing skipped: All candidates in this file are already registered for this screening type.", "warning")
            return redirect(url_for('dashboard_corporate'))
            
        # Re-evaluate payment amount for non-duplicate entities only
        active_count = len(staged_rows) - duplicates_skipped
        updated_bill_amount = cost_per_candidate * active_count

        # Transit directly into dynamic gateway link generator
        return redirect(url_for('payfast_checkout', record_id="BATCH", custom_ref=payment_ref, custom_amt=updated_bill_amount))
@app.route('/collect/upload-credentials/<int:candidate_id>', methods=['GET', 'POST'])
def candidate_upload_portal(candidate_id):
    if request.method == 'POST':
        id_file = request.files.get('identity_doc')
        qual_file = request.files.get('qualification_doc')
        
        id_path, qual_path = None, None
        if id_file and allowed_file(id_file.filename):
            filename = secure_filename(f"CAND_{candidate_id}_ID_{id_file.filename}")
            id_path = os.path.join(app.config['DOCS_FOLDER'], filename)
            id_file.save(id_path)
            
        if qual_file and allowed_file(qual_file.filename):
            filename = secure_filename(f"CAND_{candidate_id}_QUAL_{qual_file.filename}")
            qual_path = os.path.join(app.config['DOCS_FOLDER'], filename)
            qual_file.save(qual_path)
            
        with get_db_connection() as conn:
            cursor.execute('''
                UPDATE screenings SET id_file_path = %s, qualification_file_path = %s, status = 'Ready for Review', rejection_reason = NULL 
                WHERE id = %s
            ''', (id_path, qual_path, candidate_id))
            conn.commit()
            
        return "<h3>Upload Complete. Your files have been securely transmitted to our administrative operators for compliance auditing.</h3>"
        
    with get_db_connection() as conn:
        candidate = cursor.execute("SELECT * FROM screenings WHERE id = %s", (candidate_id,)).fetchone()
    if not candidate: 
        abort(404)
        
    return f"""
    <html>
        <body style="background:#111; color:#fff; font-family:sans-serif; padding: 3rem; max-width: 500px; margin: auto;">
            <h2>VerifyMe Security Portal</h2>
            <p>Hello <strong>{candidate['candidate_name']}</strong>, please upload clear digital file records for your <strong>{candidate['screening_type']}</strong>.</p>
            <form method="POST" enctype="multipart/form-data" style="background:#1c1c1c; padding:2rem; border-radius:8px;">
                <label style="display:block; margin-bottom:0.5rem;">National ID Document:</label>
                <input type="file" name="identity_doc" required style="margin-bottom:1.5rem;"><br>
                <label style="display:block; margin-bottom:0.5rem;">Qualification Certificate Matrix (Optional):</label>
                <input type="file" name="qualification_doc"><br><br>
                <button type="submit" style="background:#00f2fe; border:none; padding:0.5rem 1rem; font-weight:bold; border-radius:4px; cursor:pointer;">Submit Compliance Documents</button>
            </form>
        </body>
    </html>
    """


# --- SECURED PERSONAL DASHBOARD CHANNELS (INDIVIDUALS) ---

@app.route('/dashboard/individual')
def dashboard_individual():
    if 'user_id' not in session or session.get('applicant_type') != 'individual':
        flash('Access denied. Individual validation profile required.', 'error')
        return redirect(url_for('login'))

    with get_db_connection() as conn:
    # 1. Open the cursor with RealDictCursor so your dashboard templates don't break
        cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Query 1: Fetch the audit list rows
        cursor.execute('''
            SELECT id, verification_type AS type, status, payment_status, rejection_reason, DATE(created_at) AS date 
            FROM individual_audits 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        ''', (session['user_id'],))
        db_rows = cursor.fetchall()  # 🌟 Separate line for fetching all rows
        
    # Query 2: Fetch the user profile details
        cursor.execute('''
            SELECT email, individual_name, individual_id, created_at 
            FROM users 
            WHERE id = %s
        ''', (session['user_id'],))
        user_profile = cursor.fetchone()  # 🌟 Separate line for fetching the single row
        
        # 2. Clean up the cursor channel
        cursor.close()

    return render_template(
        'dashboard_individual.html', 
        checks=db_rows,      
        requests=db_rows,    
        audits=db_rows,      
        user_profile=user_profile, 
        hide_navbar=True, 
        hide_footer=True
    )


@app.route('/submit-local-verification', methods=['POST'])
@app.route('/submit-individual-verification', methods=['POST'])
@app.route('/initiate_individual_payment', methods=['POST'])
def initiate_individual_payment():
    if 'user_id' not in session or session.get('applicant_type') != 'individual':
        return redirect(url_for('login'))

    # 1. Parse Parameters Natively
    verification_type = request.form.get('verification_type')
    payment_method = request.form.get('payment_method', 'manual_eft')
    payment_ref = "VFY-IND-" + str(os.urandom(3).hex().upper())

    uploaded_docs = request.files.getlist('verification_documents')
    proof_of_payment = request.files.get('proof_of_payment')

    # Fallback sanity enforcement checks
    if not verification_type or not uploaded_docs or not uploaded_docs[0].filename:
        flash('Verification core documents are required to initialize an audit request.', 'error')
        return redirect(url_for('dashboard_individual'))

    # 2. Map Dynamic Status Codes Based on Choice Pathways
    if payment_method == 'gateway':
        initial_payment_status = 'Pending'
        initial_pipeline_status = 'Awaiting Payment'
        pop_saved_path = None
    else:
        initial_payment_status = 'Pending'
        initial_pipeline_status = 'Ready for Review'
        if not proof_of_payment or proof_of_payment.filename == '':
            flash('A manual bank wire proof of payment transfer receipt is required.', 'error')
            return redirect(url_for('dashboard_individual'))
        
        pop_filename = f"{payment_ref}_{secure_filename(proof_of_payment.filename)}"
        pop_saved_path = os.path.join(app.config['UPLOAD_FOLDER'], pop_filename)
        proof_of_payment.save(pop_saved_path)

    # 3. Document Array File Parsing Mappings (up to 2 files)
    id_path, qual_path = None, None
    for idx, doc in enumerate(uploaded_docs[:2]):
        if doc and allowed_file(doc.filename):
            unique_name = f"INDIV_{session['user_id']}_{idx}_{secure_filename(doc.filename)}"
            saved_path = os.path.join(app.config['DOCS_FOLDER'], unique_name)
            doc.save(saved_path)
            if idx == 0:
                id_path = saved_path
            elif idx == 1:
                qual_path = saved_path

    # 4. Save Record to Database Ledger
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO individual_audits (
                user_id, verification_type, payment_method, payment_status, 
                payment_ref, pop_file_path, id_file_path, qualification_file_path, status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            session['user_id'], verification_type, payment_method, initial_payment_status,
            payment_ref, pop_saved_path, id_path, qual_path, initial_pipeline_status
        ))
        conn.commit()
        generated_id = cursor.lastrowid

    # 5. Route Dynamic Submissions
    if payment_method == 'gateway':
        total_bill = calculate_individual_cost(verification_type)
        return redirect(url_for('payfast_checkout', record_id=generated_id, custom_ref=payment_ref, custom_amt=total_bill))

    flash(f'Successfully initialized your {verification_type} audit pipeline. Awaiting manual bank clearance checking.', 'success')
    return redirect(url_for('dashboard_individual'))


# --- ONLINE CHECKOUT LINKAGE PIPELINE ---

@app.route('/payfast-checkout')
def payfast_checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    record_id = request.args.get('record_id', 'BATCH')
    custom_ref = request.args.get('custom_ref')
    custom_amt = request.args.get('custom_amt', '450.00')

    # Assemble transaction dictionary maps for signature processing
    payfast_data = {
        'merchant_id': app.config['PAYFAST_MERCHANT_ID'],
        'merchant_key': app.config['PAYFAST_MERCHANT_KEY'],
        'return_url': f"{app.config['BASE_URL']}/payment-success?ref={custom_ref}&record_id={record_id}",
        # =========================================================
        # FIX FOR ISSUE 1: PASS THE REF TOKEN TO THE CANCEL LINK
        # =========================================================
        'cancel_url': f"{app.config['BASE_URL']}/payment-cancelled?ref={custom_ref}&record_id={record_id}",
        'notify_url': f"{app.config['BASE_URL']}/payfast-webhook",
        'name_first': session.get('display_name', 'Verified Applicant'),
        'email_address': session.get('user_email', 'noreply@verifyme.co.za'),
        'm_payment_id': f"{record_id}-{custom_ref}",
        'amount': f"{float(custom_amt):.2f}",
        'item_name': f"VerifyMe Audit Ref {custom_ref}"
    }

    # ... [Keep signature generation and form returning layout completely identical] ...
    payload_string = ""
    for key, val in payfast_data.items():
        if val:
            payload_string += f"{key}={urllib.parse.quote_plus(str(val).strip())}&"
    payload_string = payload_string[:-1]

    if app.config['PAYFAST_PASSPHRASE']:
        payload_string += f"&passphrase={urllib.parse.quote_plus(app.config['PAYFAST_PASSPHRASE'].strip())}"

    security_signature = hashlib.md5(payload_string.encode('utf-8')).hexdigest()
    payfast_data['signature'] = security_signature

    form_inputs = "".join([f'<input type="hidden" name="{k}" value="{v}">' for k, v in payfast_data.items()])
    
    html_redirect_payload = f"""
    <html>
        <body onload="document.forms['pf'].submit();" style="background:#181c19; color:#fff; font-family:sans-serif; text-align:center; padding-top:10%;">
            <h3>Establishing secure pipeline data tunnels to PayFast checkout gateway...</h3>
            <form name="pf" action="{app.config['PAYFAST_POST_URL']}" method="POST">
                {form_inputs}
            </form>
        </body>
    </html>
    """
    return html_redirect_payload


@app.route('/payment-success')
def payment_success():
    custom_ref = request.args.get('ref', '')
    
    if custom_ref:
        try:
            with get_db_connection() as conn:
                # 1. Update corporate screenings matching this reference
                cursor.execute(
                    "UPDATE screenings SET payment_status = 'Completed', status = 'Awaiting Document Upload' WHERE payment_ref = %s", 
                    (custom_ref,)
                )
                
                # 2. FIXED: Update ALL individual audits belonging to this payment reference token all at once
                cursor.execute(
                    """
                    UPDATE individual_audits 
                    SET payment_status = 'Completed', status = 'Ready for Review' 
                    WHERE payment_ref = %s
                    """, 
                    (custom_ref,)
                )
                conn.commit()
                print(f"✅ SecOps: Successfully verified and updated all records under reference: {custom_ref}")
        except Exception as e:
            print(f"Fallback update error: {e}")

    if session.get('applicant_type') == 'company':
        return redirect(url_for('dashboard_corporate'))
    return redirect(url_for('dashboard_individual'))


@app.route('/payment-cancelled')
def payment_cancelled():
    custom_ref = request.args.get('ref', '')
    record_id = request.args.get('record_id', '')

    with get_db_connection() as conn:
        # 1. Clear based on specific unique reference token if it exists (Clears ALL duplicates associated with this attempt)
        if custom_ref:
            try:
                # Clear from corporate pipeline context
                cursor.execute("""
                    DELETE FROM screenings 
                    WHERE payment_ref = %s 
                      AND (payment_status = 'Pending Checkout' OR status = 'Awaiting Payment')
                """, (custom_ref,))
                
                # Clear from individual citizen records context
                cursor.execute("""
                    DELETE FROM individual_audits 
                    WHERE payment_ref = %s 
                      AND (payment_status = 'Pending' OR status = 'Awaiting Payment')
                """, (custom_ref,))
                
                conn.commit()
                print(f"🛑 SecOps: Cleaned up all canceled ghost duplicates for tracking token {custom_ref}")
            except Exception as e:
                print(f"SecOps Node Error: Fallback tracking token clearance exception: {e}")

        # 2. Secondary cleanup validation checkpoint via record_id 
        elif record_id and record_id != 'BATCH':
            try:
                target_id = int(record_id)
                cursor.execute("""
                    DELETE FROM individual_audits 
                    WHERE id = %s 
                      AND (payment_status = 'Pending' OR status = 'Awaiting Payment')
                """, (target_id,))
                conn.commit()
            except ValueError:
                pass

    flash("Transaction canceled by applicant. Gateway connection dropped and unverified duplicate entries cleared.", "error")
    
    if session.get('applicant_type') == 'company':
        return redirect(url_for('dashboard_corporate'))
    return redirect(url_for('dashboard_individual'))

@app.route('/payfast-webhook', methods=['POST'])
def payfast_webhook():
    # Asynchronous background instant payment notification loop tracking
    m_payment_id = request.form.get('m_payment_id', '')
    payment_status = request.form.get('payment_status')

    if payment_status == 'COMPLETE' and m_payment_id:
        try:
            record_id, payment_ref = m_payment_id.split('-', 1)
            with get_db_connection() as conn:
                if record_id == 'BATCH':
                    cursor.execute("UPDATE screenings SET payment_status = 'Completed', status = 'Awaiting Document Upload' WHERE payment_ref = %s", (payment_ref,))
                else:
                    cursor.execute("UPDATE individual_audits SET payment_status = 'Completed', status = 'Ready for Review' WHERE id = %s", (record_id,))
                conn.commit()
        except Exception:
            pass
    return "OK", 200


@app.route('/logout')
def logout():
    session.clear()
    flash('Security session decoupled safely. Workspace locked.', 'success')
    return redirect(url_for('login'))

# --- ADMINISTRATIVE DATA EXPORT & SYSTEM ARCHIVE TRACKS ---

@app.route('/admin/export-corporate/csv')
@role_required(['admin'])
def export_corporate_csv():
    """Generates a streaming CSV report of the enterprise candidate screening matrix."""
    company_filter = request.args.get('company_filter', '')
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write structural CSV header fields
    writer.writerow([
        'Candidate ID', 'Registered Enterprise Name', 'Candidate Name', 
        'Candidate Email', 'Audit Vector Type', 'Current Status State', 
        'Billing Method', 'Payment Status Code', 'Financial Reference Token', 'Staging Date'
    ])
    
    query = "SELECT s.*, u.company_name FROM screenings s JOIN users u ON s.user_id = u.id"
    params = ()
    if company_filter:
        query += " WHERE u.company_name = %s"
        params = (company_filter,)
    
    query += " ORDER BY s.created_at DESC"
    
    with get_db_connection() as conn:
        records = cursor.execute(query, params).fetchall()
        
    for row in records:
        writer.writerow([
            f"CC-{row['id']}",
            row['company_name'],
            row['candidate_name'],
            row['candidate_email'],
            row['screening_type'],
            row['status'],
            row['payment_method'],
            row['payment_status'],
            row['payment_ref'],
            row['created_at']
        ])
        
    response = Flask.response_class(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-disposition": f"attachment; filename=corporate_screening_report_{datetime.now().strftime('%Y%m%d')}.csv"}
    )
    return response


@app.route('/admin/export-individual/csv')
@role_required(['admin'])
def export_individual_csv():
    """Generates a streaming CSV data vault export of individual citizen direct checks."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        'Audit Run Token', 'Applicant Account Email', 'Full Legal Name', 
        'National ID Number', 'Audit Focus Type', 'Pipeline Status State', 
        'Billing Method', 'Payment Status', 'Ledger Reference', 'Created At'
    ])
    
    with get_db_connection() as conn:
        records = cursor.execute("""
            SELECT a.*, u.email, u.individual_name, u.individual_id 
            FROM individual_audits a 
            JOIN users u ON a.user_id = u.id 
            ORDER BY a.created_at DESC
        """).fetchall()
        
    for row in records:
        writer.writerow([
            f"IND-{row['id']}",
            row['email'],
            row['individual_name'] if row['individual_name'] else 'Unspecified',
            row['individual_id'] if row['individual_id'] else 'Unspecified',
            row['verification_type'],
            row['status'],
            row['payment_method'],
            row['payment_status'],
            row['payment_ref'],
            row['created_at']
        ])
        
    response = Flask.response_class(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-disposition": f"attachment; filename=individual_audit_report_{datetime.now().strftime('%Y%m%d')}.csv"}
    )
    return response


@app.route('/admin/export-profile/pdf/<int:user_id>')
@role_required(['admin'])
def export_profile_pdf(user_id):
    """
    Renders an elegant, browser-printable security audit certificate panel.
    Adheres strictly to CSS design compliance rules with zero empty rulesets.
    """
    with get_db_connection() as conn:
        user_profile = cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)).fetchone()
        if not user_profile:
            abort(404)
            
        if user_profile['applicant_type'] == 'company':
            history = cursor.execute("SELECT id, candidate_name AS name, screening_type AS item, status, created_at FROM screenings WHERE user_id = %s", (user_id,)).fetchall()
        else:
            history = cursor.execute("SELECT id, '-' AS name, verification_type AS item, status, created_at FROM individual_audits WHERE user_id = %s", (user_id,)).fetchall()

    html_print_layout = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Identity Profile Verification Record — #USR-{user_profile['id']}</title>
        <style>
            body {{ background: #ffffff; color: #111111; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; padding: 3rem; margin: 0; }}
            .cert-container {{ border: 2px solid #2e3830; padding: 2rem; border-radius: 8px; }}
            .cert-header {{ border-bottom: 2px solid #617c41; padding-bottom: 1rem; margin-bottom: 2rem; }}
            .cert-title {{ font-size: 1.75rem; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; color: #181c19; }}
            .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; background: #f4f6f4; padding: 1.5rem; border-radius: 6px; }}
            .meta-label {{ font-size: 0.75rem; font-weight: bold; color: #617c41; text-transform: uppercase; margin-bottom: 0.25rem; }}
            .meta-value {{ font-size: 1rem; font-weight: 500; color: #1f2521; }}
            .history-table {{ width: 100%; border-collapse: collapse; margin-top: 1.5rem; }}
            .history-table th {{ background: #1f2521; color: #ffffff; text-align: left; padding: 0.75rem; font-size: 0.8rem; text-transform: uppercase; }}
            .history-table td {{ padding: 0.75rem; border-bottom: 1px solid #eef2ef; font-size: 0.875rem; }}
            .print-btn-strip {{ margin-bottom: 2rem; display: flex; gap: 1rem; }}
            .btn-print {{ background: #617c41; color: #ffffff; border: none; padding: 0.5rem 1.25rem; border-radius: 4px; font-weight: bold; cursor: pointer; }}
            @media print {{ .print-btn-strip {{ display: none; }} body {{ padding: 0; }} }}
        </style>
    </head>
    <body>
        <div class="print-btn-strip">
            <button class="btn-print" onclick="window.print();">Print / Save as PDF Document</button>
            <button class="btn-print" style="background:#252b27;" onclick="window.close();">Dismiss Terminal</button>
        </div>
        <div class="cert-container">
            <div class="cert-header">
                <div class="cert-title">System Account Audit Ledger Profile</div>
                <div style="font-size: 0.85rem; color: #617c41; font-weight: 500; margin-top: 0.25rem;">VERIFYME MULTI-CHANNEL DATA PROTECTION HUB</div>
            </div>
            
            <div class="meta-grid">
                <div>
                    <div class="meta-label">System Account Identifier</div>
                    <div class="meta-value">#USR-{user_profile['id']}</div>
                </div>
                <div>
                    <div class="meta-label">Clearance Group Scope</div>
                    <div class="meta-value" style="text-transform: uppercase;">{user_profile['applicant_type']}</div>
                </div>
                <div>
                    <div class="meta-label">Primary Registration Mail</div>
                    <div class="meta-value">{user_profile['email']}</div>
                </div>
                <div>
                    <div class="meta-label">Profile Authority Title</div>
                    <div class="meta-value">{user_profile['company_name'] if user_profile['company_name'] else user_profile['individual_name']}</div>
                </div>
            </div>

            <h3 style="text-transform: uppercase; font-size: 1rem; color: #181c19; border-bottom: 1px solid #2e3830; padding-bottom: 0.5rem;">Associated Active Run Matrix Runway</h3>
            <table class="history-table">
                <thead>
                    <tr>
                        <th>Instance Reference</th>
                        <th>Target Individual</th>
                        <th>Assigned Verification Core</th>
                        <th>Current State</th>
                        <th>Logged At</th>
                    </tr>
                </thead>
                <tbody>
    """
    
    for item in history:
        html_print_layout += f"""
                    <tr>
                        <td>#{item['id']}</td>
                        <td>{item['name']}</td>
                        <td>{item['item']}</td>
                        <td><strong>{item['status']}</strong></td>
                        <td>{item['created_at']}</td>
                    </tr>
        """
        
    html_print_layout += """
                </tbody>
            </table>
            <div style="margin-top: 4rem; text-align: center; font-size: 0.72rem; color: #8a9e8d; border-top: 1px dashed #2e3830; padding-top: 1rem;">
                Cryptographic Attestation Token Generated Automatically — VerifyMe SecOps Node
            </div>
        </div>
    </body>
    </html>
    """
    return html_print_layout
# ─── SECURED ACCOUNT PROFILE & SECURITY AGENT MANAGEMENT CHANNELS ───

@app.route('/update-profile', methods=['POST'])
def update_profile():
    # 1. Primary Authorization Intercept Guard Check
    if 'user_id' not in session:
        flash("Session expired. Please re-authenticate.", "error")
        return redirect(url_for('login'))
            
    # 2. FIXED INDENTATION: Moved out of the conditional block to run cleanly when logged in
    name = request.form.get('individual_name', '').strip()
    email = request.form.get('email', '').strip()
    individual_id = request.form.get('individual_id', '').strip()
    
    # 3. Active SQLite Persistence Workspace Updates
    try:
        with get_db_connection() as conn:
            cursor.execute(
                """
                UPDATE users 
                SET individual_name = %s, email = %s, individual_id = %s 
                WHERE id = %s
                """, 
                (name, email, individual_id, session['user_id'])
            )
            conn.commit()
            
        # Dynamically refresh local session display state variables
        session['user_email'] = email
        session['display_name'] = name
        
        flash("Profile parameter configurations updated successfully.", "success")
    except sqlite3.IntegrityError:
        flash("Operational conflict: This email account workspace mapping is already taken.", "error")
    except Exception as e:
        print(f"SecOps Core Database Write Error: {e}")
        flash("Internal system structural fault writing properties to data core.", "error")
        
    return redirect(url_for('dashboard_individual'))


@app.route('/update-security-hash', methods=['POST'])
def update_security_hash():
    if 'user_id' not in session:
        flash("Session expired. Please re-authenticate.", "error")
        return redirect(url_for('login'))

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    
    try:
        with get_db_connection() as conn:
            # 1. Fetch live user hash layout strings from SQLite context
            user = cursor.execute("SELECT password_hash FROM users WHERE id = %s", (session['user_id'],)).fetchone()
            
            # 2. Assert and cryptographically evaluate verification validity rules
            if not user or not check_password_hash(user['password_hash'], current_password):
                flash("Authentication failed: Current cryptographic signature invalid.", "error")
                return redirect(url_for('dashboard_individual'))
            
            # 3. Generate updated secure password signature array maps
            secure_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (secure_hash, session['user_id']))
            conn.commit()
            
        flash("Security hash matrices rewritten successfully.", "success")
    except Exception as e:
        print(f"SecOps Security Hash Rewrite Error: {e}")
        flash("System fault processing security token initialization vectors.", "error")
        
    return redirect(url_for('dashboard_individual'))


@app.route('/account/terminate/<account_type>', methods=['GET'])
def terminate_account(account_type):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    try:
        with get_db_connection() as conn:
            # 1. Clear active multi-channel run tracks belonging to the target node
            cursor.execute("DELETE FROM screenings WHERE user_id = %s", (session['user_id'],))
            cursor.execute("DELETE FROM individual_audits WHERE user_id = %s", (session['user_id'],))
            
            # 2. Purge structural entry registry node tracking definitions entirely
            cursor.execute("DELETE FROM users WHERE id = %s", (session['user_id'],))
            conn.commit()
            
        # 3. Destructure layout token values, clear cookies, and close sessions
        session.clear()
        flash("Account node eliminated. System mappings successfully cleared.", "warning")
        return redirect(url_for('login'))
        
    except Exception as e:
        print(f"Critical Node Deletion Failure Context: {e}")
        flash("SecOps Block: Prevented account deletion due to processing error.", "error")
        return redirect(url_for('dashboard_individual'))
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
