import os
import sqlite3
import csv
import io
import urllib.parse
import hashlib
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
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')
    
    # PayFast API Binding Configurations
    PAYFAST_MERCHANT_ID = os.environ.get('PAYFAST_MERCHANT_ID', '10050117')
    PAYFAST_MERCHANT_KEY = os.environ.get('PAYFAST_MERCHANT_KEY', 'muy2vlzbld3vi')
    PAYFAST_PASSPHRASE = os.environ.get('PAYFAST_PASSPHRASE')
    PAYFAST_POST_URL = os.environ.get('PAYFAST_POST_URL', 'https://sandbox.payfast.co.za/eng/process')

app = Flask(__name__)
app.config.from_object(Config)

DATABASE = 'verifyme.db'

# --- FILE CAPTURE CONFIGURATIONS ---
UPLOAD_FOLDER = os.path.join('static', 'uploads', 'receipts')
DOCS_FOLDER = os.path.join('static', 'uploads', 'credentials')
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOCS_FOLDER'] = DOCS_FOLDER

# Ensure target server storage paths exist safely
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOCS_FOLDER, exist_ok=True)

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

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  
    return conn

def init_db():
    """Initializes the verification data vault structures inside SQLite."""
    with get_db_connection() as conn:
        # 1. Main Accounts Ledger
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                applicant_type TEXT NOT NULL,       -- 'individual', 'company', or 'admin'
                individual_name TEXT,              
                individual_id TEXT,                
                company_name TEXT,                  
                company_contact TEXT,              
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 2. Corporate Screenings Pipeline Table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS screenings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,            
                candidate_name TEXT NOT NULL,
                candidate_email TEXT NOT NULL,       
                screening_type TEXT NOT NULL,        
                status TEXT DEFAULT 'Awaiting Payment', 
                payment_method TEXT DEFAULT 'manual_eft',                 
                payment_status TEXT DEFAULT 'Pending',-- 'Pending', 'Completed', 'Failed'
                payment_ref TEXT,                    
                pop_file_path TEXT,                  
                id_file_path TEXT,                   
                qualification_file_path TEXT,        
                rejection_reason TEXT,               
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # 3. Individual Self-Verification Audit Ledger
        conn.execute('''
            CREATE TABLE IF NOT EXISTS individual_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,            
                verification_type TEXT NOT NULL,     
                status TEXT DEFAULT 'Awaiting Payment', 
                payment_method TEXT DEFAULT 'manual_eft',
                payment_status TEXT DEFAULT 'Pending',
                payment_ref TEXT,                    
                pop_file_path TEXT,                  
                id_file_path TEXT,                   
                qualification_file_path TEXT,        
                rejection_reason TEXT,               
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()

        # Seed initial system administrator safely if slot is unoccupied
        try:
            admin_check = conn.execute("SELECT 1 FROM users WHERE applicant_type = 'admin'").fetchone()
            if not admin_check:
                hashed_admin_pass = generate_password_hash("adminsecret", method='pbkdf2:sha256')
                conn.execute('''
                    INSERT INTO users (email, password_hash, applicant_type, individual_name)
                    VALUES (?, ?, ?, ?)
                ''', ('admin@insphiredops.co.za', adminsecret, 'admin', 'SecOps Specialist'))
                conn.commit()
        except sqlite3.Error:
            pass

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


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        applicant_type = request.form.get('applicant_type') 

        individual_name = request.form.get('individual_name')
        individual_id = request.form.get('individual_id')
        company_name = request.form.get('company_name')
        company_contact = request.form.get('company_contact')

        if applicant_type == 'individual':
            company_name, company_contact = None, None
            if not individual_name or not individual_id:
                flash('Please complete your Full Legal Name and National ID fields.', 'error')
                return redirect(url_for('register'))
        else:
            individual_name, individual_id = None, None
            if not company_name or not company_contact:
                flash('Please complete your Registered Entity and Representative fields.', 'error')
                return redirect(url_for('register'))

        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

        with get_db_connection() as conn:
            try:
                conn.execute('''
                    INSERT INTO users (
                        email, password_hash, applicant_type, individual_name, individual_id, company_name, company_contact
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (email, password_hash, applicant_type, individual_name, individual_id, company_name, company_contact))
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
            
            if user['applicant_type'] == 'company':
                session['display_name'] = user['company_name']
                return redirect(url_for('dashboard_corporate'))
            elif user['applicant_type'] == 'admin':
                session['display_name'] = user['individual_name']
                return redirect(url_for('admin_dashboard'))
            else:
                session['display_name'] = user['individual_name']
                return redirect(url_for('dashboard_individual'))
        
        flash('Invalid credentials validation parameters provided.', 'error')
        return redirect(url_for('login'))

    return render_template('auth/login.html')


# ─── THE ADMINISTRATIVE MASTER WORKSPACE VAULT ───────────

@app.route('/admin/workspace')
@role_required(['admin'])
def admin_dashboard():
    conn = get_db_connection()
    
    total_users = conn.execute("SELECT COUNT(*) FROM users WHERE applicant_type != 'admin'").fetchone()[0]
    total_corp = conn.execute("SELECT COUNT(*) FROM screenings").fetchone()[0]
    total_indiv = conn.execute("SELECT COUNT(*) FROM individual_audits").fetchone()[0]
    
    metrics = {
        "total_users": total_users,
        "total_corp": total_corp,
        "total_indiv": total_indiv,
        "gross_revenue": "Cross-Channel Verification Active"
    }

    pending_eft_count = conn.execute("SELECT COUNT(DISTINCT payment_ref) FROM screenings WHERE payment_method = 'manual_eft' AND payment_status = 'Pending'").fetchone()[0]
    pending_eft_count += conn.execute("SELECT COUNT(*) FROM individual_audits WHERE payment_method = 'manual_eft' AND payment_status = 'Pending'").fetchone()[0]
    
    ready_review_count = conn.execute("SELECT COUNT(*) FROM screenings WHERE status = 'Ready for Review'").fetchone()[0]
    ready_review_count += conn.execute("SELECT COUNT(*) FROM individual_audits WHERE status = 'Ready for Review'").fetchone()[0]
    
    quick_alerts = {
        "pending_efts": pending_eft_count,
        "ready_reviews": ready_review_count
    }

    companies = conn.execute("SELECT DISTINCT company_name FROM users WHERE company_name IS NOT NULL AND company_name != ''").fetchall()
    selected_company = request.args.get('company_filter', '')
    
    query_corp = "SELECT s.*, u.company_name FROM screenings s JOIN users u ON s.user_id = u.id"
    if selected_company:
        corporate_candidates = conn.execute(query_corp + " WHERE u.company_name = ? ORDER BY s.created_at DESC", (selected_company,)).fetchall()
    else:
        corporate_candidates = conn.execute(query_corp + " ORDER BY s.created_at DESC").fetchall()

    individual_requests = conn.execute("""
        SELECT a.*, u.email FROM individual_audits a JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC
    """).fetchall()

    payments_queue = conn.execute('''
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

    users_ledger = conn.execute("SELECT id, email, company_name, individual_name, applicant_type FROM users WHERE applicant_type != 'admin'").fetchall()
    conn.close()
    
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
            conn.execute("UPDATE screenings SET status = ? WHERE id = ?", (new_status, candidate_id))
        else:
            conn.execute("UPDATE individual_audits SET status = ? WHERE id = ?", (new_status, candidate_id))
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
            conn.execute("UPDATE screenings SET status = ?, rejection_reason = ? WHERE id = ?", (status_label, reason, record_id))
        else:
            conn.execute("UPDATE individual_audits SET status = ?, rejection_reason = ? WHERE id = ?", (status_label, reason, record_id))
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
        conn.execute("UPDATE screenings SET payment_status = ?, status = ? WHERE payment_ref = ?", (new_pay_status, new_candidate_status, pay_ref))
        conn.execute("UPDATE individual_audits SET payment_status = ?, status = ? WHERE payment_ref = ?", (new_pay_status, 'Ready for Review' if action == 'Confirm' else 'Awaiting Payment', pay_ref))
        conn.commit()
    
    flash(f"Financial Ledger Clearance executed: Reference {pay_ref} is now [{new_pay_status}].", "success")
    return redirect(url_for('admin_dashboard', tab='payments'))


@app.route('/admin/purge-user/<int:user_id>', methods=['POST'])
@role_required(['admin'])
def purge_user(user_id):
    with get_db_connection() as conn:
        conn.execute("DELETE FROM screenings WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM individual_audits WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
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
        candidates = conn.execute('''
            SELECT id, candidate_name AS name, candidate_email AS email, screening_type AS type, status, payment_status, DATE(created_at) AS date 
            FROM screenings WHERE user_id = ? ORDER BY created_at DESC
        ''', (session['user_id'],)).fetchall()

    return render_template('dashboard_corporate.html', candidates=candidates, hide_navbar=True, hide_footer=True)


@app.route('/initiate-screening', methods=['POST'])
def initiate_screening():
    if 'user_id' not in session or session.get('applicant_type') != 'company':
        return redirect(url_for('login'))

    screening_type = request.form.get('screening_type')
    payment_ref = "VFY-TX-" + str(os.urandom(3).hex().upper())
    
    if 'candidate_csv' not in request.files:
        flash('Candidate dataset directory file target missing.', 'error')
        return redirect(url_for('dashboard_corporate'))

    csv_file = request.files['candidate_csv']
    if csv_file.filename == '':
        flash('Invalid verification array selection.', 'error')
        return redirect(url_for('dashboard_corporate'))

    if 'pop_receipt' not in request.files:
        flash('Proof of payment document required for ledger checkout routing.', 'error')
        return redirect(url_for('dashboard_corporate'))
    
    pop_file = request.files['pop_receipt']
    pop_saved_path = None
    if pop_file.filename != '' and allowed_file(pop_file.filename):
        base_name = secure_filename(pop_file.filename)
        unique_filename = f"{payment_ref}_{base_name}"
        pop_saved_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        pop_file.save(pop_saved_path)

    try:
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
            flash('No functional candidates verified inside data stream.', 'error')
            return redirect(url_for('dashboard_corporate'))

        with get_db_connection() as conn:
            for c_name, c_email in staged_rows:
                conn.execute('''
                    INSERT INTO screenings (
                        user_id, candidate_name, candidate_email, screening_type, status, payment_method, payment_status, payment_ref, pop_file_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (session['user_id'], c_name, c_email, screening_type, 'Awaiting Payment', 'manual_eft', 'Pending', payment_ref, pop_saved_path))
            conn.commit()

        flash(f'Staged {len(staged_rows)} candidate items under Reference {payment_ref}. Automated launch requires admin validation.', 'success')

    except Exception as e:
        flash(f'Bulk processing exception generated: {str(e)}', 'error')

    return redirect(url_for('dashboard_corporate'))


# --- CANDIDATE PORTAL DOCUMENT UPLOAD SYSTEM ---

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
            conn.execute('''
                UPDATE screenings SET id_file_path = ?, qualification_file_path = ?, status = 'Ready for Review', rejection_reason = NULL 
                WHERE id = ?
            ''', (id_path, qual_path, candidate_id))
            conn.commit()
            
        return "<h3>Upload Complete. Your files have been securely transmitted to our administrative operators for compliance auditing.</h3>"
        
    with get_db_connection() as conn:
        candidate = conn.execute("SELECT * FROM screenings WHERE id = ?", (candidate_id,)).fetchone()
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
        db_rows = conn.execute('''
            SELECT id, verification_type AS type, status, payment_status, rejection_reason, DATE(created_at) AS date 
            FROM individual_audits WHERE user_id = ? ORDER BY created_at DESC
        ''', (session['user_id'],)).fetchall()
        
        user_profile = conn.execute('SELECT email, individual_name, individual_id, created_at FROM users WHERE id = ?', (session['user_id'],)).fetchone()

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
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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

    record_id = request.args.get('record_id')
    custom_ref = request.args.get('custom_ref')
    custom_amt = request.args.get('custom_amt', '450.00')

    # Assemble transaction dictionary maps for signature processing
    payfast_data = {
        'merchant_id': app.config['PAYFAST_MERCHANT_ID'],
        'merchant_key': app.config['PAYFAST_MERCHANT_KEY'],
        'return_url': f"{app.config['BASE_URL']}/payment-success?ref={custom_ref}",
        'cancel_url': f"{app.config['BASE_URL']}/payment-cancelled",
        'notify_url': f"{app.config['BASE_URL']}/payfast-webhook",
        'name_first': session.get('display_name', 'Verified Applicant'),
        'email_address': session.get('user_email', 'noreply@verifyme.co.za'),
        'm_payment_id': f"IND-{record_id}",
        'amount': f"{float(custom_amt):.2f}",
        'item_name': f"VerifyMe Audit Ref {custom_ref}"
    }

    # Generate cryptographic security signature string
    payload_string = ""
    for key, val in payfast_data.items():
        if val:
            payload_string += f"{key}={urllib.parse.quote_plus(str(val).strip())}&"
    payload_string = payload_string[:-1]

    if app.config['PAYFAST_PASSPHRASE']:
        payload_string += f"&passphrase={urllib.parse.quote_plus(app.config['PAYFAST_PASSPHRASE'].strip())}"

    security_signature = hashlib.md5(payload_string.encode('utf-8')).hexdigest()
    payfast_data['signature'] = security_signature

    # Generate a secure auto-submitting form page to redirect the user to the sandbox gateway smoothly
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
    ref = request.args.get('ref')
    with get_db_connection() as conn:
        conn.execute("UPDATE individual_audits SET payment_status = 'Completed', status = 'Ready for Review' WHERE payment_ref = ?", (ref,))
        conn.commit()
    flash("Payment authorized successfully! Your audit verification run is now live.", "success")
    return redirect(url_for('dashboard_individual'))


@app.route('/payment-cancelled')
def payment_cancelled():
    flash("Transaction cancelled by applicant. Gateway connection dropped.", "warning")
    return redirect(url_for('dashboard_individual'))


@app.route('/payfast-webhook', methods=['POST'])
def payfast_webhook():
    # Asynchronous background instant payment notification loop tracking
    m_payment_id = request.form.get('m_payment_id')
    payment_status = request.form.get('payment_status')

    if payment_status == 'COMPLETE' and m_payment_id:
        try:
            record_id = m_payment_id.split('-')[1]
            with get_db_connection() as conn:
                conn.execute("UPDATE individual_audits SET payment_status = 'Completed', status = 'Ready for Review' WHERE id = ?", (record_id,))
                conn.commit()
        except Exception:
            pass
    return "OK", 200


@app.route('/logout')
def logout():
    session.clear()
    flash('Security session decoupled safely. Workspace locked.', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)