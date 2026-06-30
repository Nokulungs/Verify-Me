import os
import secrets
from datetime import datetime, timedelta
import sqlite3
import csv
import io
import urllib.parse
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import uuid
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from flask_mail import Mail, Message  # Single, clean import
from io import StringIO
from flask import Response
import boto3
from botocore.exceptions import NoCredentialsError

# Initialize Environmental Context
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
    region_name=os.environ.get('AWS_REGION', 'af-south-1')
)

BUCKET_NAME = os.environ.get('AWS_STORAGE_BUCKET_NAME')

def upload_file_to_s3(file, custom_filename):
    """
    Streams file objects directly up to AWS S3 bucket architecture.
    Returns the public access URL of the file if successful.
    """
    try:
        s3_client.upload_fileobj(
            file,
            BUCKET_NAME,
            custom_filename,
            ExtraArgs={
                "ContentType": file.content_type  # Ensures PDFs view in browser instead of downloading directly
            }
        )
        # Generate the permanent file asset URL structure
        file_url = f"https://{BUCKET_NAME}.s3.{os.environ.get('AWS_REGION', 'af-south-1')}.amazonaws.com/{custom_filename}"
        return file_url
        
    except NoCredentialsError:
        print("CRITICAL S3 ERROR: AWS credentials mapping missing or invalid.")
        return None
    except Exception as e:
        print(f"CRITICAL S3 ERROR: {e}")
        return None
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

    # ✉️ All your Mail Configurations belong right here inside the class!
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'nokulungabembe@gmail.com'
    MAIL_PASSWORD = 'mxio exxl lngw bbfi' 
    MAIL_DEFAULT_SENDER = ('VerifyMe Security', 'nokulungabembe@gmail.com')

# Define the Flask application exactly ONCE
app = Flask(__name__)

# 1. Load the unified configurations into the app environment first
app.config.from_object(Config)

# 2. Finally, initialize Mail now that the settings are fully baked into the app
mail = Mail(app)


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# --- FILE CAPTURE CONFIGURATIONS ---
UPLOAD_FOLDER = os.path.join('static', 'uploads', 'receipts')
DOCS_FOLDER = os.path.join('static', 'uploads', 'credentials')
UPLOAD_REGISTRY_DIR = os.path.join(BASE_DIR,'s' 'uploads', 'registries')
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
    if DATABASE_URL:
        conn = psycopg2.connect(DATABASE_URL)
    else:
        conn = psycopg2.connect(
            host="localhost",
            database="verifyme",
            user="postgres",
            password="yourpassword",
            port="5432"
        )
    return conn

def init_db():
    """Initializes verification schemas and default market rates inside PostgreSQL."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
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
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''');
    
    # Updated screenings table configuration with dynamic pricing lock-ins
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS screenings (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,            
            candidate_name TEXT NOT NULL,
            candidate_email TEXT NOT NULL,       
            screening_type TEXT NOT NULL,        
            institution_variant TEXT,            
            charged_amount DECIMAL(10, 2) DEFAULT 0.00, 
            status TEXT DEFAULT 'Awaiting Payment', 
            payment_method TEXT DEFAULT 'manual_eft',                 
            payment_status TEXT DEFAULT 'Pending',
            payment_ref TEXT,                    
            pop_file_path TEXT, 
            id_number TEXT,                 
            id_file_path TEXT,   
            license_number TEXT,
            license_file_path TEXT,                
            qualification_file_path TEXT,  
            social_handle TEXT,
            popia_consent_granted_at TIMESTAMP,
            upload_token TEXT,
            rejection_reason TEXT,               
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''');

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
    ''');

    # 🆕 NEW: Dynamic Administrative Control Price Matrix Setup
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pricing_settings (
            id SERIAL PRIMARY KEY,
            key_name VARCHAR(100) UNIQUE NOT NULL,
            display_name VARCHAR(100) NOT NULL,
            price_zar DECIMAL(10, 2) NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''');

    # 🆕 NEW: Password Resets Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''');
    conn.commit()

    # Pre-seed pricing matrix table values if empty
    try:
        cursor.execute("SELECT COUNT(*) FROM pricing_settings")
        if cursor.fetchone()[0] == 0:
            default_matrix = [
                ('Identity Verification', 'Identity Verification & Validation', 30.00),
                ('Criminal Check', 'Criminal Record & Background Check', 240.00),
                ('SAQA Foreign Evaluation', 'SAQA Certificate Evaluation', 360.00),
                ('Credit Check', 'Credit and financial checks', 185.00),
                ('Licence Verification', 'Licence Verification', 150.00),
                ('Global Compliance', 'Global compliance Screening', 450.00),
                ('Social Media Footprint', 'Social Media Footprint analysis', 220.00),
                ('Matric (Pre-1992)', 'Matric (Pre-1992)', 280.00),
                ('Matric (Post-1992)', 'Matric (Post-1992)', 190.00),
                ('University of Pretoria (PTA)', 'University of Pretoria (PTA)', 228.00),
                ('University of Johannesburg (JHB)', 'University of Johannesburg (JHB)', 336.00),
                ('University of the Witwatersrand (WITS)', 'University of the Witwatersrand (WITS)', 336.00),
                ('All N Certificates', 'All N Certificates', 200.00),
                ('Other Tertiary Institutions', 'Other Tertiary Institutions', 240.00)
            ]
            cursor.executemany('''
                INSERT INTO pricing_settings (key_name, display_name, price_zar)
                VALUES (%s, %s, %s)
            ''', default_matrix)
            conn.commit()
            print("⚙️ Seed Optimization: Populated default ZAR values into the tracking system.")
    except Exception as matrix_err:
        print(f"Pricing matrix diagnostic issue: {matrix_err}")

    # Seed Admin Account
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
        conn.close()

# Initialize tables on start
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
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        applicant_type = (request.form.get('applicant_type') or '').strip()

        individual_name = (request.form.get('individual_name') or '').strip()
        individual_id = (request.form.get('individual_id') or '').strip()
        company_name = (request.form.get('company_name') or '').strip()
        company_contact = (request.form.get('company_contact') or '').strip()

        if not email or not applicant_type or not password:
            flash('Infrastructure authentication failure: Core fields cannot be left blank.', 'error')
            return render_template('auth/register.html')

        is_valid, password_error_msg = is_strong_password(password)
        if not is_valid:
            flash(password_error_msg, 'error')
            return render_template('auth/register.html')

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

        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (
                        email, password_hash, applicant_type, individual_name, individual_id, company_name, company_contact
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ''', (email, password_hash, applicant_type, individual_name, individual_id, company_name, company_contact))
                conn.commit()
                cursor.close()
                
            flash('Workspace profile structured successfully! Please sign in.', 'success')
            return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            flash('This exact email workspace slot is already registered within our system network.', 'error')
            return render_template('auth/register.html')

    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''

        if not email or not password:
            flash('Infrastructure authentication failure: Parameters cannot be left blank.', 'error')
            return render_template('auth/login.html')

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
                user = cursor.fetchone()
                cursor.close()
        except Exception as e:
            print(f"Login Database Connectivity Error: {e}")
            flash('A core infrastructure network data error occurred. Please try again.', 'error')
            return render_template('auth/login.html')

        is_valid_admin = (email == 'admin@insphiredops.co.za' and password == 'adminsecret')
        is_valid_hash = user and check_password_hash(user['password_hash'], password)

        if is_valid_admin or is_valid_hash:
            if is_valid_admin and user and user['password_hash'] == 'adminsecret':
                try:
                    corrected_hash = generate_password_hash("adminsecret", method='pbkdf2:sha256')
                    with get_db_connection() as repair_conn:
                        repair_cursor = repair_conn.cursor()
                        repair_cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s", (corrected_hash, email))
                        repair_conn.commit()
                        repair_cursor.close()
                    print("🔧 Security Ledger Auto-Healed: Fixed plain-text admin password hash in database.")
                except Exception as repair_err:
                    print(f"🔧 Security Ledger Auto-Heal Failed: {repair_err}")

            session.clear()
            session['user_id'] = user['id'] if user else 1
            session['user_email'] = email
            session['applicant_type'] = user['applicant_type'] if user else 'admin'
            
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
        
        flash('Invalid credentials validation parameters provided.', 'error')
        return render_template('auth/login.html')

    return render_template('auth/login.html')


@app.route('/submit-screening', methods=['POST'])
def submit_screening():
    if 'user_id' not in session or session.get('applicant_type') != 'corporate':
        flash('Unauthorized entry point.', 'danger')
        return redirect(url_for('dashboard'))

    candidate_name = request.form.get('candidate_name')
    candidate_email = request.form.get('candidate_email')
    
    # Capture multiple selections from your front-end checkboxes/multi-select
    selected_verifications = request.form.getlist('verification_types') 
    institution_variant = request.form.get('institution_variant', None)

    if not candidate_name or not candidate_email or not selected_verifications:
        flash('Missing required verification fields.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # 1. Fetch current dynamic pricing records directly from PostgreSQL
        cursor.execute("SELECT key_name, price_zar FROM pricing_settings")
        price_map = {row[0]: float(row[1]) for row in cursor.fetchall()}

        # 2. Loop through selections, match keys, and aggregate the true total cost
        total_calculated_charge = 0.00
        for verification in selected_verifications:
            # Check for structural variant pricing mappings (e.g., specific universities)
            if verification == 'Tertiary Education' and institution_variant in price_map:
                total_calculated_charge += price_map[institution_variant]
            elif verification in price_map:
                total_calculated_charge += price_map[verification]
            else:
                # Standard fallback structural item base cost
                total_calculated_charge += price_map.get('Other Tertiary Institutions', 240.00)

        # 3. File Processing Blocks
        pop_file = request.files.get('pop_file')
        id_file = request.files.get('id_file')
        qual_file = request.files.get('qualification_file')

        pop_path = save_file_safely(pop_file, 'proof_of_payments') if pop_file else None
        id_path = save_file_safely(id_file, 'identities') if id_file else None
        qual_path = save_file_safely(qual_file, 'qualifications') if qual_file else None

        # Generation token for candidate direct links if backgrounding is needed
        upload_token = generate_secure_token()

        # Join the mapped choices cleanly to represent the screening configuration bulk bundle
        screening_bundle_name = ", ".join(selected_verifications)

        # 4. Write back into the system database with frozen transactional rates locked in place
        cursor.execute('''
            INSERT INTO screenings (
                user_id, candidate_name, candidate_email, screening_type, 
                institution_variant, charged_amount, status, payment_status, 
                pop_file_path, id_file_path, qualification_file_path, upload_token
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            current_user.id, candidate_name, candidate_email, screening_bundle_name,
            institution_variant, total_calculated_charge, 'Awaiting Payment', 'Pending',
            pop_path, id_path, qual_path, upload_token
        ))
        
        conn.commit()
        flash(f'Screening order configured! Total transactional balance calculated: R{total_calculated_charge:.2f}', 'success')

    except Exception as err:
        conn.rollback()
        print(f"Error executing processing run setup: {err}")
        flash('An internal system error occurred while calculating verification parameters.', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('dashboard'))


def save_file_safely(file_storage, folder):
    """Utility helper to secure name schemas and structure file uploads."""
    import os
    from werkzeug.utils import secure_filename
    
    UPLOAD_FOLDER = os.path.join('static', 'uploads', folder)
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        
    filename = secure_filename(file_storage.filename)
    unique_name = f"{generate_secure_token()[:8]}_{filename}"
    full_path = os.path.join(UPLOAD_FOLDER, unique_name)
    file_storage.save(full_path)
    return full_path


def generate_secure_token():
    import secrets
    return secrets.token_urlsafe(16)

# ─── THE ADMINISTRATIVE MASTER WORKSPACE VAULT ───────────
@app.route('/admin/workspace', methods=['GET', 'POST'])
@role_required(['admin'])
def admin_dashboard():
    # --------------------------------------------------------------------------
    # 🆕 ACTION BLOCK: Handle Price Metric Form Updates (POST Submissions)
    # --------------------------------------------------------------------------
    if request.method == 'POST':
        updated_prices = request.form.getlist('prices[]')
        setting_ids = request.form.getlist('ids[]')
        
        try:
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    for setting_id, price in zip(setting_ids, updated_prices):
                        clean_price = float(price) if price else 0.00
                        cursor.execute("""
                            UPDATE pricing_settings 
                            SET price_zar = %s, updated_at = NOW()
                            WHERE id = %s
                        """, (clean_price, setting_id))
                    conn.commit()
            flash('Dynamic verification pricing settings matrices updated successfully.', 'success')
        except Exception as e:
            flash(f'Failed to adjust pricing data: {str(e)}', 'error')
            
        # Forces the admin workspace view to focus cleanly back on the pricing tab panel layout
        return redirect(url_for('admin_dashboard', tab='pricing'))

    # --------------------------------------------------------------------------
    # 🔍 READ BLOCK: Fetching operational dataset parameters (GET Request)
    # --------------------------------------------------------------------------
    
    # 1. Fallback dictionary for internal revenue computations if records aren't generated yet
    SCREENING_PRICES = {
        'Identity Verification & Validation': 450.00,
        'Criminal Record & Background Check': 550.00,
        'Credit & Financial Check': 380.00,
        'Professional License Verification': 320.00,
        'Global Compliance Screening': 620.00,
        'Social Media & Digital Footprint': 280.00
    }

    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Pull live operational prices straight out of the database settings matrix
        cursor.execute("SELECT * FROM pricing_settings ORDER BY id ASC")
        pricing_entries = cursor.fetchall()
        
        # Override the hardcoded fallback map dictionary if live settings metrics are populated in DB
        if pricing_entries:
            SCREENING_PRICES = {item['display_name']: float(item['price_zar']) for item in pricing_entries}
        
        # 2. Base metrics counts
        cursor.execute("SELECT COUNT(*) FROM users WHERE applicant_type != 'admin'")
        total_users = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) FROM screenings")
        total_corp = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) FROM individual_audits")
        total_indiv = cursor.fetchone()['count']

        # 3. Dynamic Revenue Stream Extraction
        total_revenue = 0.0

        # Fetch string pricing tokens for individual audits (uses verification_type)
        cursor.execute("SELECT verification_type FROM individual_audits WHERE payment_status = 'Completed';")
        individual_rows = cursor.fetchall()
        for row in individual_rows:
            v_type = row['verification_type']
            total_revenue += SCREENING_PRICES.get(v_type, 0.0)

        # Fetch string pricing tokens for corporate screenings (uses screening_type)
        cursor.execute("SELECT screening_type FROM screenings WHERE payment_status = 'Pending Review';")
        corporate_rows = cursor.fetchall()
        for row in corporate_rows:
            s_type = row['screening_type']
            total_revenue += SCREENING_PRICES.get(s_type, 0.0)
        
        metrics = {
            "total_users": total_users,
            "total_corp": total_corp,
            "total_indiv": total_indiv,
            "gross_revenue": total_revenue  # Exposing the live computed float variable to the UI
        }

        # 4. Alerts, Filters, Queues, and Data Engine Operations
        cursor.execute("SELECT COUNT(DISTINCT payment_ref) FROM screenings WHERE payment_method = 'manual_eft' AND payment_status = 'Pending'")
        pending_eft_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) FROM individual_audits WHERE payment_method = 'manual_eft' AND payment_status = 'Pending'")
        pending_eft_count += cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) FROM screenings WHERE status = 'Ready for Review'")
        ready_review_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) FROM individual_audits WHERE status = 'Ready for Review'")
        ready_review_count += cursor.fetchone()['count']
        
        quick_alerts = {
            "pending_efts": pending_eft_count,
            "ready_reviews": ready_review_count
        }

        cursor.execute("SELECT DISTINCT company_name FROM users WHERE company_name IS NOT NULL AND company_name != ''")
        companies = cursor.fetchall()
        selected_company = request.args.get('company_filter', '')
        
        query_corp = "SELECT s.*, u.company_name FROM screenings s JOIN users u ON s.user_id = u.id"
        if selected_company:
            cursor.execute(query_corp + " WHERE u.company_name = %s ORDER BY s.created_at DESC", (selected_company,))
        else:
            cursor.execute(query_corp + " ORDER BY s.created_at DESC")
        corporate_candidates = cursor.fetchall()

        cursor.execute("SELECT a.*, u.email FROM individual_audits a JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC")
        individual_requests = cursor.fetchall()

        cursor.execute('''
            SELECT payment_ref, u.company_name AS party_name, screening_type AS service, payment_method, payment_status, pop_file_path,
                   COUNT(s.id) AS units, 'company' AS type
            FROM screenings s JOIN users u ON s.user_id = u.id
            WHERE payment_ref IS NOT NULL AND payment_ref != ''
            GROUP BY payment_ref, u.company_name, screening_type, payment_method, payment_status, pop_file_path
            UNION ALL
            SELECT payment_ref, u.individual_name AS party_name, verification_type AS service, payment_method, payment_status, pop_file_path,
                   1 AS units, 'individual' AS type
            FROM individual_audits a JOIN users u ON a.user_id = u.id
            WHERE payment_ref IS NOT NULL AND payment_ref != ''
            GROUP BY payment_ref, u.individual_name, verification_type, payment_method, payment_status, pop_file_path
            ORDER BY payment_status DESC
        ''')
        payments_queue = cursor.fetchall()

        cursor.execute("SELECT id, email, company_name, individual_name, applicant_type FROM users WHERE applicant_type != 'admin'")
        users_ledger = cursor.fetchall()
        cursor.close()
    
    # 5. Single unified return context explicitly offering pricing_entries array matrices
    return render_template(
        'admin_dashboard.html',
        total_revenue=total_revenue,
        metrics=metrics,
        quick_alerts=quick_alerts,
        companies=companies,
        selected_company=selected_company,
        corporate_candidates=corporate_candidates,
        individual_requests=individual_requests,
        payments_queue=payments_queue,
        users_ledger=users_ledger,
        pricing_entries=pricing_entries  # 🚀 Live database settings are now fully piped to the HTML engine
    )

@app.route('/admin/update-candidate-status', methods=['POST'])
@role_required(['admin'])
def update_candidate_status():
    candidate_id = request.form.get('id')
    new_status = request.form.get('status')
    track = request.form.get('track', 'corporate') 
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if track == 'corporate':
            cursor.execute("UPDATE screenings SET status = %s WHERE id = %s", (new_status, candidate_id))
        else:
            cursor.execute("UPDATE individual_audits SET status = %s WHERE id = %s", (new_status, candidate_id))
        conn.commit()
        cursor.close()
    
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
        cursor = conn.cursor()
        if track == 'corporate':
            cursor.execute("UPDATE screenings SET status = %s, rejection_reason = %s WHERE id = %s", (status_label, reason, record_id))
        else:
            cursor.execute("UPDATE individual_audits SET status = %s, rejection_reason = %s WHERE id = %s", (status_label, reason, record_id))
        conn.commit()
        cursor.close()
    
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
        cursor = conn.cursor()
        cursor.execute("UPDATE screenings SET payment_status = %s, status = %s WHERE payment_ref = %s", (new_pay_status, new_candidate_status, pay_ref))
        cursor.execute("UPDATE individual_audits SET payment_status = %s, status = %s WHERE payment_ref = %s", (new_pay_status, 'Ready for Review' if action == 'Confirm' else 'Awaiting Payment', pay_ref))
        conn.commit()
        cursor.close()
    
    flash(f"Financial Ledger Clearance executed: Reference {pay_ref} is now [{new_pay_status}].", "success")
    return redirect(url_for('admin_dashboard', tab='payments'))

@app.route('/admin/purge-user/<int:user_id>', methods=['POST'])
@role_required(['admin'])
def purge_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM screenings WHERE user_id = %s", (user_id,))
        cursor.execute("DELETE FROM individual_audits WHERE user_id = %s", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        cursor.close()
    
    flash("Master profile purged successfully.", "success")
    return redirect(url_for('admin_dashboard', tab='users'))

@app.route('/admin/view-document/<path:filename>')
@role_required(['admin'])
def admin_view_document(filename):
    """Securely streams compliance documents or handles straight redirects to cloud asset storage grids."""
    from flask import redirect
    
    # If the database string is already an absolute HTTP web address, hand it straight off to the cloud browser context
    if filename.startswith('http://') or filename.startswith('https://'):
        return redirect(filename)
        
    # 🔄 Fallback layer: If it's an old legacy record from your computer's local drive storage framework
    from flask import send_from_directory, abort
    import os
    
    clean_filename = os.path.basename(filename)
    absolute_app_root = os.path.abspath(os.path.dirname(__file__))
    target_storage_dir = os.path.join(absolute_app_root, 'static', 'uploads', 'credentials')
    full_file_path = os.path.join(target_storage_dir, clean_filename)

    if os.path.exists(full_file_path):
        return send_from_directory(target_storage_dir, clean_filename)
        
    abort(404)

    # Serve securely using the absolute root directory path paired with the variable sub-path filename
    return send_from_directory(absolute_root_path, filename)
# --- SECURED CORPORATE WORKSPACE & DATA PROCESSING ---
@app.route('/dashboard/corporate')
def dashboard_corporate():
    if 'user_id' not in session or session.get('applicant_type') != 'company':
        flash('Access denied. Corporate clearance required.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']

    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # 📞 NEW: Fetch user/corporate metadata details for the profile view component
        cursor.execute('''
            SELECT id, email, phone, company_name, company_contact
            FROM users 
            WHERE id = %s
        ''', (user_id,))
        user_data = cursor.fetchone()
        
        # Fetch candidate screening records
        cursor.execute('''
            SELECT id, candidate_name AS name, candidate_email AS email, 
                   screening_type AS type, status, payment_status, payment_ref,
                   DATE(created_at) AS date 
            FROM screenings 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        ''', (user_id,))
        candidates = cursor.fetchall()
        
        # Count candidates who need to upload documents
        cursor.execute('''
            SELECT COUNT(*) FROM screenings 
            WHERE user_id = %s AND status = 'Awaiting Document Upload'
        ''', (user_id,))
        attention_required_count = cursor.fetchone()['count']
        
        # Count entries awaiting gateway settlement
        cursor.execute('''
            SELECT COUNT(*) FROM screenings 
            WHERE user_id = %s AND (payment_status IN ('Pending Checkout', 'Pending', 'Cancelled') OR status = 'Awaiting Payment')
        ''', (user_id,))
        unpaid_count = cursor.fetchone()['count']

        pricing_entries = [] # 🆕 Safeguards against NameError exceptions if something goes wrong

        try:
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute("SELECT * FROM pricing_settings ORDER BY id ASC")
                    pricing_entries = cursor.fetchall()
        except Exception as e:
             print(f"Failed to fetch dynamic corporate pricing settings matrix: {e}")
        
        cursor.close()

    return render_template(
        'dashboard_corporate.html', 
        user_data=user_data,  # 💥 NOW INJECTED INTO THE CONTEXT MATRICES 💥
        candidates=candidates, 
        attention_required_count=attention_required_count,
        unpaid_count=unpaid_count,
        hide_navbar=True, 
        hide_footer=True,
        pricing_entries=pricing_entries
    )

# 🌟 Create a clean mirror fallback so url_for('dashboard_corporate') never fails
@app.route('/dashboard-corporate')
def dashboard_corporate_fallback():
    return redirect(url_for('dashboard_corporate'))

@app.route('/initiate-screening', methods=['POST'])
def initiate_screening():
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

    csv_path = None
    if csv_file and csv_file.filename != '':
        filename = secure_filename(csv_file.filename)
        csv_path = os.path.join(app.config['UPLOAD_REGISTRY_DIR'], f"{payment_ref}_{filename}")
        csv_file.save(csv_path)

    try:
        csv_file.seek(0)
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
            c_name = row[0].strip()
            c_email = row[1].strip()
            # Approach B variant reading mapping configuration
            c_variant = row[2].strip() if len(row) > 2 else ''
            
            if c_name and c_email: 
                staged_rows.append((c_name, c_email, c_variant))

        if not staged_rows:
            flash('No functional candidates verified inside data stream registry.', 'error')
            return redirect(url_for('dashboard_corporate'))

        if len(staged_rows) != candidate_count:
            flash(f"Registry Validation Mismatch: You declared a target metric of {candidate_count} candidate(s), but your uploaded CSV file contains {len(staged_rows)} rows. Please ensure they match exactly.", 'error')
            return redirect(url_for('dashboard_corporate'))

    except Exception as e:
        flash(f'Bulk metrics processing exception generated: {str(e)}', 'error')
        return redirect(url_for('dashboard_corporate'))

    # Prepare file storage paths if handling Manual EFT
    pop_saved_path = None
    if payment_method == 'manual_eft':
        if 'pop_receipt' not in request.files:
            flash('Proof of payment document required for manual ledger checkout tracking.', 'error')
            return redirect(url_for('dashboard_corporate'))

        pop_file = request.files['pop_receipt']
        if pop_file and pop_file.filename != '' and allowed_file(pop_file.filename):
            base_name = secure_filename(pop_file.filename)
            unique_filename = f"{payment_ref}_{base_name}"
            pop_saved_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            pop_file.save(pop_saved_path)

    # Process pricing lookups and insert operations
    duplicates_skipped = 0
    total_batch_bill_amount = 0.0
    
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Pull live rate parameters out of the DB pricing matrix
        cursor.execute("SELECT key_name, price_zar FROM pricing_settings")
        live_prices = {row['key_name']: float(row['price_zar']) for row in cursor.fetchall()}
        
        for c_name, c_email, c_variant in staged_rows:
            # Rule A: Cross-check distinct compound unique configurations
            cursor.execute('''
                SELECT 1 FROM screenings 
                WHERE user_id = %s AND candidate_email = %s AND screening_type = %s
                LIMIT 1
            ''', (session['user_id'], c_email, screening_type))
            if cursor.fetchone():
                duplicates_skipped += 1
                continue

            # Calculate individual row total utilizing Approach B's delimiter splitting architecture
            row_calculated_charge = 0.0
            
            if screening_type == 'Qualification Verification':
                if ';' in c_variant:
                    # Clean split cell by semicolon for multiple items
                    individual_variants = [v.strip() for v in c_variant.split(';') if v.strip()]
                    for variant in individual_variants:
                        row_calculated_charge += live_prices.get(variant, live_prices.get('Other Tertiary Institutions', 240.00))
                elif c_variant:
                    row_calculated_charge += live_prices.get(c_variant, live_prices.get('Other Tertiary Institutions', 240.00))
                else:
                    row_calculated_charge += live_prices.get('Other Tertiary Institutions', 240.00)
            else:
                # Use flat mapping keys for standalone services (Identity, Criminal, etc.)
                row_calculated_charge += live_prices.get(screening_type, live_prices.get('Identity Verification', 30.00))

            total_batch_bill_amount += row_calculated_charge
            upload_token = secrets.token_urlsafe(32)

            # Insert screening rows with specific charged_amount footprint logged safely
            cursor.execute('''
                INSERT INTO screenings (
                    user_id, candidate_name, candidate_email, screening_type, institution_variant, 
                    charged_amount, status, payment_method, payment_status, payment_ref, pop_file_path, upload_token
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                session['user_id'], c_name, c_email, screening_type, c_variant or None,
                row_calculated_charge, 'Pending Input', payment_method, 
                'Pending Review' if payment_method == 'manual_eft' else 'Pending Checkout',
                payment_ref, pop_saved_path, upload_token
            ))
            
            # Dispatch invite links securely
            invite_link = f"{Config.BASE_URL}/upload-documents/{upload_token}"
            msg = Message(
                subject=f"Action Required: VerifyMe Screening Link for {c_name}",
                recipients=[c_email]
            )
            msg.html = f"""
            <!DOCTYPE html>
            <html>
            <body style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #121413; color: #f5f5f5; padding: 20px;">
                <div style="background-color: #1a1d1b; max-width: 550px; margin: 0 auto; padding: 30px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05);">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #4eb637; margin-bottom: 20px; font-family: monospace;">// VERIFYME CONTAINER</div>
                    <h2 style="color: #ffffff;">Hello {c_name},</h2>
                    <p style="color: #a3a3a3;">An automated enterprise background screening request (<strong>{screening_type}</strong>) has been deployed for you by {session.get('display_name', 'an Enterprise Client')}.</p>
                    <p style="color: #a3a3a3;">To advance this identity verification process, please click the secure button below to access your documentation upload workspace:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{invite_link}" style="background-color: #4eb637; color: #000000; text-decoration: none; padding: 12px 24px; font-weight: 600; border-radius: 6px; display: inline-block;">Open Verification Portal</a>
                    </div>
                </body>
                </html>
                """
            with app.app_context():
                mail.send(msg)
            
        conn.commit()
        cursor.close()

    if duplicates_skipped == len(staged_rows):
        flash("Batch processing skipped: All candidates in this file are already registered for this screening type.", "warning")
        return redirect(url_for('dashboard_corporate'))

    if payment_method == 'manual_eft':
        flash(f"Staged pipeline records under Reference {payment_ref}. Loaded {len(staged_rows) - duplicates_skipped} entries. Total dynamic value calculated: ZAR {total_batch_bill_amount:.2f}", "success")
        return redirect(url_for('dashboard_corporate'))
    else:
        # Route directly into Checkout with dynamically calculated batch total matrix amount
        return redirect(url_for('payfast_checkout', record_id="BATCH", custom_ref=payment_ref, custom_amt=total_batch_bill_amount))

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
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE screenings SET id_file_path = %s, qualification_file_path = %s, status = 'Ready for Review', rejection_reason = NULL 
                WHERE id = %s
            ''', (id_path, qual_path, candidate_id))
            conn.commit()
            cursor.close()
            
        return "<h3>Upload Complete. Your files have been securely transmitted to our administrative operators for compliance auditing.</h3>"
        
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM screenings WHERE id = %s", (candidate_id,))
        candidate = cursor.fetchone()
        cursor.close()
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
        cursor = conn.cursor(cursor_factory=RealDictCursor)
    
        cursor.execute('''
            SELECT id, verification_type AS type, status, payment_status, rejection_reason, DATE(created_at) AS date 
            FROM individual_audits 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        ''', (session['user_id'],))
        db_rows = cursor.fetchall()
        
        cursor.execute('''
            SELECT email, individual_name, individual_id, created_at 
            FROM users 
            WHERE id = %s
        ''', (session['user_id'],))
        user_profile = cursor.fetchone()
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

    verification_type = request.form.get('verification_type')
    payment_method = request.form.get('payment_method', 'manual_eft')
    payment_ref = "VFY-IND-" + str(os.urandom(3).hex().upper())

    uploaded_docs = request.files.getlist('verification_documents')
    proof_of_payment = request.files.get('proof_of_payment')

    if not verification_type or not uploaded_docs or not uploaded_docs[0].filename:
        flash('Verification core documents are required to initialize an audit request.', 'error')
        return redirect(url_for('dashboard_individual'))

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

    with get_db_connection() as conn:
        cursor = conn.cursor()
        # 🛠️ FIXED FOR POSTGRES: Added "RETURNING id" clause to fetch inserted row id
        cursor.execute('''
            INSERT INTO individual_audits (
                user_id, verification_type, payment_method, payment_status, 
                payment_ref, pop_file_path, id_file_path, qualification_file_path, status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
        ''', (
            session['user_id'], verification_type, payment_method, initial_payment_status,
            payment_ref, pop_saved_path, id_path, qual_path, initial_pipeline_status
        ))
        generated_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()

    if payment_method == 'gateway':
        total_bill = calculate_individual_cost(verification_type)
        return redirect(url_for('payfast_checkout', record_id=generated_id, custom_ref=payment_ref, custom_amt=total_bill))

    flash(f'Successfully initialized your {verification_type} audit pipeline. Awaiting manual bank clearance checking.', 'success')
    return redirect(url_for('dashboard_individual'))

# --- ONLINE CHECKOUT LINKAGE PIPELINE ---
# --- ONLINE CHECKOUT LINKAGE PIPELINE ---
@app.route('/payfast-checkout')
def payfast_checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    record_id = request.args.get('record_id', 'BATCH')
    custom_ref = request.args.get('custom_ref')
    custom_amt = request.args.get('custom_amt', '450.00')

    payfast_data = {
        'merchant_id': app.config['PAYFAST_MERCHANT_ID'],
        'merchant_key': app.config['PAYFAST_MERCHANT_KEY'],
        'return_url': f"{app.config['BASE_URL']}/payment-success?ref={custom_ref}&record_id={record_id}",
        'cancel_url': f"{app.config['BASE_URL']}/payment-cancelled?ref={custom_ref}&record_id={record_id}",
        'notify_url': f"{app.config['BASE_URL']}/payfast-webhook",
        'name_first': session.get('display_name', 'Verified Applicant'),
        'email_address': session.get('user_email', 'noreply@verifyme.co.za'),
        'm_payment_id': f"{record_id}-{custom_ref}",
        'amount': f"{float(custom_amt):.2f}",
        'item_name': f"VerifyMe Audit Ref {custom_ref}",
        # 🌟 FIX: Use PayFast's official custom fields which are guaranteed to survive redirects
        'custom_str1': str(record_id),
        'custom_str2': str(custom_ref)
    }

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

@app.route('/payment-success', methods=['GET', 'POST'])
def payment_success():
    # 🌟 FIX: Extract from custom fields, query args, or combined payment string
    custom_ref = request.values.get('custom_str2') or request.values.get('ref') or request.values.get('custom_ref')
    m_payment_id = request.values.get('m_payment_id', '')

    if not custom_ref and '-' in m_payment_id:
        try:
            _, custom_ref = m_payment_id.split('-', 1)
        except ValueError:
            pass

    if custom_ref:
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                # Update corporate requests under this reference
                cursor.execute(
                    "UPDATE screenings SET payment_status = 'Completed', status = 'Awaiting Document Upload' WHERE payment_ref = %s", 
                    (custom_ref,)
                )
                # Update individual audits under this reference
                cursor.execute(
                    "UPDATE individual_audits SET payment_status = 'Completed', status = 'Ready for Review' WHERE payment_ref = %s", 
                    (custom_ref,)
                )
                conn.commit()
                cursor.close()
                print(f"✅ SecOps: Browser return success auto-update complete for reference: {custom_ref}")
                flash(f"Payment verified successfully for reference: {custom_ref}", "success")
        except Exception as e:
            print(f"Fallback update error: {e}")
    else:
        print("⚠️ Warning: payment-success reached but no reference token could be extracted.")

    if session.get('applicant_type') == 'company':
        return redirect(url_for('dashboard_corporate'))
    return redirect(url_for('dashboard_individual'))

@app.route('/payment-cancelled', methods=['GET', 'POST'])
def payment_cancelled():
    # 🌟 FIX: Check everywhere for the identifying reference token
    custom_ref = request.values.get('custom_str2') or request.values.get('ref') or request.values.get('custom_ref')
    record_id = request.values.get('custom_str1') or request.values.get('record_id', '')
    m_payment_id = request.values.get('m_payment_id', '')

    if not custom_ref and '-' in m_payment_id:
        try:
            record_id, custom_ref = m_payment_id.split('-', 1)
        except ValueError:
            pass

    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        if custom_ref:
            try:
                # 1. Purge uncompleted batch screenings for corporate accounts
                cursor.execute("""
                    DELETE FROM screenings 
                    WHERE payment_ref = %s 
                      AND (payment_status IN ('Pending Checkout', 'Pending', 'Cancelled', 'Pending Review') 
                           OR status IN ('Awaiting Payment', 'Awaiting Review'))
                """, (custom_ref,))
                
                # 2. Purge uncompleted audits for individual accounts
                cursor.execute("""
                    DELETE FROM individual_audits 
                    WHERE payment_ref = %s 
                      AND (payment_status IN ('Pending Checkout', 'Pending') 
                           OR status IN ('Awaiting Payment', 'Ready for Review'))
                """, (custom_ref,))
                
                conn.commit()
                print(f"🛑 SecOps: Cleaned up canceled ghost records for reference token {custom_ref}")
            except Exception as e:
                print(f"SecOps Node Error Context: {e}")

        elif record_id and record_id != 'BATCH':
            try:
                target_id = int(record_id)
                cursor.execute("""
                    DELETE FROM individual_audits 
                    WHERE id = %s 
                      AND (payment_status IN ('Pending Checkout', 'Pending') 
                           OR status = 'Awaiting Payment')
                """, (target_id,))
                conn.commit()
                print(f"🛑 SecOps: Cleaned up canceled single audit record for ID {target_id}")
            except (ValueError, Exception) as e:
                print(f"SecOps Single Record Deletion Error: {e}")
                pass
                
        cursor.close()

    flash("Transaction canceled by applicant. Gateway connection dropped and duplicate entries cleared.", "error")
    
    if session.get('applicant_type') == 'company':
        return redirect(url_for('dashboard_corporate'))
    return redirect(url_for('dashboard_individual'))
    
@app.route('/payfast-webhook', methods=['POST'])
def payfast_webhook():
    m_payment_id = request.form.get('m_payment_id', '')
    payment_status = request.form.get('payment_status')
    custom_str1 = request.form.get('custom_str1', '')
    custom_str2 = request.form.get('custom_str2', '')

    if payment_status == 'COMPLETE':
        try:
            # Fallback split logic if custom strings are absent
            record_id = custom_str1 if custom_str1 else m_payment_id.split('-', 1)[0]
            payment_ref = custom_str2 if custom_str2 else m_payment_id.split('-', 1)[1]
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                if record_id == 'BATCH':
                    cursor.execute("UPDATE screenings SET payment_status = 'Completed', status = 'Awaiting Document Upload' WHERE payment_ref = %s", (payment_ref,))
                else:
                    cursor.execute("UPDATE individual_audits SET payment_status = 'Completed', status = 'Ready for Review' WHERE id = %s", (int(record_id),))
                conn.commit()
                cursor.close()
        except Exception as e:
            print(f"Webhook database callback error: {e}")
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
    company_filter = request.args.get('company_filter', '')
    output = io.StringIO()
    writer = csv.writer(output)
    
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
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query, params)
        records = cursor.fetchall()
        cursor.close()
        
    for row in records:
        writer.writerow([
            f"CC-{row['id']}", row['company_name'], row['candidate_name'], row['candidate_email'],
            row['screening_type'], row['status'], row['payment_method'], row['payment_status'],
            row['payment_ref'], row['created_at']
        ])
        
    return Flask.response_class(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-disposition": f"attachment; filename=corporate_screening_report_{datetime.now().strftime('%Y%m%d')}.csv"}
    )

@app.route('/admin/export-individual/csv')
@role_required(['admin'])
def export_individual_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        'Audit Run Token', 'Applicant Account Email', 'Full Legal Name', 
        'National ID Number', 'Audit Focus Type', 'Pipeline Status State', 
        'Billing Method', 'Payment Status', 'Ledger Reference', 'Created At'
    ])
    
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT a.*, u.email, u.individual_name, u.individual_id 
            FROM individual_audits a 
            JOIN users u ON a.user_id = u.id 
            ORDER BY a.created_at DESC
        """)
        records = cursor.fetchall()
        cursor.close()
        
    for row in records:
        writer.writerow([
            f"IND-{row['id']}", row['email'], row['individual_name'] if row['individual_name'] else 'Unspecified',
            row['individual_id'] if row['individual_id'] else 'Unspecified', row['verification_type'],
            row['status'], row['payment_method'], row['payment_status'], row['payment_ref'], row['created_at']
        ])
        
    return Flask.response_class(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-disposition": f"attachment; filename=individual_audit_report_{datetime.now().strftime('%Y%m%d')}.csv"}
    )

@app.route('/admin/export-profile/pdf/<int:user_id>')
@role_required(['admin'])
def export_profile_pdf(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_profile = cursor.fetchone()
        
        if not user_profile:
            cursor.close()
            abort(404)
            
        if user_profile['applicant_type'] == 'company':
            cursor.execute("SELECT id, candidate_name AS name, screening_type AS item, status, created_at FROM screenings WHERE user_id = %s", (user_id,))
        else:
            cursor.execute("SELECT id, '-' AS name, verification_type AS item, status, created_at FROM individual_audits WHERE user_id = %s", (user_id,))
        history = cursor.fetchall()
        cursor.close()

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
                <div style="font-size: 0.85rem; color: #617c41; font-weight: 500; margin-top: 0.25rem;">VERIFYME DATA PROTECTION HUB</div>
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
            <h3 style="text-transform: uppercase; font-size: 1rem; color: #181c19; border-bottom: 1px solid #2e3830; padding-bottom: 0.5rem;">Associated Active Run Matrix</h3>
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
        </div>
    </body>
    </html>
    """
    return html_print_layout

# --- SECURED ACCOUNT PROFILE & SECURITY AGENT MANAGEMENT CHANNELS ---
@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        flash("Session expired. Please re-authenticate.", "error")
        return redirect(url_for('login'))
            
    name = request.form.get('individual_name', '').strip()
    email = request.form.get('email', '').strip()
    individual_id = request.form.get('individual_id', '').strip()
    
    try:
        with get_db_connection() as conn:
            # 🛠️ FIXED: Added cursor instantiation
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE users 
                SET individual_name = %s, email = %s, individual_id = %s 
                WHERE id = %s
                """, 
                (name, email, individual_id, session['user_id'])
            )
            conn.commit()
            cursor.close()
            
        session['user_email'] = email
        session['display_name'] = name
        flash("Profile parameter configurations updated successfully.", "success")
    except psycopg2.IntegrityError:
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
            # 🛠️ FIXED: Added cursor factory to prevent key reading lookup failures
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("SELECT password_hash FROM users WHERE id = %s", (session['user_id'],))
            user = cursor.fetchone()
            
            if not user or not check_password_hash(user['password_hash'], current_password):
                cursor.close()
                flash("Authentication failed: Current cryptographic signature invalid.", "error")
                return redirect(url_for('dashboard_individual'))
            
            secure_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (secure_hash, session['user_id']))
            conn.commit()
            cursor.close()
            
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
            # 🛠️ FIXED: Created local cursor definition context block
            cursor = conn.cursor()
            cursor.execute("DELETE FROM screenings WHERE user_id = %s", (session['user_id'],))
            cursor.execute("DELETE FROM individual_audits WHERE user_id = %s", (session['user_id'],))
            cursor.execute("DELETE FROM users WHERE id = %s", (session['user_id'],))
            conn.commit()
            cursor.close()
            
        session.clear()
        flash("Account node eliminated. System mappings successfully cleared.", "warning")
        return redirect(url_for('login'))
    except Exception as e:
        print(f"Critical Node Deletion Failure Context: {e}")
        flash("SecOps Block: Prevented account deletion due to processing error.", "error")
        return redirect(url_for('dashboard_individual'))

@app.route('/update-corporate-profile', methods=['POST'])
def update_corporate_profile():
    if 'user_id' not in session or session.get('applicant_type') != 'company':
        return jsonify({'success': False, 'message': 'Unauthorized context access.'}), 403

    # 📞 Only capture what's on the form now: the phone string node
    phone = request.form.get('phone', '').strip()

    if not phone:
        return jsonify({'success': False, 'message': 'Phone number field is required.'}), 400

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # 🔒 Target ONLY your explicit phone column row node
                cursor.execute("""
                    UPDATE users 
                    SET phone = %s 
                    WHERE id = %s
                """, (phone, session['user_id']))
                conn.commit()

        return jsonify({'success': True, 'message': 'Corporate profile updated successfully.'})
        
    except Exception as e:
        print(f"💥 Profile Save Core Error: {str(e)}")
        return jsonify({'success': False, 'message': f'Server database update failure: {str(e)}'}), 500

@app.route('/update-corporate-password', methods=['POST'])
def update_corporate_password():
    if 'user_id' not in session or session.get('applicant_type') != 'company':
        return jsonify({'success': False, 'message': 'Unauthorized access.'}), 403

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'New password confirmation sets do not match.'}), 400

    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT password_hash FROM users WHERE id = %s", (session['user_id'],))
                user_record = cursor.fetchone()

                if not user_record or not check_password_hash(user_record['password_hash'], current_password):
                    return jsonify({'success': False, 'message': 'Current security password hash verification failed.'}), 422

                new_hash = generate_password_hash(new_password)
                cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, session['user_id']))
                conn.commit()
        return jsonify({'success': True, 'message': 'Workspace security hashes updated.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Password rotation failure: {str(e)}'}), 500


@app.route('/delete-corporate-account', methods=['POST'])
def delete_corporate_account():
    if 'user_id' not in session or session.get('applicant_type') != 'company':
        return jsonify({'success': False, 'message': 'Unauthorized context.'}), 403

    user_id = session['user_id']
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Clean out all dependent data traces linked to this profile container
                cursor.execute("DELETE FROM screenings WHERE user_id = %s", (user_id,))
                cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
                conn.commit()
        session.clear()
        return jsonify({'success': True, 'redirect': url_for('login')})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Irreversible destruction pipeline execution failure.'}), 500

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        # Check if user exists in database
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s;", (email,))
        user = cursor.fetchone()
        
        if user:
                user_id = user[0]
                token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(hours=1)
                
                cursor.execute("""
                    INSERT INTO password_resets (user_id, token, expires_at)
                    VALUES (%s, %s, %s);
                """, (user_id, token, expires_at))
                db.commit()
                
                # 1. Generate the secure recovery absolute URL
                reset_link = url_for('reset_password', token=token, _external=True)
                
                # 2. 🚀 NEW: Compile and dispatch the actual email payload
                msg = Message("VerifyMe Access Recovery Sequence", recipients=[email])
                msg.body = f"""Greetings Explorer,

    An access recovery sequence has been initiated for your VerifyMe node. 
    Click the secure vector link below to establish new credentials:

    {reset_link}

    This operational window will automatically expire in 1 hour. If you did not trigger this run, disregard this communication.
    """
                # Send it into the digital void to the user's inbox
                mail.send(msg)
                
                # 3. Clean production notification (No link exposed to the interface!)
                flash("If that account exists in our matrix, a secure recovery vector link has been dispatched to your inbox.", "success")

        cursor.close()
        db.close()
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html')


# --- 2. EXECUTE PASSWORD RESET SUBMISSION ROUTE ---
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db = get_db_connection()
    cursor = db.cursor()
    
    # Check if token exists, hasn't been used, and hasn't expired yet
    cursor.execute("""
        SELECT id, user_id, expires_at, used 
        FROM password_resets 
        WHERE token = %s AND used = FALSE;
    """, (token,))
    reset_record = cursor.fetchone()
    
    if not reset_record:
        flash("Invalid, spent, or corrupted security token parameter.", "error")
        cursor.close()
        db.close()
        return redirect(url_for('forgot_password'))
        
    reset_id, user_id, expires_at, used = reset_record
    
    # Check if the token lifespan window has run out
    if datetime.now() > expires_at:
        flash("This recovery vector session has expired. Please initiate a fresh run.", "error")
        cursor.close()
        db.close()
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash("Credentials match discrepancy detected. Try again.", "error")
            cursor.close()
            db.close()
            return render_template('reset_password.html', token=token)
            
        # Hash new password string securely
        hashed_password = generate_password_hash(new_password)
        
        # 1. Update the user's password column entry
        cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s;", (hashed_password, user_id))
        # 2. Mark this token as spent so it cannot be maliciously reused
        cursor.execute("UPDATE password_resets SET used = TRUE WHERE id = %s;", (reset_id,))
        
        db.commit()
        cursor.close()
        db.close()
        
        flash("Security credentials updated successfully. Please authenticate via standard sign-in.", "success")
        return redirect(url_for('login'))
        
    cursor.close()
    db.close()
    return render_template('reset_password.html', token=token)

@app.route('/send-screening-invite/<int:screening_id>', methods=['POST'])
def send_screening_invite(screening_id):
    if 'user_id' not in session or session.get('applicant_type') != 'company':
        return jsonify({'success': False, 'message': 'Unauthorized context.'}), 403

    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # 1. Fetch the screening data row to ensure it belongs to this company container
                cursor.execute("""
                    SELECT id, candidate_name, candidate_email, screening_type 
                    FROM screenings 
                    WHERE id = %s AND user_id = %s
                """, (screening_id, session['user_id']))
                screening = cursor.fetchone()

                if not screening:
                    return jsonify({'success': False, 'message': 'Screening record node not found.'}), 404

                # 2. Generate a secure unique token string asset
                upload_token = secrets.token_urlsafe(32)

                # 3. Save the token and flip state to 'Awaiting Document Upload'
                cursor.execute("""
                    UPDATE screenings 
                    SET status = 'Pending Input',
                        upload_token = %s
                    WHERE id = %s
                """, (upload_token, screening_id))
                conn.commit()

        # 4. Compile the secure dynamic link payload target
        # e.g., http://localhost:5000/upload-documents/Ab12Cd34Eff...
        invite_link = f"{Config.BASE_URL}/upload-documents/{upload_token}"

        # 5. Engine Dispatch Email Construction
        # 5. Engine Dispatch Email Construction
        msg = Message(
            subject=f"Action Required: VerifyMe Screening Link for {screening['candidate_name']}",
            recipients=[screening['candidate_email']]
        )
        
        # Premium HTML template block matching your VerifyMe design styles
        msg.html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #121413; color: #f5f5f5; margin: 0; padding: 20px; }}
                .email-card {{ background-color: #1a1d1b; max-width: 550px; margin: 0 auto; padding: 30px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05); }}
                .brand-header {{ font-size: 1.5rem; font-weight: bold; color: #4eb637; margin-bottom: 20px; font-family: monospace; }}
                h2 {{ color: #ffffff; font-size: 1.3rem; margin-top: 0; }}
                p {{ color: #a3a3a3; line-height: 1.6; font-size: 0.95rem; }}
                .btn-container {{ text-align: center; margin: 30px 0; }}
                .btn-action {{ background-color: #4eb637; color: #000000 !important; text-decoration: none; padding: 12px 24px; font-weight: 600; border-radius: 6px; display: inline-block; transition: background 0.2s; }}
                .footer-text {{ font-size: 0.8rem; color: #666666; margin-top: 30px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 15px; }}
            </style>
        </head>
        <body>
            <div class="email-card">
                <div class="brand-header">// VERIFYME CONTAINER</div>
                <h2>Hello {screening['candidate_name']},</h2>
                <p>An automated enterprise background screening request (<strong>{screening['screening_type']}</strong>) has been deployed for you by <strong>{session.get('display_name')}</strong>.</p>
                <p>To advance this identity verification process, please open your secure verification workspace via the portal link below to upload your required documentation:</p>
                
                <div class="btn-container">
                    <a href="{invite_link}" class="btn-action">Open Verification Portal</a>
                </div>
                
                <p>Once submitted, the status will automatically update to <strong>Ready for Review</strong> on the workspace matrix.</p>
                
                <div class="footer-text">
                    This is an automated transmission from the VerifyMe Security Automated Router. Please do not reply directly to this email.
                </div>
            </div>
        </body>
        </html>
        """
        
        # Execute the dispatch thread safely
        mail.send(msg)

        return jsonify({'success': True, 'message': 'Secure invitation workspace link successfully dispatched.'})

    except Exception as e:
        print(f"💥 Screening invite pipeline failure: {str(e)}")
        return jsonify({'success': False, 'message': f'Internal server routing fault: {str(e)}'}), 500

import werkzeug

@app.route('/upload-documents/<token>', methods=['GET', 'POST'])
def token_upload_portal(token):
    """
    Secure onboarding matrix that takes candidate credentials, streams raw binary files
    straight up to AWS S3, updates the tracking columns, and triggers an administrative alert state.
    """
    # 🗄️ 1. Fetch record securely using the unique safe token format
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM screenings WHERE upload_token = %s", (token,))
            screening = cursor.fetchone()

    # 🛑 2. Guard security boundary against injection or old slots
    if not screening:
        print(f"SECURITY BREACH THREAT: Unauthorized token asset interaction: {token}")
        abort(404)

    # 🔄 3. POST Layer: Process Submitted Identity & Compliance Files
    if request.method == 'POST':
        id_number = request.form.get('id_number')
        license_number = request.form.get('license_number')
        social_handle = request.form.get('social_handle')
        
        id_file = request.files.get('id_file')
        qual_file = request.files.get('qualification_file')
        license_file = request.files.get('license_file')
        
        # Pull table definitions directly out of your schema configuration
        update_fields = {
            "id_number": id_number if id_number else screening.get('id_number'),
            "license_number": license_number if license_number else screening.get('license_number'),
            "social_handle": social_handle if social_handle else screening.get('social_handle'),
            "popia_consent_granted_at": datetime.utcnow()
        }
        
        # ☁️ AWS S3 Stream Pipeline A: Identification Certificate
        if id_file and id_file.filename != '':
            secure_name = f"CAND_{screening['id']}_ID_{secure_filename(id_file.filename)}"
            s3_url = upload_file_to_s3(id_file, secure_name)
            if s3_url:
                update_fields["id_file_path"] = s3_url
                
        # ☁️ AWS S3 Stream Pipeline B: Qualification Matrix Data
        if qual_file and qual_file.filename != '':
            secure_name = f"CAND_{screening['id']}_QUAL_{secure_filename(qual_file.filename)}"
            s3_url = upload_file_to_s3(qual_file, secure_name)
            if s3_url:
                update_fields["qualification_file_path"] = s3_url

        # ☁️ AWS S3 Stream Pipeline C: Road Traffic Driver Licence
        if license_file and license_file.filename != '':
            secure_name = f"CAND_{screening['id']}_LIC_{secure_filename(license_file.filename)}"
            s3_url = upload_file_to_s3(license_file, secure_name)
            if s3_url:
                update_fields["license_file_path"] = s3_url

        # 🗄️ 4. Execute Transaction and upgrade state to trigger Admin visibility
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE screenings SET 
                        candidate_id_number = %s, 
                        id_file_path = %s,
                        qualification_file_path = %s,
                        license_number = %s, 
                        license_file_path = %s,
                        linkedin_handle = %s, 
                        other_social_handle=%s,
                        consent_granted_at = %s,
                        status = 'Ready for Review'
                    WHERE upload_token = %s
                """, (
                    update_fields.get("candidate_id_number"), 
                    update_fields.get("id_file_path", screening.get('id_file_path')),
                    update_fields.get("qualification_file_path", screening.get('qualification_file_path')),
                    update_fields.get("license_number"), 
                    update_fields.get("license_file_path", screening.get('license_file_path')),
                    update_fields.get("other_social_handle"), 
                    update_fields.get("linkedin_handle"),
                    update_fields.get("consent_granted_at"),
                    token
                ))
                conn.commit()
        
        return "<h1 style='font-family:sans-serif; text-align:center; padding-top:10%; color:#4eb637;'>Submission Successful! Your compliance profile has been securely synchronized.</h1>"

    # 🎨 5. Compile Portal UI layout for initial GET actions
    return render_template('upload_portal.html', screening=screening)

@app.route('/admin/export-monthly-report')
def export_monthly_report():
    # Matrix Rate definitions matching corporate calculations
    SCREENING_PRICES = {
        'Identity Verification & Validation': 450.00,
        'Criminal Record & Background Check': 550.00,
        'Credit & Financial Check': 380.00,
        'Professional License Verification': 320.00,
        'Global Compliance Screening': 620.00,
        'Social Media & Digital Footprint': 280.00
    }

    # Setup memory stream for file rendering
    si = StringIO()
    cw = csv.writer(si)
    
    # 1. Write the spreadsheet headers cleanly
    cw.writerow(['Reference Link Token', 'Channel Variant', 'Party Name / Target', 'Service Core Variant', 'Payment Status State', 'Calculated Revenue (ZAR)', 'Logged Timestamp'])
    
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # 2. Extract and parse corporate rows
        cursor.execute("""
            SELECT s.id, u.company_name, s.candidate_name, s.screening_type, s.payment_status, s.created_at 
            FROM screenings s 
            JOIN users u ON s.user_id = u.id 
            ORDER BY s.created_at DESC
        """)
        corp_data = cursor.fetchall()
        for row in corp_data:
            fee = SCREENING_PRICES.get(row['screening_type'], 0.0)
            cw.writerow([
                f"CC-{row['id']}",
                'Corporate',
                f"{row['company_name']} ({row['candidate_name']})",
                row['screening_type'],
                row['payment_status'],
                f"R{fee:.2f}",
                row['created_at']
            ])
            
        # 3. Extract and parse individual rows
        cursor.execute("""
            SELECT a.id, u.individual_name, u.email, a.verification_type, a.payment_status, a.created_at 
            FROM individual_audits a 
            JOIN users u ON a.user_id = u.id 
            ORDER BY a.created_at DESC
        """)
        indiv_data = cursor.fetchall()
        for row in indiv_data:
            fee = SCREENING_PRICES.get(row['verification_type'], 0.0)
            name_label = row['individual_name'] if row['individual_name'] else row['email']
            cw.writerow([
                f"IND-{row['id']}",
                'Individual',
                name_label,
                row['verification_type'],
                row['payment_status'],
                f"R{fee:.2f}",
                row['created_at']
            ])
            
        cursor.close()

    # 4. Generate response payload stream with clear down-stream attachments declaration
    output = si.getvalue()
    current_month = datetime.now().strftime('%Y-%m')
    filename = f"VerifyMe_Financial_Report_{current_month}.csv"
    
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.route('/admin/pricing-matrix', methods=['GET', 'POST'])
def admin_pricing_matrix():
    # 1. Enforce strict session access verification
    if 'user_id' not in session or session.get('applicant_type') != 'admin':
        flash('Unauthorized console entry point.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # 2. Capture the pricing modifications submitted via form arrays
        updated_prices = request.form.getlist('prices[]')
        setting_ids = request.form.getlist('ids[]')
        
        try:
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    for setting_id, price in zip(setting_ids, updated_prices):
                        # Convert input securely to numeric float types
                        clean_price = float(price) if price else 0.00
                        cursor.execute("""
                            UPDATE pricing_settings 
                            SET price_zar = %s, updated_at = NOW()
                            WHERE id = %s
                        """, (clean_price, setting_id))
                    conn.commit()
            flash('Dynamic verification pricing settings matrices updated successfully.', 'success')
        except Exception as e:
            flash(f'Failed to adjust pricing data: {str(e)}', 'error')
            
        return redirect(url_for('admin_pricing_matrix'))

    # 3. GET request: Fetch all current pricing parameters to display on screen
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM pricing_settings ORDER BY id ASC")
            pricing_entries = cursor.fetchall()

    # Pass the data out to a dedicated admin portal view template
    return render_template('admin_dashboard.html', pricing_entries=pricing_entries)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
