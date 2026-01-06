from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, make_response, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Assessment, Franchise, TokenPurchase
from dotenv import load_dotenv
import os
from flask_mail import Message, Mail
from flask_login import LoginManager
import random
import string
from datetime import datetime, timedelta
import pandas as pd
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.colors import black
import io
import fitz  # PyMuPDF
from PyPDF2 import PdfWriter, PdfReader
from types import SimpleNamespace
from sqlalchemy import text, inspect
import razorpay
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import uuid
from urllib.parse import urlparse

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key_here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)
db.init_app(app)
login_manager = LoginManager(app)
login_manager.init_app(app)

# Add after your existing app config
app.config['RAZORPAY_KEY_ID'] = os.getenv('RAZORPAY_KEY_ID')
app.config['RAZORPAY_KEY_SECRET'] = os.getenv('RAZORPAY_KEY_SECRET')

razorpay_client = razorpay.Client(auth=(app.config['RAZORPAY_KEY_ID'], app.config['RAZORPAY_KEY_SECRET']))

# For email verification tokens
serializer = URLSafeTimedSerializer(app.secret_key)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def inject_user_franchise_info():
    """Make franchise parent info available to ALL templates"""
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.franchise_id:
            user_franchise_obj = Franchise.query.get(user.franchise_id)
            return dict(user_franchise=user_franchise_obj)
    return dict(user_franchise=None)

with app.app_context():
    db.create_all()
    
    try:
        with db.engine.connect() as conn:
            # Check existing columns for USER table
            result = conn.execute(text("PRAGMA table_info(user)"))
            columns = result.fetchall()
            user_column_names = [col[1] for col in columns]
            print(f"Existing user columns: {user_column_names}")
            
            # Check existing columns for FRANCHISE table 
            result = conn.execute(text("PRAGMA table_info(franchise)"))
            columns = result.fetchall()
            franchise_column_names = [col[1] for col in columns]
            print(f"Existing franchise columns: {franchise_column_names}")

            
            # Check existing columns
            inspector = inspect(db.engine)
            user_columns = [col['name'] for col in inspector.get_columns('user')]
            franchise_columns = [col['name'] for col in inspector.get_columns('franchise')]

            print("Existing user columns:", user_columns)
            print("Existing franchise columns:", franchise_columns)

            # Sync schema
            try:
                with db.engine.connect() as conn:
                    # Check assessment table columns
                    assessment_columns = [col['name'] for col in inspector.get_columns('assessment')]
                    print("Existing assessment columns:", assessment_columns)
                    
                    # Add user columns
                    if 'origin' not in user_columns:
                        conn.execute(text('ALTER TABLE user ADD COLUMN origin VARCHAR(20) DEFAULT "self_registered"'))
                        conn.commit()
                        print("Added origin column to user table")
                    
                    # Add franchise columns for hierarchy
                    if 'parent_franchise_id' not in franchise_columns:
                        conn.execute(text('ALTER TABLE franchise ADD COLUMN parent_franchise_id INTEGER'))
                        conn.commit()
                        print("Added parent_franchise_id column to franchise table")
                    
                    if 'created_by_user_id' not in franchise_columns:
                        conn.execute(text('ALTER TABLE franchise ADD COLUMN created_by_user_id INTEGER'))
                        conn.commit()
                        print("Added created_by_user_id column to franchise table")
                    
                    if 'razorpay_key_id' not in franchise_columns:
                        conn.execute(text('ALTER TABLE franchise ADD COLUMN razorpay_key_id VARCHAR(100)'))
                        conn.commit()
                        print("Added razorpay_key_id column to franchise table")
                    
                    if 'razorpay_key_secret' not in franchise_columns:
                        conn.execute(text('ALTER TABLE franchise ADD COLUMN razorpay_key_secret VARCHAR(100)'))
                        conn.commit()
                        print("Added razorpay_key_secret column to franchise table")
                    
                    # Add missing assessment table columns (your OLD database structure)
                    if 'name' not in assessment_columns:
                        conn.execute(text('ALTER TABLE assessment ADD COLUMN name VARCHAR(100)'))
                        conn.commit()
                        print("Added name column to assessment table")
                    
                    if 'class_name' not in assessment_columns:
                        conn.execute(text('ALTER TABLE assessment ADD COLUMN class_name VARCHAR(50)'))
                        conn.commit()
                        print("Added class_name column to assessment table")
                    
                    if 'school' not in assessment_columns:
                        conn.execute(text('ALTER TABLE assessment ADD COLUMN school VARCHAR(100)'))
                        conn.commit()
                        print("Added school column to assessment table")
                    
                    if 'dob' not in assessment_columns:
                        conn.execute(text('ALTER TABLE assessment ADD COLUMN dob DATE'))
                        conn.commit()
                        print("Added dob column to assessment table")
                    
                    if 'contact' not in assessment_columns:
                        conn.execute(text('ALTER TABLE assessment ADD COLUMN contact VARCHAR(20)'))
                        conn.commit()
                        print("Added contact column to assessment table")
                    
                    if 'parent_name' not in assessment_columns:
                        conn.execute(text('ALTER TABLE assessment ADD COLUMN parent_name VARCHAR(100)'))
                        conn.commit()
                        print("Added parent_name column to assessment table")
                    
                    if 'parent_contact' not in assessment_columns:
                        conn.execute(text('ALTER TABLE assessment ADD COLUMN parent_contact VARCHAR(20)'))
                        conn.commit()
                        print("Added parent_contact column to assessment table")
                    
                    if 'parent_email' not in assessment_columns:
                        conn.execute(text('ALTER TABLE assessment ADD COLUMN parent_email VARCHAR(100)'))
                        conn.commit()
                        print("Added parent_email column to assessment table")
                    
                    if 'date' not in assessment_columns:
                        conn.execute(text('ALTER TABLE assessment ADD COLUMN date DATE'))
                        conn.commit()
                        print("Added date column to assessment table")
                    
                    print("Database schema updated successfully!")
            except Exception as e:
                print(f"Schema sync error: {e}")
            
            # Add missing columns to USER table
            if 'force_password_reset' not in user_column_names:
                try:
                    conn.execute(text("ALTER TABLE user ADD COLUMN force_password_reset INTEGER DEFAULT 1;"))
                    conn.commit()
                    print("Added force_password_reset column successfully")
                except Exception as e:
                    print(f"Error adding force_password_reset column: {e}")

            if 'email_verified' not in user_column_names:
                try:
                    conn.execute(text("ALTER TABLE user ADD COLUMN email_verified INTEGER DEFAULT 0;"))
                    conn.commit()
                    print("Added email_verified column successfully")
                except Exception as e:
                    print(f"Error adding email_verified column: {e}")

            if 'verification_token' not in user_column_names:
                try:
                    conn.execute(text("ALTER TABLE user ADD COLUMN verification_token TEXT;"))
                    conn.commit()
                    print("Added verification_token column successfully")
                except Exception as e:
                    print(f"Error adding verification_token column: {e}")

            # Add reset token columns to USER table
            if 'reset_token' not in user_column_names:
                try:
                    conn.execute(text("ALTER TABLE user ADD COLUMN reset_token TEXT;"))
                    conn.commit()
                    print("Added reset_token column successfully")
                except Exception as e:
                    print(f"Error adding reset_token column: {e}")

            if 'reset_token_expiry' not in user_column_names:
                try:
                    conn.execute(text("ALTER TABLE user ADD COLUMN reset_token_expiry DATETIME;"))
                    conn.commit()
                    print("Added reset_token_expiry column successfully")
                except Exception as e:
                    print(f"Error adding reset_token_expiry column: {e}")

            if 'origin' not in user_column_names:
                try:
                    conn.execute(text("ALTER TABLE user ADD COLUMN origin TEXT DEFAULT 'self_registered';"))
                    conn.commit()
                    print("Added origin column successfully")
                except Exception as e:
                    print(f"Error adding origin column: {e}")

            # Add missing columns to FRANCHISE table
            if 'whatsapp_number' not in franchise_column_names:
                try:
                    conn.execute(text("ALTER TABLE franchise ADD COLUMN whatsapp_number TEXT;"))
                    conn.commit()
                    print("Added whatsapp_number column successfully")
                except Exception as e:
                    print(f"Error adding whatsapp_number column: {e}")

            if 'payment_status' not in franchise_column_names:
                try:
                    conn.execute(text("ALTER TABLE franchise ADD COLUMN payment_status TEXT DEFAULT 'pending';"))
                    conn.commit()
                    print("Added payment_status column successfully")
                except Exception as e:
                    print(f"Error adding payment_status column: {e}")

            if 'payment_id' not in franchise_column_names:
                try:
                    conn.execute(text("ALTER TABLE franchise ADD COLUMN payment_id TEXT;"))
                    conn.commit()
                    print("Added payment_id column successfully")
                except Exception as e:
                    print(f"Error adding payment_id column: {e}")

            if 'is_active' not in franchise_column_names:
                try:
                    conn.execute(text("ALTER TABLE franchise ADD COLUMN is_active INTEGER DEFAULT 0;"))
                    conn.commit()
                    print("Added is_active column successfully")
                except Exception as e:
                    print(f"Error adding is_active column: {e}")

            if 'registration_date' not in franchise_column_names:
                try:
                    conn.execute(text("ALTER TABLE franchise ADD COLUMN registration_date DATETIME;"))
                    conn.commit()
                    print("Added registration_date column (no default)")
                    
                    # Update existing rows with current timestamp
                    conn.execute(text("UPDATE franchise SET registration_date = CURRENT_TIMESTAMP;"))
                    conn.commit()
                    print("Updated registration_date values for existing rows")
                except Exception as e:
                    print(f"Error adding registration_date column: {e}")

            # Add analysis counter to FRANCHISE table
            if 'analysis_counter' not in franchise_column_names:
                try:
                    conn.execute(text("ALTER TABLE franchise ADD COLUMN analysis_counter INTEGER DEFAULT 0;"))
                    conn.commit()
                    print("Added analysis_counter column successfully")
                except Exception as e:
                    print(f"Error adding analysis_counter column: {e}")

            if 'tokens_total' not in franchise_column_names:
                try:
                    conn.execute(text("ALTER TABLE franchise ADD COLUMN tokens_total INTEGER DEFAULT 0;"))
                    conn.commit()
                    print("Added tokens_total column successfully")
                except Exception as e:
                    print(f"Error adding tokens_total column: {e}")

            if 'tokens_used' not in franchise_column_names:
                try:
                    conn.execute(text("ALTER TABLE franchise ADD COLUMN tokens_used INTEGER DEFAULT 0;"))
                    conn.commit()
                    print("Added tokens_used column successfully")
                except Exception as e:
                    print(f"Error adding tokens_used column: {e}")

            # Update superusers to disable forced password reset
            conn.execute(text("UPDATE user SET force_password_reset = 0 WHERE role = 'superuser';"))
            conn.commit()
            print("Updated superuser password reset flags")
            
    except Exception as e:
        print(f"Schema sync error: {e}")


def getattr_jinja(obj, attr):
    return getattr(obj, attr, "")

app.jinja_env.globals['getattr'] = getattr_jinja

@app.route('/', methods=['GET', 'POST'])
def login():
    # Check if this is a whitelabel access
    host = request.headers.get('Host', '')
    franchise = None
    
    # Try to find franchise by website domain
    if host:
        # Clean the host - remove port if present
        clean_host = host.split(':')[0]
        
        # Try exact domain match first
        franchise = Franchise.query.filter(
            db.or_(
                Franchise.website == f'http://{clean_host}',
                Franchise.website == f'https://{clean_host}',
                Franchise.website == clean_host,
                Franchise.website == f'http://www.{clean_host}',
                Franchise.website == f'https://www.{clean_host}',
                Franchise.website == f'www.{clean_host}'
            )
        ).first()
        
        # If no exact match, try partial match as fallback
        if not franchise:
            franchise = Franchise.query.filter(
                db.or_(
                    Franchise.website.contains(clean_host),
                    Franchise.website.contains(clean_host.replace('www.', ''))
                )
            ).first()
    
    # Handle auto-login parameters from email link (MOVED OUTSIDE POST block)
    email_param = request.args.get('email')
    password_param = request.args.get('password')
    
    if email_param and password_param:
        user = User.query.filter_by(email=email_param).first()
        if user and check_password_hash(user.password, password_param):
            # If accessing via franchise domain, ensure user belongs to that franchise
            if franchise:
                user_franchise = db.session.get(Franchise, user.franchise_id) if user.franchise_id else None
                
                # Check if user belongs to this franchise or is a sub-franchise
                if user.franchise_id != franchise.id:
                    # Check if user's franchise is a sub-franchise of the current domain
                    if not (user_franchise and user_franchise.parent_franchise_id == franchise.id):
                        return render_template('whitelabel_login.html' if franchise else 'login.html', 
                                            error='Access denied for this domain', 
                                            franchise=franchise)
            
            session['user_id'] = user.id
            
            # Always force password reset for first-time login from email
            if user.force_password_reset:
                return redirect(url_for('reset_password', first_time=1))
            else:
                return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            # If accessing via franchise domain, ensure user belongs to that franchise
            if franchise:
                user_franchise = db.session.get(Franchise, user.franchise_id) if user.franchise_id else None
                
                # Check if user belongs to this franchise or is a sub-franchise
                if user.franchise_id != franchise.id:
                    # Check if user's franchise is a sub-franchise of the current domain
                    if not (user_franchise and user_franchise.parent_franchise_id == franchise.id):
                        return render_template('whitelabel_login.html' if franchise else 'login.html', 
                                            error='Access denied for this domain', 
                                            franchise=franchise)
            
            session['user_id'] = user.id
            
            if user.role != 'superuser' and user.force_password_reset:
                return redirect(url_for('reset_password', first_time=1))
            else:
                return redirect(url_for('dashboard'))
        else:
            return render_template('whitelabel_login.html' if franchise else 'login.html',
                                 error='Invalid credentials',
                                 franchise=franchise)
    
    return render_template('whitelabel_login.html' if franchise else 'login.html',
                         franchise=franchise)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    
    if user.role != 'superuser' and user.force_password_reset:
        return redirect(url_for('reset_password', first_time=1))
    
    host = request.headers.get('Host', '')
    franchise = None
    
    if host:
        franchise = Franchise.query.filter_by(website=host, is_active=True).first()
    
    if user.role == 'superuser':
        total_franchises = Franchise.query.filter_by(parent_franchise_id=None).count()
        total_students = Assessment.query.count()
        
        return render_template('dashboard.html', 
                             user=user,
                             total_franchises=total_franchises,
                             total_students=total_students,
                             franchise=franchise)
    
    elif user.role == 'user' and user.franchise_id:
        franchise_obj = db.session.get(Franchise, user.franchise_id)
        if franchise_obj:
            # Count sub-franchises created by this white-label user
            sub_franchises_count = Franchise.query.filter_by(
                parent_franchise_id=user.franchise_id
            ).count()
            
            # Get franchise IDs for filtering students
            franchise_ids = [user.franchise_id]
            sub_franchise_ids = [f.id for f in Franchise.query.filter_by(
                parent_franchise_id=user.franchise_id
            ).all()]
            franchise_ids.extend(sub_franchise_ids)
            
            # Count students across franchise and sub-franchises
            students_count = Assessment.query.join(User).filter(
                User.franchise_id.in_(franchise_ids)
            ).count()
            
            # ✅ FIX: Calculate tokens correctly based on franchise type
            if franchise_obj.parent_franchise_id:
                # Sub-franchise: Get tokens from TokenPurchase table
                purchases = TokenPurchase.query.filter_by(
                    franchise_id=franchise_obj.id,
                    payment_status='completed'
                ).all()
                
                total_purchased = sum(p.tokens_bought for p in purchases)
                tokens_used = franchise_obj.tokens_used or 0
                tokens_remaining = total_purchased - tokens_used
            else:
                # White-label: Calculate from TokenPurchase table
                purchases = TokenPurchase.query.filter_by(
                    franchise_id=franchise_obj.id,
                    payment_status='completed'
                ).all()
                
                total_purchased = sum(p.tokens_bought for p in purchases)
                tokens_used = franchise_obj.tokens_used or 0
                tokens_remaining = total_purchased - tokens_used
            
            # For display purposes - get parent logo if exists
            parent_logo = None
            if franchise_obj.parent_franchise_id:
                parent_franchise = db.session.get(Franchise, franchise_obj.parent_franchise_id)
                if parent_franchise and parent_franchise.logo_filename:
                    parent_logo = parent_franchise.logo_filename
            
            return render_template('dashboard.html', 
                                   user=user, 
                                   franchise=franchise_obj, 
                                   total_franchises=sub_franchises_count,
                                   total_students=students_count,
                                   tokens_bought=total_purchased,
                                   tokens_used=tokens_used,
                                   tokens_left=tokens_remaining,
                                   parent_logo=parent_logo)
        
    return redirect(url_for('logout'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error='Email already registered')
        
        if Franchise.query.filter_by(email=email).first():
            return render_template('register.html', error='Email already registered')
        
        # Generate verification token
        token = serializer.dumps(email, salt='email-verification')
        
        # Store email in session for verification process
        session['pending_registration_email'] = email
        session['verification_token'] = token
        
        # Send verification email
        try:
            msg = Message(
                subject='Verify Your Email - Kareer Studio',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            
            verification_link = url_for('verify_email', token=token, _external=True)
            msg.body = f"""
            Welcome to Kareer Studio!
            
            Please click the link below to verify your email and complete your registration:
            {verification_link}
            
            This link will expire in 1 hour.
            
            Best regards,
            Kareer Studio Team
            """
            
            mail.send(msg)
            flash('Verification email sent! Please check your inbox.', 'info')
            return render_template('email_sent.html', email=email)
            
        except Exception as e:
            flash('Error sending verification email. Please try again.', 'error')
            return render_template('register.html', error='Email sending failed')
    
    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        # Debug: Print session data to see what's stored
        print(f"Session pending email: {session.get('pending_registration_email')}")
        print(f"Token received: {token}")
        
        # Try to load the token
        email = serializer.loads(token, salt='email-verification', max_age=3600)
        print(f"Email from token: {email}")
        
        if session.get('pending_registration_email') == email:
            session['email_verified'] = True
            flash('Email verified successfully! Please complete your registration.', 'success')
            return redirect(url_for('registration_step1'))
        else:
            flash(f'Session mismatch. Expected: {session.get("pending_registration_email")}, Got: {email}', 'error')
            return redirect(url_for('register'))
            
    except SignatureExpired:
        flash('Verification link has expired. Please request a new verification email.', 'error')
        return redirect(url_for('register'))
    except BadSignature:
        flash('Invalid verification link format.', 'error')
        return redirect(url_for('register'))
    except Exception as e:
        flash(f'Verification error: {str(e)}', 'error')
        print(f"Verification error: {str(e)}")
        return redirect(url_for('register'))

@app.route('/registration-step1', methods=['GET', 'POST'])
def registration_step1():
    if not session.get('email_verified'):
        flash('Please verify your email first.', 'error')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        # Store step 1 data in session
        session['step1_data'] = {
            'franchise_name': request.form.get('franchise_name'),
            'company_name': request.form.get('company_name'),
            'address': request.form.get('address'),
            'phone': request.form.get('phone'),
            'whatsapp_number': request.form.get('whatsapp_number'),
            'website': request.form.get('website'),
            'gst_number': request.form.get('gstnumber', '').upper(),
            'pan_number': request.form.get('pannumber', '').upper()
        }
        
        # Handle logo upload
        logo = request.files.get('logo')
        if logo and logo.filename:
            if len(logo.read()) > 2 * 1024 * 1024:
                flash('Logo size should not exceed 2MB', 'error')
                return render_template('registration_step1.html')
            
            logo.seek(0)
            
            # Validate image dimensions (optional - you can add PIL for this)
            import uuid
            file_extension = logo.filename.rsplit('.', 1)[1].lower()
            logo_filename = f"franchise_logo_{uuid.uuid4().hex[:8]}.{file_extension}"
            
            static_dir = os.path.join(app.root_path, 'static')
            if not os.path.exists(static_dir):
                os.makedirs(static_dir)
            
            logo.save(os.path.join(static_dir, logo_filename))
            session['step1_data']['logo_filename'] = logo_filename
        
        return redirect(url_for('registration_step2'))
    
    return render_template('registration_step1.html')

@app.route('/registration-step2', methods=['GET', 'POST'])
def registration_step2():
    if not session.get('step1_data'):
        flash('Please complete step 1 first.', 'error')
        return redirect(url_for('registration_step1'))
    
    if request.method == 'POST':
        # Create Razorpay order
        amount = 100  # ₹1 in paise (100 paise = ₹1)
        
        try:
            razorpay_order = razorpay_client.order.create({
                'amount': amount,
                'currency': 'INR',
                'payment_capture': 1
            })
            
            return render_template('payment.html', 
                                 order_id=razorpay_order['id'],
                                 amount=amount,
                                 key_id=app.config['RAZORPAY_KEY_ID'])
        except Exception as e:
            flash('Error creating payment order. Please try again.', 'error')
            return render_template('registration_step2.html')
    
    return render_template('registration_step2.html')

@app.route('/payment-success', methods=['POST'])
def payment_success():
    # Verify payment
    payment_id = request.form.get('razorpay_payment_id')
    order_id = request.form.get('razorpay_order_id')
    signature = request.form.get('razorpay_signature')
    
    try:
        # Verify signature
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        })
        
        # Payment verified, create franchise and user
        step1_data = session.get('step1_data')
        email = session.get('pending_registration_email')
        
        franchise = Franchise(
            franchise_name=step1_data['franchise_name'],
            company_name=step1_data['company_name'],
            address=step1_data['address'],
            phone=step1_data['phone'],
            whatsapp_number=step1_data['whatsapp_number'],
            email=email,
            website=step1_data['website'],
            gst_number=step1_data['gst_number'],
            pan_number=step1_data['pan_number'],
            logo_filename=step1_data.get('logo_filename'),
            payment_status='paid',
            payment_id=payment_id,
            is_active=True
        )
        
        db.session.add(franchise)
        db.session.commit()
        
        # Create user account
        password = generate_password()
        user = User(
            email=email,
            password=generate_password_hash(password),
            role='user',
            franchise_id=franchise.id,
            email_verified=True,
            force_password_reset=True
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Send welcome email with login details
        try:
            msg = Message(
                subject='Welcome to Your Whitelabel Platform!',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            
            website_url = step1_data['website'] if step1_data['website'].startswith(('http://', 'https://')) else f"https://{step1_data['website']}"
            
            msg.body = f"""
            Congratulations! Your whitelabel platform is ready.

            Company: {step1_data['company_name']}
            Platform URL: {website_url}

            Login Credentials:
            Email: {email}
            Temporary Password: {password}

            🔧 FINAL STEP - Point Your Domain to Our Server:

            1. Go to your domain registrar's DNS settings
            2. Add an A Record:
            • Name: @ (or leave blank for root domain)  
            • Value: 82.25.93.94
            • TTL: 300 (5 minutes) or default
            3. Wait 5-30 minutes for DNS to update
            4. Visit your domain - it's ready!

            Next Steps:
            1. Complete DNS setup above
            2. Visit {website_url} 
            3. Login with credentials above
            4. Change your password for security
            5. Start adding students and generating reports

            ⚠️ Important: You must complete the DNS setup for your custom domain to work properly.

            Best regards,
            Kareer Studio Team
            """
            
            mail.send(msg)
        except Exception as e:
            print(f"Error sending welcome email: {e}")
        
        # Clear session data
        session.pop('pending_registration_email', None)
        session.pop('email_verified', None)
        session.pop('step1_data', None)
        session.pop('verification_token', None)
        
        return render_template('registration_complete.html', 
                             company_name=step1_data['company_name'],
                             website_url=website_url)
        
    except Exception as e:
        flash('Payment verification failed. Please contact support.', 'error')
        return redirect(url_for('registration_step2'))

@app.route('/payment-failed')
def payment_failed():
    flash('Payment failed. Please try again.', 'error')
    return redirect(url_for('registration_step2'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    # Check if this is a whitelabel access
    host = request.headers.get('Host', '')
    franchise = None
    
    if host:
        clean_host = host.split(':')[0]
        franchise = Franchise.query.filter(
            db.or_(
                Franchise.website == f'http://{clean_host}',
                Franchise.website == f'https://{clean_host}',
                Franchise.website == clean_host,
                Franchise.website == f'http://www.{clean_host}',
                Franchise.website == f'https://www.{clean_host}',
                Franchise.website == f'www.{clean_host}'
            )
        ).first()
        
        if not franchise:
            franchise = Franchise.query.filter(
                db.or_(
                    Franchise.website.contains(clean_host),
                    Franchise.website.contains(clean_host.replace('www.', ''))
                )
            ).first()
    
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No account found with this email address.', 'error')
            return render_template('forgot_password.html', franchise=franchise)
        
        # Generate reset token
        reset_token = str(uuid.uuid4())
        user.reset_token = reset_token
        user.reset_token_expiry = datetime.now() + timedelta(hours=1)  # 1 hour expiry
        
        try:
            db.session.commit()
            
            # Send reset email
            reset_link = url_for('reset_password_token', token=reset_token, _external=True)
            
            msg = Message(
                subject='Password Reset Request - Kareer Studio',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            
            msg.body = f"""
Hello,

You have requested a password reset for your Kareer Studio account.

Click the link below to reset your password:
{reset_link}

This link will expire in 1 hour.

If you didn't request this password reset, please ignore this email.

Best regards,
Kareer Studio Team
"""
            
            mail.send(msg)
            flash('Password reset link has been sent to your email address.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error sending password reset email. Please try again.', 'error')
            print(f"Error sending reset email: {e}")
    
    return render_template('forgot_password.html', franchise=franchise)

@app.route('/reset_password_token/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    # Find user by reset token
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or not user.reset_token_expiry or datetime.now() > user.reset_token_expiry:
        flash('Invalid or expired password reset link.', 'error')
        return redirect(url_for('forgot_password'))
    
    # Check if this is a whitelabel access
    host = request.headers.get('Host', '')
    franchise = None
    
    if host:
        clean_host = host.split(':')[0]
        franchise = Franchise.query.filter(
            db.or_(
                Franchise.website == f'http://{clean_host}',
                Franchise.website == f'https://{clean_host}',
                Franchise.website == clean_host,
                Franchise.website == f'http://www.{clean_host}',
                Franchise.website == f'https://www.{clean_host}',
                Franchise.website == f'www.{clean_host}'
            )
        ).first()
        
        if not franchise:
            franchise = Franchise.query.filter(
                db.or_(
                    Franchise.website.contains(clean_host),
                    Franchise.website.contains(clean_host.replace('www.', ''))
                )
            ).first()
    
    if not franchise and user.role == 'user' and user.franchise_id:
        franchise = Franchise.query.get(user.franchise_id)
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('reset_password_token.html', franchise=franchise)
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('reset_password_token.html', franchise=franchise)
        
        # Update password
        user.password = generate_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expiry = None
        user.force_password_reset = False
        
        db.session.commit()
        
        flash('Your password has been reset successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password_token.html', franchise=franchise)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Add franchise detection
    host = request.headers.get('Host', '')
    franchise = None
    
    if host:
        # Clean the host - remove port if present
        clean_host = host.split(':')[0]
        
        # Try exact domain match first
        franchise = Franchise.query.filter(
            db.or_(
                Franchise.website == f'http://{clean_host}',
                Franchise.website == f'https://{clean_host}',
                Franchise.website == clean_host,
                Franchise.website == f'http://www.{clean_host}',
                Franchise.website == f'https://www.{clean_host}',
                Franchise.website == f'www.{clean_host}'
            )
        ).first()
        
        # If no exact match, try partial match as fallback
        if not franchise:
            franchise = Franchise.query.filter(
                db.or_(
                    Franchise.website.contains(clean_host),
                    Franchise.website.contains(clean_host.replace('www.', ''))
                )
            ).first()
    
    if not franchise and user.role == 'user' and user.franchise_id:
        franchise = Franchise.query.get(user.franchise_id)
    
    # "first_time" query param distinguishes forced from regular password reset
    first_time = request.args.get('first_time', None)
    block_cancel = bool(first_time) and user.role != 'superuser' and user.force_password_reset
    
    # Only redirect to forced reset if user is not superuser, is flagged, and not already on forced reset page
    if not first_time and user.role != 'superuser' and user.force_password_reset and request.method == 'GET':
        return redirect(url_for('reset_password', first_time=1))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not check_password_hash(user.password, current_password):
            flash('Current password is incorrect!', 'error')
            return render_template('reset_password.html', user=user, block_cancel=block_cancel, franchise=franchise)
        
        if new_password != confirm_password:
            flash('New password and confirm password do not match!', 'error')
            return render_template('reset_password.html', user=user, block_cancel=block_cancel, franchise=franchise)
        
        if len(new_password) < 6:
            flash('New password must be at least 6 characters long!', 'error')
            return render_template('reset_password.html', user=user, block_cancel=block_cancel, franchise=franchise)
        
        user.password = generate_password_hash(new_password)
        if block_cancel:
            user.force_password_reset = False
        
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    # Pass block_cancel to template - controls cancel button/navbar logic
    return render_template('reset_password.html', user=user, block_cancel=block_cancel, franchise=franchise)

def generate_password(length=8):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

@app.route('/add_franchise', methods=['GET', 'POST'])
def add_franchise():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    
    # Allow both superuser AND white-label users to add franchises
    if user.role not in ['superuser', 'user']:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # White-label users must have a franchise_id
    if user.role == 'user' and not user.franchise_id:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # CHECK IF WHITE-LABEL USER HAS RAZORPAY SETTINGS
        if user.role == 'user' and user.franchise_id:
            franchise_check = db.session.get(Franchise, user.franchise_id)
            if not franchise_check or not franchise_check.razorpay_key_id or not franchise_check.razorpay_key_secret:
                flash('Please configure your Razorpay payment settings before adding franchises.', 'warning')
                return redirect(url_for('razorpay_settings'))
        
        # Get form data with CORRECT field names
        franchise_name = request.form.get('franchise_name')
        company_name = request.form.get('company_name')
        address = request.form.get('address')
        phone = request.form.get('phone')
        email = request.form.get('email')
        gstnumber = request.form.get('gstnumber', '').upper()
        pannumber = request.form.get('pannumber', '').upper()
        whatsapp_number = request.form.get('whatsappnumber')
        
        # Check if franchise with this email already exists
        existing = Franchise.query.filter_by(email=email).first()
        if existing:
            flash('A franchise with this email already exists.', 'error')
            return render_template('add_franchise.html', user=user)
        
        # Handle logo upload
        logo_filename = None
        if 'logo' in request.files:
            logo = request.files['logo']
            if logo and logo.filename:
                logo_filename = str(uuid.uuid4()) + '_' + logo.filename
                static_dir = os.path.join(app.root_path, 'static')
                if not os.path.exists(static_dir):
                    os.makedirs(static_dir)
                logo.save(os.path.join(static_dir, logo_filename))
        
        try:
            # Determine parent_franchise_id and website
            parent_franchise_id = None
            created_by_user_id = None
            website = None
            
            if user.role == 'user':
                # White-label user is creating a sub-franchise
                parent_franchise_id = user.franchise_id
                created_by_user_id = user.id
                
                # Get parent's website
                parent_franchise = db.session.get(Franchise, user.franchise_id)
                if parent_franchise:
                    website = parent_franchise.website
            
            # Create new franchise
            new_franchise = Franchise(
                franchise_name=franchise_name,
                company_name=company_name,
                address=address,
                phone=phone,
                email=email,
                website=website,  # Use parent's website for sub-franchises
                gst_number=gstnumber,
                pan_number=pannumber,
                logo_filename=logo_filename,
                whatsapp_number=whatsapp_number,
                parent_franchise_id=parent_franchise_id,
                created_by_user_id=created_by_user_id,
                is_active=True,  # Auto-active
                payment_status='completed' if user.role == 'user' else 'pending'
            )
            
            db.session.add(new_franchise)
            db.session.commit()
            
            # Generate verification token
            token = serializer.dumps(email, salt='franchise-email-verify')
            
            # Generate password
            password = generate_password()

            # Create user account for the franchise
            franchise_user = User(
                email=email,
                password=generate_password_hash(password),
                role='user',
                franchise_id=new_franchise.id,
                email_verified=True,  # Auto-verified
                force_password_reset=True,  # MUST reset on first login
                origin='admin_added'
            )
            db.session.add(franchise_user)
            db.session.commit()

            # Send login credentials email (NO verification needed)
            try:
                msg = Message(
                    subject="Franchise Account Created - Login Credentials",
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[email]
                )
                
                if user.role == 'user':
                    # Sub-franchise email
                    parent_franchise = db.session.get(Franchise, user.franchise_id)
                    
                    msg.body = f"""Welcome {franchise_name}!

            Your franchise account has been created by {parent_franchise.company_name}.

            LOGIN CREDENTIALS:
            Website: {website}
            Email: {email}
            Password: {password}

            IMPORTANT: This password is valid for ONE LOGIN ONLY. You MUST change your password immediately after first login.

            Please login now and set your new password.

            Best regards,
            {parent_franchise.company_name}"""
                else:
                    # Main franchise email (created by superuser)
                    msg.body = f"""Welcome {franchise_name}!

            Your franchise account has been created by Kareer Studio.

            LOGIN CREDENTIALS:
            Website: [Your website will be provided]
            Email: {email}
            Password: {password}

            IMPORTANT: This password is valid for ONE LOGIN ONLY. You MUST change your password immediately after first login.

            Please login and set your new password.

            Best regards,
            Kareer Studio Team"""
                
                mail.send(msg)
                flash('Franchise added successfully! Login credentials sent to ' + email, 'success')
            except Exception as e:
                print(f"Email error: {str(e)}")
                flash('Franchise added but email could not be sent. Please contact the franchise manually.', 'warning')

            return redirect(url_for('manage_franchise'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error: {str(e)}")
            flash('An error occurred while saving the franchise. Please try again.', 'error')
            return render_template('add_franchise.html', user=user)
    
    # GET request - show the form
    # GET request - show the form
    # For white-label users, get their franchise data for logo display
    franchise_context = None
    if user.role == 'user' and user.franchise_id:
        franchise_context = db.session.get(Franchise, user.franchise_id)

    return render_template('add_franchise.html', user=user, franchise=franchise_context)

@app.route('/verify_franchise/<token>')
def verify_franchise(token):
    try:
        email = serializer.loads(token, salt='franchise-email-verify', max_age=3600)
        
        franchise_user = User.query.filter_by(email=email, origin='admin_added').first()
        if not franchise_user:
            flash('Invalid verification link or user not found.', 'error')
            return redirect(url_for('login'))
        
        # Mark email as verified
        franchise_user.email_verified = True
        db.session.commit()
        
        # Store email in session for payment process
        session['franchise_payment_email'] = email
        flash('Email verified successfully! Please complete the payment process.', 'success')
        return redirect(url_for('franchise_payment'))
        
    except SignatureExpired:
        flash('Verification link has expired. Please contact administrator.', 'error')
    except BadSignature:
        flash('Invalid verification link.', 'error')
    except Exception as e:
        flash(f'Verification error: {str(e)}', 'error')
    
    return redirect(url_for('login'))

@app.route('/franchise_payment', methods=['GET', 'POST'])
def franchise_payment():
    if 'franchise_payment_email' not in session:
        flash('Session expired. Please verify your email again.', 'error')
        return redirect(url_for('login'))

    email = session['franchise_payment_email']
    franchise_user = User.query.filter_by(email=email, origin='admin_added').first()

    if not franchise_user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    franchise = Franchise.query.get(franchise_user.franchise_id)

    if request.method == 'POST':
        # Create Razorpay order with franchise-specific pricing
        amount = 500  # ₹5 for admin-added franchises (in paise)

        try:
            razorpay_order = razorpay_client.order.create({
                'amount': amount,
                'currency': 'INR',
                'payment_capture': 1
            })

            # Directly render the payment page with Razorpay integration
            return render_template('franchise_payment.html',
                                   order_id=razorpay_order['id'],
                                   amount=amount,
                                   key_id=app.config['RAZORPAY_KEY_ID'],
                                   franchise=franchise)
        except Exception as e:
            flash('Error creating payment order. Please try again.', 'error')
            return render_template('franchise_payment_form.html', franchise=franchise)

    # GET request - show initial payment form
    return render_template('franchise_payment_form.html', franchise=franchise)

@app.route('/franchise_payment_success', methods=['POST'])
def franchise_payment_success():
    # Verify payment
    payment_id = request.form.get('razorpay_payment_id')
    order_id = request.form.get('razorpay_order_id')
    signature = request.form.get('razorpay_signature')

    try:
        # Verify signature
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        })

        # Get user and franchise
        email = session.get('franchise_payment_email')
        franchise_user = User.query.filter_by(email=email, origin='admin_added').first()
        franchise = Franchise.query.get(franchise_user.franchise_id)

        # Update franchise status
        franchise.payment_status = 'paid'
        franchise.payment_id = payment_id
        franchise.is_active = True
        db.session.commit()

        # Send welcome email with main website link
        try:
            msg = Message(
                subject='Welcome to Kareer Studio - Account Ready!',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )

            # Generate a new temporary password for the welcome email
            temp_password = generate_password()
            
            # Update the user's password with the new temporary password
            franchise_user.password = generate_password_hash(temp_password)
            franchise_user.force_password_reset = True
            db.session.commit()

            msg.body = f"""
Congratulations! Your franchise account is now active.

Company: {franchise.company_name}
Franchise: {franchise.franchise_name}

Login Details:
Website: {request.url_root}
Email: {email}
Temporary Password: {temp_password}

You will be required to change your password on first login.

Best regards,
Kareer Studio Team
"""

            mail.send(msg)
            
        except Exception as e:
            print(f"Error sending welcome email: {e}")

        # Clear session
        session.pop('franchise_payment_email', None)

        return render_template('franchise_setup_complete.html',
                               company_name=franchise.company_name,
                               main_website=request.url_root)

    except Exception as e:
        flash('Payment verification failed. Please contact support.', 'error')
        return redirect(url_for('franchise_payment'))

@app.route('/edit_franchise/<int:id>', methods=['GET', 'POST'])
def edit_franchise(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Allow both superuser AND white-label users
    if user.role not in ['superuser', 'user']:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    franchise = Franchise.query.get_or_404(id)
    
    # White-label users can only edit franchises they created
    if user.role == 'user':
        if franchise.created_by_user_id != user.id:
            flash('Access denied. You can only edit franchises you created.', 'error')
            return redirect(url_for('manage_franchise'))
    
    if request.method == 'POST':
        franchise.franchise_name = request.form.get('franchise_name')
        franchise.company_name = request.form.get('company_name')
        franchise.address = request.form.get('address')
        franchise.phone = request.form.get('phone')
        franchise.email = request.form.get('email')
        franchise.website = request.form.get('website')
        
        # Get form values
        gst = request.form.get('gstnumber', '').strip()
        pan = request.form.get('pannumber', '').strip()

        # Only update if new value provided, otherwise keep existing
        if gst:
            franchise.gst_number = gst.upper()
        if pan:
            franchise.pan_number = pan.upper()
        
        logo = request.files.get('logo')
        if logo and logo.filename:
            if len(logo.read()) > 2 * 1024 * 1024:
                flash('Logo size should not exceed 2MB', 'error')
                return render_template('edit_franchise.html', franchise=franchise, user=user)
            logo.seek(0)
            
            if franchise.logo_filename:
                old_logo_path = os.path.join(app.root_path, 'static', franchise.logo_filename)
                if os.path.exists(old_logo_path):
                    os.remove(old_logo_path)
            
            import uuid
            file_extension = logo.filename.rsplit('.', 1)[1].lower()
            logo_filename = f"franchise_logo_{uuid.uuid4().hex[:8]}.{file_extension}"
            static_dir = os.path.join(app.root_path, 'static')
            if not os.path.exists(static_dir):
                os.makedirs(static_dir)
            logo.save(os.path.join(static_dir, logo_filename))
            franchise.logo_filename = logo_filename
        
        try:
            db.session.commit()
            flash('Franchise updated successfully!', 'success')
            return redirect(url_for('manage_franchise'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating the franchise. Please try again.', 'error')
    
    # For white-label users, pass their franchise context for logo display in navbar
    franchise_context = None
    if user.role == 'user' and user.franchise_id:
        franchise_context = db.session.get(Franchise, user.franchise_id)

    return render_template('edit_franchise.html', 
                        franchise=franchise,  # The franchise being edited
                        user=user,
                        franchise_context=franchise_context)  # The logged-in user's franchise for navbar logo

@app.route('/delete_franchise/<int:id>', methods=['POST'])
def delete_franchise(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    
    if user.role not in ['superuser', 'user']:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    franchise = Franchise.query.get_or_404(id)
    
    if user.role == 'user':
        if franchise.created_by_user_id != user.id:
            flash('Access denied. You can only delete franchises you created.', 'error')
            return redirect(url_for('manage_franchise'))
    
    try:
        # Step 1: Get all users for this franchise
        from sqlalchemy import text as sql_text
        
        # Step 2: Delete assessments using raw SQL
        db.session.execute(sql_text("DELETE FROM assessment WHERE user_id IN (SELECT id FROM user WHERE franchise_id = :fid)"), {"fid": id})
        
        # Step 3: Delete token purchases using raw SQL (ignore errors if table structure is wrong)
        try:
            db.session.execute(sql_text("DELETE FROM token_purchase WHERE franchise_id = :fid"), {"fid": id})
        except:
            pass
        
        # Step 4: Delete users using raw SQL
        db.session.execute(sql_text("DELETE FROM user WHERE franchise_id = :fid"), {"fid": id})
        
        # Step 5: Delete the franchise using raw SQL
        db.session.execute(sql_text("DELETE FROM franchise WHERE id = :fid"), {"fid": id})
        
        db.session.commit()
        flash('Franchise deleted successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('Error deleting franchise. Please try again.', 'error')
        print(f"Delete error: {str(e)}")
    
    return redirect(url_for('manage_franchise'))

@app.route('/manage_franchise')
def manage_franchise():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    
    # Allow both superuser AND white-label users
    if user.role not in ['superuser', 'user']:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if user.role == 'superuser':
        # Superuser sees only top-level franchises (no parent)
        franchises = Franchise.query.filter_by(parent_franchise_id=None).all()
    elif user.role == 'user' and user.franchise_id:
        # White-label user sees only sub-franchises they created
        franchises = Franchise.query.filter_by(parent_franchise_id=user.franchise_id).all()
    else:
        franchises = []
    
    # For white-label users, pass their franchise context for logo
    franchise_context = None
    if user.role == 'user' and user.franchise_id:
        franchise_context = db.session.get(Franchise, user.franchise_id)

    return render_template('manage_franchise.html', franchises=franchises, user=user, franchise=franchise_context)

@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Add franchise detection
    host = request.headers.get('Host', '')
    franchise = None
    if host:
        clean_host = host.split(':')[0]  # Clean the host - remove port if present
        # Try exact domain match first
        franchise = Franchise.query.filter(
            db.or_(
                Franchise.website == f"http://{clean_host}",
                Franchise.website == f"https://{clean_host}",
                Franchise.website == clean_host,
                Franchise.website == f"http://www.{clean_host}",
                Franchise.website == f"https://www.{clean_host}",
                Franchise.website == f"www.{clean_host}"
            )
        ).first()
        
        # If no exact match, try partial match as fallback
        if not franchise:
            franchise = Franchise.query.filter(
                db.or_(
                    Franchise.website.contains(clean_host),
                    Franchise.website.contains(clean_host.replace('www.', ''))
                )
            ).first()
    
    if not franchise and user.role == 'user' and user.franchise_id:
        franchise = Franchise.query.get(user.franchise_id)
    
    # Determine default center name
    default_center_name = ""
    if user.role == 'superuser':
        default_center_name = "Kareer Studio"
    elif user.role == 'user' and user.franchise_id:
        franchise_obj = Franchise.query.get(user.franchise_id)
        default_center_name = franchise_obj.company_name if franchise_obj and franchise_obj.company_name else ""
    
    # Calculate tokens left for franchise users
    tokens_left = 0
    if user.role == 'user' and user.franchise_id:
        franchise_obj = Franchise.query.get(user.franchise_id)
        
        # Check if this is a sub-franchise or white-label
        if franchise_obj.parent_franchise_id:
            # Sub-franchise: calculate from PARENT's purchases
            parent_franchise = Franchise.query.get(franchise_obj.parent_franchise_id)
            purchases = TokenPurchase.query.filter_by(
                franchise_id=parent_franchise.id,
                payment_status='completed'
            ).all()
            total_purchased = sum(p.tokens_bought for p in purchases)
            tokens_used = parent_franchise.tokens_used or 0
            tokens_left = total_purchased - tokens_used
        else:
            # White-label: calculate from own purchases
            purchases = TokenPurchase.query.filter_by(
                franchise_id=franchise_obj.id,
                payment_status='completed'
            ).all()
            total_purchased = sum(p.tokens_bought for p in purchases)
            tokens_used = franchise_obj.tokens_used or 0
            tokens_left = total_purchased - tokens_used
    
    assessment = None
    if request.method == 'POST':
        # Add token check for franchise users
        # Add token check for franchise users
        if user.role == 'user' and user.franchise_id:
            franchise_obj = Franchise.query.get(user.franchise_id)
            
            # Recalculate tokens_left before checking
            if franchise_obj.parent_franchise_id:
                parent_franchise = Franchise.query.get(franchise_obj.parent_franchise_id)
                purchases = TokenPurchase.query.filter_by(
                    franchise_id=parent_franchise.id,
                    payment_status='completed'
                ).all()
                total_purchased = sum(p.tokens_bought for p in purchases)
                tokens_used = parent_franchise.tokens_used or 0
                tokens_left = total_purchased - tokens_used
            else:
                purchases = TokenPurchase.query.filter_by(
                    franchise_id=franchise_obj.id,
                    payment_status='completed'
                ).all()
                total_purchased = sum(p.tokens_bought for p in purchases)
                tokens_used = franchise_obj.tokens_used or 0
                tokens_left = total_purchased - tokens_used
            
            if tokens_left < 1:
                new_analysis_no = generate_next_analysis_no(user)  # Generate new analysis number for the form (needed for GET rendering)
                empty_assessment = SimpleNamespace(name='', parent_name='', dob='', class_='', address='', institute='', contact='', email='', analysis_no='', center_name='')
                flash('Insufficient tokens! Please purchase tokens to add more students.', 'error')
                return render_template('add_student.html', user=user, new_analysis_no=new_analysis_no, default_center_name=default_center_name, assessment=empty_assessment, franchise=franchise, insufficient_tokens=True, tokens_left=tokens_left)
        
        data = request.form
        new_analysis_no = generate_next_analysis_no(user)  # Auto-generate analysis number instead of using user input
        
        assessment = Assessment(user_id=user.id)
        
        for hand in ['l', 'r']:
            for i in range(1, 6):
                pattern_key = f'{hand}{i}_pattern'
                rc_key = f'{hand}{i}_rc'
                setattr(assessment, pattern_key, data.get(pattern_key))
                rc_value = data.get(rc_key)
                setattr(assessment, rc_key, int(rc_value) if rc_value else None)
        
        assessment.name = data.get('name')
        assessment.parent_name = data.get('parent_name')
        assessment.dob = data.get('dob')
        assessment.class_ = data.get('class_')
        
        # validate address here
        address_input = data.get('address', '')
        if len(address_input) > 50:
            flash('Address cannot exceed 50 characters. It has been limited to 50.', 'error')
            address_input = address_input[:50]
        assessment.address = address_input
        
        assessment.institute = data.get('institute')
        assessment.contact = data.get('contact')
        assessment.email = data.get('email')
        assessment.analysis_no = new_analysis_no  # Use auto-generated number
        
        center_name_input = data.get('center_name')
        if not center_name_input:  # If form field is empty, use default
            assessment.center_name = default_center_name
        else:
            assessment.center_name = center_name_input
        
        db.session.add(assessment)
        
        # Deduct token for franchise users AFTER successful student addition
        if user.role == 'user' and user.franchise_id:
            if franchise_obj.parent_franchise_id:
                # Sub-franchise: deduct from PARENT's pool
                parent_franchise = Franchise.query.get(franchise_obj.parent_franchise_id)
                if parent_franchise:
                    parent_franchise.tokens_used = (parent_franchise.tokens_used or 0) + 1
            else:
                # White-label: deduct from own pool
                franchise_obj.tokens_used += 1
        
        db.session.commit()
        flash('Student assessment saved successfully!')
        return render_template('add_student.html', assessment=assessment, user=user, franchise=franchise, tokens_left=tokens_left)
    else:
        # Create empty assessment-like object with attributes for template
        new_analysis_no = generate_next_analysis_no(user)  # Generate new analysis number for the form (needed for GET rendering)
        empty_assessment = SimpleNamespace(name='', parent_name='', dob='', class_='', address='', institute='', contact='', email='', analysis_no='', center_name='')
        return render_template('add_student.html', user=user, new_analysis_no=new_analysis_no, default_center_name=default_center_name, assessment=empty_assessment, franchise=franchise, tokens_left=tokens_left)

@app.route('/edit_student/<int:id>', methods=['GET', 'POST'])
def edit_student(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    assessment = Assessment.query.get_or_404(id)
    
    if user.role != 'superuser' and assessment.user_id != user.id:
        flash('Access denied')
        return redirect(url_for('manage_student'))
    
    # Add franchise detection
    host = request.headers.get('Host', '')
    franchise = None
    
    if host:
        # Clean the host - remove port if present
        clean_host = host.split(':')[0]
        
        # Try exact domain match first
        franchise = Franchise.query.filter(
            db.or_(
                Franchise.website == f'http://{clean_host}',
                Franchise.website == f'https://{clean_host}',
                Franchise.website == clean_host,
                Franchise.website == f'http://www.{clean_host}',
                Franchise.website == f'https://www.{clean_host}',
                Franchise.website == f'www.{clean_host}'
            )
        ).first()
        
        # If no exact match, try partial match as fallback
        if not franchise:
            franchise = Franchise.query.filter(
                db.or_(
                    Franchise.website.contains(clean_host),
                    Franchise.website.contains(clean_host.replace('www.', ''))
                )
            ).first()
    
    if not franchise and user.role == 'user' and user.franchise_id:
        franchise = Franchise.query.get(user.franchise_id)
    
    # Determine default center name for this route too
    default_center_name = ""
    if user.role == "superuser":
        default_center_name = "Kareer Studio"
    elif user.role == "user" and user.franchise_id:
        franchise_obj = Franchise.query.get(user.franchise_id)
        default_center_name = franchise_obj.company_name if franchise_obj and franchise_obj.company_name else ""
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update':
            data = request.form
            
            assessment.name = data.get('name')
            assessment.parent_name = data.get('parent_name')
            assessment.dob = data.get('dob')
            assessment.class_ = data.get('class')
            assessment.address = data.get('address')
            assessment.institute = data.get('institute')
            assessment.contact = data.get('contact')
            assessment.email = data.get('email')
            assessment.analysis_no = data.get('analysis_no')
            
            # Center Name (FIXED for superuser)
            if user.role == 'superuser':
                assessment.center_name = "Kareer Studio"
            else:
                center_name_input = data.get('center_name')
                if not center_name_input:
                    assessment.centername = default_center_name
                else:
                    assessment.centername = center_name_input
            
            for hand in ['l', 'r']:
                for i in range(1, 6):
                    pattern_key = f"{hand}{i}_pattern"
                    rc_key = f"{hand}{i}_rc"
                    setattr(assessment, pattern_key, data.get(pattern_key))
                    rc_value = data.get(rc_key)
                    setattr(assessment, rc_key, int(rc_value) if rc_value else None)
            
            db.session.commit()
            flash('Student assessment updated successfully!', 'success')
            return redirect(url_for('manage_student'))
        
        elif action == 'calculate':
            return redirect(url_for('calculation_result'), code=307)
    
    return render_template('edit_student.html', assessment=assessment, user=user, franchise=franchise)


@app.route('/delete_student/<int:id>', methods=['POST'])
def delete_student(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    assessment = Assessment.query.get_or_404(id)
    db.session.delete(assessment)
    db.session.commit()
    flash('Student assessment deleted successfully!')
    return redirect(url_for('manage_student'))

@app.route('/manage_student')
def manage_student():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Add franchise detection
    host = request.headers.get('Host', '')
    franchise = None
    
    if host:
        # Clean the host - remove port if present
        clean_host = host.split(':')[0]
        
        # Try exact domain match first
        franchise = Franchise.query.filter(
            db.or_(
                Franchise.website == f'http://{clean_host}',
                Franchise.website == f'https://{clean_host}',
                Franchise.website == clean_host,
                Franchise.website == f'http://www.{clean_host}',
                Franchise.website == f'https://www.{clean_host}',
                Franchise.website == f'www.{clean_host}'
            )
        ).first()
        
        # If no exact match, try partial match as fallback
        if not franchise:
            franchise = Franchise.query.filter(
                db.or_(
                    Franchise.website.contains(clean_host),
                    Franchise.website.contains(clean_host.replace('www.', ''))
                )
            ).first()
    
    if not franchise and user.role == 'user' and user.franchise_id:
        franchise = Franchise.query.get(user.franchise_id)
    
    assessments = Assessment.query.all() if user.role == 'superuser' else Assessment.query.filter_by(user_id=user.id).all()
    
    return render_template('manage_student.html', assessments=assessments, user=user, franchise=franchise)

@app.route('/search_students')
def search_students():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    search_term = request.args.get('query', '').strip()
    
    # Get base query based on user role
    if user.role == 'superuser':
        query = Assessment.query
    else:
        query = Assessment.query.filter_by(user_id=user.id)
    
    # Apply search filter if search term exists
    if search_term:
        query = query.filter(Assessment.name.ilike(f'%{search_term}%'))
    
    assessments = query.all()
    
    # Convert to JSON format with email included
    results = []
    for assessment in assessments:
        results.append({
            'id': assessment.id,
            'analysis_no': assessment.analysis_no or '-',
            'name': assessment.name or '-',
            'parent_name': assessment.parent_name or '-',
            'dob': assessment.dob or '-',
            'class_': assessment.class_ or '-',
            'institute': assessment.institute or '-',
            'contact': assessment.contact or '-',
            'email': assessment.email or '-'
        })
    
    return jsonify({'results': results, 'count': len(results)})

@app.route('/search_franchises')
def search_franchises():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user = User.query.get(session['user_id'])
    
    # Only superusers can search franchises
    if user.role != 'superuser':
        return jsonify({'error': 'Access denied'}), 403

    search_term = request.args.get('query', '').strip()

    # Get base query
    query = Franchise.query

    # Apply search filter if search term exists
    if search_term:
        query = query.filter(
            db.or_(
                Franchise.franchise_name.ilike(f'%{search_term}%'),
                Franchise.company_name.ilike(f'%{search_term}%'),
                Franchise.email.ilike(f'%{search_term}%'),
                Franchise.phone.ilike(f'%{search_term}%')
            )
        )

    franchises = query.all()

    # Convert to JSON format
    results = []
    for franchise in franchises:
        results.append({
            'id': franchise.id,
            'franchise_name': franchise.franchise_name or '-',
            'company_name': franchise.company_name or '-',
            'email': franchise.email or '-',
            'phone': franchise.phone or '-',
            'address': franchise.address or '-',
            'gst_number': franchise.gst_number or '-',
            'pan_number': franchise.pan_number or '-'
        })

    return jsonify({'results': results, 'count': len(results)})

def consolidate_career_recommendations(highly_recommended, recommended):
    """
    Consolidate career categories into domain names when all categories 
    of a domain are present in the same section
    """
    try:
        # Read the career domains CSV
        domain_df = pd.read_csv('Global_Career_Categories_Final.csv')
        
        # Create mapping from domain to its categories
        domain_to_categories = {}
        for _, row in domain_df.iterrows():
            domain = str(row['Career Domains']).strip()
            category = str(row['Career Categories']).strip()
            
            if pd.notna(row['Career Domains']) and pd.notna(row['Career Categories']):
                if domain not in domain_to_categories:
                    domain_to_categories[domain] = set()
                domain_to_categories[domain].add(category)
        
        # Convert to sets for easier processing
        highly_rec_set = set(highly_recommended)
        recommended_set = set(recommended)
        
        # Track domains to replace
        highly_rec_domains = []
        recommended_domains = []
        
        # Check each domain
        for domain, categories in domain_to_categories.items():
            # Check if ALL categories are in highly_recommended
            if categories.issubset(highly_rec_set):
                highly_rec_domains.append(domain)
                # Remove individual categories from the set
                highly_rec_set -= categories
            
            # Check if ALL categories are in recommended (and not already handled above)
            elif categories.issubset(recommended_set):
                recommended_domains.append(domain)
                # Remove individual categories from the set
                recommended_set -= categories
        
        # Build final lists - DON'T sort alphabetically, maintain percentage order
        final_highly_recommended = highly_rec_domains + list(highly_rec_set)
        final_recommended = recommended_domains + list(recommended_set)

        return {
            'highly_recommended': final_highly_recommended,
            'recommended': final_recommended
        }

    except Exception as e:
        print(f"Error in domain consolidation: {e}")
        # Return original lists if consolidation fails
        return {
            'highly_recommended': highly_recommended,
            'recommended': recommended
        }


def calculate_career_recommendations(percentages_display, rc_values, total_rc):
    try:
        career_df = pd.read_csv('Global_Career_Categories_Temp.csv')
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return {'highly_recommended': [], 'recommended': []}

    finger_mapping = {
        'r1': 'Management',
        'r2': 'Logic',
        'r3': 'Body Balance',
        'r4': 'Communication',
        'r5': 'Observation',
        'l1': 'Leadership',
        'l2': 'Visual',
        'l3': 'Body Movement',
        'l4': 'Rhythm',
        'l5': 'Physical Senses'
    }

    def convert_to_numeric(value):
        if value == 'X':
            if total_rc > 0:
                return round((24 / total_rc) * 100, 2)
            else:
                return 0
        try:
            return float(value)
        except:
            return 0

    # Store careers with their calculated scores
    career_scores = []

    for _, row in career_df.iterrows():
        career_name = str(row.iloc[0]).strip()
        if not career_name or career_name.lower() == 'nan':
            continue

        required_traits = []
        for col_idx in range(1, len(row)):
            if pd.notna(row.iloc[col_idx]) and str(row.iloc[col_idx]).strip() != '':
                required_traits.append(str(row.iloc[col_idx]).strip())

        trait_values = []
        for trait in required_traits:
            finger_key = None
            for k, v in finger_mapping.items():
                if v.lower() == trait.lower():
                    finger_key = k
                    break

            if finger_key and finger_key in percentages_display:
                val = percentages_display[finger_key]
                num_val = convert_to_numeric(val)
                trait_values.append(num_val)
            else:
                trait_values.append(0)

        if not trait_values:
            continue

        avg_value = sum(trait_values) / len(trait_values)
        career_scores.append({'name': career_name, 'score': avg_value})

    # Sort careers by score (percentage) highest first
    career_scores.sort(key=lambda x: x['score'], reverse=True)

    # Separate by score threshold
    highly_recommended = [item['name'] for item in career_scores if item['score'] >= 10]
    recommended = [item['name'] for item in career_scores if 9 <= item['score'] < 10]

    # Apply domain consolidation
    consolidated = consolidate_career_recommendations(highly_recommended, recommended)

    # DO NOT sort consolidated lists alphabetically. Keep original order as returned from consolidation

    # For screen/list views - show all, in percentage order (no slicing)
    all_highly_recommended = consolidated['highly_recommended']
    all_recommended = consolidated['recommended']

    # For PDF - show only first 20, in percentage order
    pdf_highly_recommended = all_highly_recommended[:20]
    pdf_recommended = all_recommended[:20]

    return {
        'highly_recommended': all_highly_recommended,  # use this for screen
        'recommended': all_recommended,                # use this for screen
        'pdf_highly_recommended': pdf_highly_recommended,  # use this for PDF
        'pdf_recommended': pdf_recommended                 # use this for PDF
    }

def generate_filled_pdf(student_data, percentages_display, rc_values, total_rc,
                        left_brain_result, right_brain_result, achievement_styles,
                        kin_result, aud_result, vis_result, work_ability_results,
                        personality_features, career_recommendations, franchise=None):
    try:
        current_user = None
        if 'user_id' in session:
            current_user = db.session.get(User, session['user_id'])
        
        # Determine template and franchise details based on user role and franchise hierarchy
            # Determine template and franchise details based on user role and franchise hierarchy
        template_path = "Brainography_Template_Blank.pdf"  # Default
        include_franchise_details = False  # Default
        franchise_for_display = None  # Will store the franchise whose details to show
        
        if current_user:
            if current_user.role == 'user' and current_user.franchise_id:
                # User is franchise or sub-franchise
                franchise_obj = db.session.get(Franchise, current_user.franchise_id)
                
                if franchise_obj:
                    if franchise_obj.parent_franchise_id:
                        # Sub-franchise: use IKIGAI template with PARENT franchise details
                        template_path = "Brainography_IKIGAI.pdf"
                        include_franchise_details = True
                        # Get parent franchise for displaying details
                        franchise_for_display = db.session.get(Franchise, franchise_obj.parent_franchise_id)
                    else:
                        # White-label (no parent): use IKIGAI template with own details
                        template_path = "Brainography_IKIGAI.pdf"
                        include_franchise_details = True
                        # Use own franchise for displaying details
                        franchise_for_display = franchise_obj
        
        template_pdf = PdfReader(template_path)
        overlay_buffer = io.BytesIO()
        c = canvas.Canvas(overlay_buffer, pagesize=A4)
        width, height = A4

        # Store content for each page
        page_contents = {}

        # Helper function to store content for a page
        def store_content(page_num, content_type, x, y, text, font_size=10, box_width=60):
            if page_num not in page_contents:
                page_contents[page_num] = []
            page_contents[page_num].append({
                'type': content_type,
                'x': x, 'y': y, 'text': text,
                'font_size': font_size, 'box_width': box_width
            })

        # FRANCHISE-SPECIFIC ADDITIONS (ONLY if include_franchise_details is True)
        if include_franchise_details and franchise_for_display:
            logo_to_use = franchise_for_display.logo_filename
            website_to_use = franchise_for_display.website
            franchise_name_to_use = franchise_for_display.franchise_name
            phone_to_use = franchise_for_display.phone
            address_to_use = franchise_for_display.address
            email_to_use = franchise_for_display.email

            
            # Now use the determined values for PDF
            if logo_to_use:
                store_content(1, 'logo_large', 60, 720, os.path.join('static', logo_to_use), 150, 100)
            
            if franchise_name_to_use:
                store_content(1, 'left_text', 60, 190, f"{franchise_name_to_use}", 20)
            
            # Add phone number on page 1
            if phone_to_use:
                store_content(1, 'left_text', 60, 103, f"{phone_to_use}", 15)
            
            # Add website link on page 1
            if website_to_use:
                store_content(1, 'left_text', 60, 85, website_to_use, 15)

            # PAGE 2: Add Franchise Name
            if franchise_name_to_use:
                store_content(2, 'left_text', 60, 87, f"{franchise_name_to_use}", 11)

            # PAGE 33: Add Franchise Name
            if franchise_name_to_use:
                store_content(30, 'left_text', 59, 150, f"{franchise_name_to_use}", 12)

            # ADD LOGO AND WEBSITE ON EVERY PAGE (1-32)
            # ADD LOGO AND WEBSITE ON EVERY PAGE (1-32)
            total_template_pages = len(template_pdf.pages)
            for page_num in range(2, total_template_pages):
                # Add franchise logo at top-right corner
                if logo_to_use:
                    logo_path = os.path.join('static', logo_to_use)
                    store_content(page_num, 'logo', 440, 760, logo_path, 100, 70)
                
                # Add website link at top-right area
                if website_to_use:
                    store_content(page_num, 'centered_text', 250, 28, website_to_use, 12)

            # PAGE 32: Add complete franchise details
            if total_template_pages >= 32:
                if address_to_use:
                    address_lines = [line.strip() for line in address_to_use.split(',') if line.strip()]
                    y_position = 301
                    for line in address_lines:
                        store_content(32, 'left_text', 87, y_position, line, 12)
                        y_position -= 12  # Move down for next line (12 points spacing)
                store_content(32, 'left_text', 110, 206, f"{phone_to_use or ''}", 12)
                store_content(32, 'left_text', 110, 179, f"{email_to_use or ''}", 12)
                store_content(32, 'left_text', 110, 154, f"{website_to_use or ''}", 12)
                
                # Add larger logo on page 32
                if logo_to_use:
                    logo_path = os.path.join('static', logo_to_use)
                    store_content(32, 'logo', 70, 320, logo_path, 100, 70)

        # PAGE 3 - PERSONAL DETAILS (ALWAYS ADD - regardless of template)
        store_content(3, 'left_text', 210, 725, student_data.get('analysis_no', ''), 14)
        store_content(3, 'left_text', 210, 689, student_data.get('name', ''), 14)
        store_content(3, 'left_text', 210, 654, student_data.get('parent_name', ''), 14)
        store_content(3, 'left_text', 210, 617, student_data.get('dob', ''), 14)
        store_content(3, 'left_text', 210, 581, student_data.get('class', ''), 14)
        store_content(3, 'left_text', 210, 545, student_data.get('institute', ''), 14)
        store_content(3, 'left_text', 210, 508, student_data.get('contact', ''), 14)
        store_content(3, 'left_text', 210, 471, student_data.get('email', ''), 14)
        store_content(3, 'left_text', 210, 436, student_data.get('address', ''), 12)
        store_content(3, 'left_text', 210, 393, student_data.get('center_name', ''), 14)

        # PAGE 8 - FINGER PERCENTAGES (ALWAYS ADD)
        # Right hand fingers (R1-R5)
        store_content(8, 'centered_text', 180, 652, f"{percentages_display.get('r1', 'X')}{'%' if percentages_display.get('l1') != 'X' else ''}", 14, 80)
        store_content(8, 'centered_text', 180, 525, f"{percentages_display.get('r2', 'X')}{'%' if percentages_display.get('l2') != 'X' else ''}", 14, 80)
        store_content(8, 'centered_text', 180, 400, f"{percentages_display.get('r3', 'X')}{'%' if percentages_display.get('l3') != 'X' else ''}", 14, 80)
        store_content(8, 'centered_text', 180, 277, f"{percentages_display.get('r4', 'X')}{'%' if percentages_display.get('l4') != 'X' else ''}", 14, 80)
        store_content(8, 'centered_text', 180, 152, f"{percentages_display.get('r5', 'X')}{'%' if percentages_display.get('l5') != 'X' else ''}", 14, 80)

        # Left hand fingers (L1-L5)
        store_content(8, 'centered_text', 334, 652, f"{percentages_display.get('l1', 'X')}{'%' if percentages_display.get('r1') != 'X' else ''}", 14, 80)
        store_content(8, 'centered_text', 334, 525, f"{percentages_display.get('l2', 'X')}{'%' if percentages_display.get('r2') != 'X' else ''}", 14, 80)
        store_content(8, 'centered_text', 334, 400, f"{percentages_display.get('l3', 'X')}{'%' if percentages_display.get('r3') != 'X' else ''}", 14, 80)
        store_content(8, 'centered_text', 334, 277, f"{percentages_display.get('l4', 'X')}{'%' if percentages_display.get('r4') != 'X' else ''}", 14, 80)
        store_content(8, 'centered_text', 334, 152, f"{percentages_display.get('l5', 'X')}{'%' if percentages_display.get('r5') != 'X' else ''}", 14, 80)

        # PAGE 9 & 10 - THINKING PATTERN (ALWAYS ADD)
        store_content(9, 'centered_text', 69, 502, left_brain_result, 14, 100)
        store_content(10, 'centered_text', 69, 502, right_brain_result, 14, 100)

        # PAGE 11 - WORK ABILITY QUOTIENTS (ALWAYS ADD)
        store_content(11, 'centered_text', 405, 679, work_ability_results.get('iq', ''), 14, 80)
        store_content(11, 'centered_text', 405, 572, work_ability_results.get('eq', ''), 14, 80)
        store_content(11, 'centered_text', 405, 469, work_ability_results.get('cq', ''), 14, 80)
        store_content(11, 'centered_text', 405, 360, work_ability_results.get('vq', ''), 14, 80)
        store_content(11, 'centered_text', 405, 254, work_ability_results.get('aq', ''), 14, 80)

        # PAGES 12-16 - INDIVIDUAL WORK ABILITY PAGES (ALWAYS ADD)
        store_content(12, 'centered_text', 409, 708, work_ability_results.get('iq', ''), 14, 80)
        store_content(13, 'centered_text', 411, 708, work_ability_results.get('eq', ''), 14, 80)
        store_content(14, 'centered_text', 408, 708, work_ability_results.get('cq', ''), 14, 80)
        store_content(15, 'centered_text', 408, 708, work_ability_results.get('vq', ''), 14, 80)
        store_content(16, 'centered_text', 408, 708, work_ability_results.get('aq', ''), 14, 80)

        # PAGE 17 - ACHIEVEMENT STYLES (ALWAYS ADD)
        store_content(17, 'centered_text', 439, 653, achievement_styles.get('follower', ''), 14, 80)
        store_content(17, 'centered_text', 439, 522, achievement_styles.get('experimental', ''), 14, 80)
        store_content(17, 'centered_text', 439, 390, achievement_styles.get('different', ''), 14, 80)
        store_content(17, 'centered_text', 439, 262, achievement_styles.get('thoughtful', ''), 14, 80)

        # PAGES 18-21 - INDIVIDUAL ACHIEVEMENT STYLE PAGES (ALWAYS ADD)
        store_content(18, 'centered_text', 119, 592, achievement_styles.get('follower', ''), 14, 80)
        store_content(19, 'centered_text', 122, 560, achievement_styles.get('experimental', ''), 14, 80)
        store_content(20, 'centered_text', 122, 592, achievement_styles.get('different', ''), 14, 80)
        store_content(21, 'centered_text', 122, 560, achievement_styles.get('thoughtful', ''), 14, 80)

        # PAGE 22 - LEARNING STYLES (ALWAYS ADD)
        store_content(22, 'centered_text', 180, 634, aud_result, 14, 80)
        store_content(22, 'centered_text', 468, 530, vis_result, 14, 80)
        store_content(22, 'centered_text', 175, 422, kin_result, 14, 80)

        # PAGE 23 - PERSONALITY CHECKMARKS (ALWAYS ADD)
        if personality_features:
            for feature_name, sub_features in personality_features.items():
                if sub_features and any(sub_features.values()):
                    if 'STEADY' in feature_name.upper():
                        store_content(23, 'centered_text', 329, 577, "✓", 16, 40)
                    elif 'DOMINANT' in feature_name.upper():
                        store_content(23, 'centered_text', 81, 577, "✓", 16, 40)
                    elif 'INFLUENTIAL' in feature_name.upper():
                        store_content(23, 'centered_text', 205, 577, "✓", 16, 40)
                    elif 'CONSCIOUS' in feature_name.upper():
                        store_content(23, 'centered_text', 453, 577, "✓", 16, 40)

        # PAGE 28 - CAREER RECOMMENDATIONS (ALWAYS ADD)
        store_content(28, 'career_list', 50, 698, career_recommendations.get('highly_recommended', []), 20, 15)
        store_content(28, 'career_list', 325, 700, career_recommendations.get('recommended', []), 20, 15)

        # Now create pages and add content
        total_template_pages = len(template_pdf.pages)
        current_page = 1

        for page_num in range(1, total_template_pages + 1):
            if page_num > 1:
                c.showPage()

            # Add content for this page
            if page_num in page_contents:
                for content in page_contents[page_num]:
                    if content['type'] == 'left_text':
                        c.setFont("Helvetica", content['font_size'])
                        c.drawString(content['x'], content['y'], str(content['text']) if content['text'] else "")
                    elif content['type'] == 'centered_text':
                        c.setFont("Helvetica-Bold", content['font_size'])
                        text_str = str(content['text']) if content['text'] else ""
                        text_width = c.stringWidth(text_str, "Helvetica-Bold", content['font_size'])
                        centered_x = content['x'] - (text_width / 2) + (content['box_width'] / 2)
                        c.drawString(centered_x, content['y'], text_str)
                    elif content['type'] == 'logo' or content['type'] == 'logo_large':
                        try:
                            if os.path.exists(content['text']):
                                width_img = content['font_size']  # Using font_size as width
                                height_img = content['box_width']  # Using box_width as height
                                c.drawImage(content['text'], content['x'], content['y'],
                                           width=width_img, height=height_img,
                                           mask='auto', preserveAspectRatio=True)
                        except Exception:
                            pass
                    elif content['type'] == 'career_list':
                        careers = content['text']
                        max_items = content['font_size']
                        line_height = content['box_width']
                        x_start = content['x']
                        y_start = content['y']
                        c.setFont("Helvetica", 10)
                        y = y_start
                        item_count = 0

                        for career in careers:
                            if item_count >= max_items:
                                break
                            c.drawString(x_start, y, f"• {career}")
                            y -= line_height
                            item_count += 1

        c.save()

        # Create overlay PDF
        overlay_buffer.seek(0)
        overlay_pdf = PdfReader(overlay_buffer)

        # Merge template with overlay
        output_pdf = PdfWriter()

        for i in range(len(template_pdf.pages)):
            template_page = template_pdf.pages[i]
            if i < len(overlay_pdf.pages):
                overlay_page = overlay_pdf.pages[i]
                template_page.merge_page(overlay_page)
            output_pdf.add_page(template_page)

        # Write final PDF to buffer
        final_buffer = io.BytesIO()
        output_pdf.write(final_buffer)
        final_buffer.seek(0)

        return final_buffer

    except Exception as e:
        print(f"Error in generate_filled_pdf: {str(e)}")
        return None

def add_career_list_to_pdf(c, page_num, x_start, y_start, max_items, line_height, careers):
    """Add career list to PDF with left alignment and bullets"""
    while c.getPageNumber() < page_num:
        c.showPage()
    c.setFont("Helvetica", 10)
    c.setFillColor(black)
    y = y_start
    item_count = 0
    for career in careers:
        if item_count >= max_items:
            break
        # Add bullet before career name for PDF formatting
        c.drawString(x_start, y, f"• {career}")
        y -= line_height
        item_count += 1

def create_fallback_pdf(student_data, percentages_display, rc_values, total_rc,
                       left_brain_result, right_brain_result, achievement_styles,
                       kin_result, aud_result, vis_result, work_ability_results,
                       personality_features, career_recommendations):
    """Fallback PDF creation if template is not available"""
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    
    # Simple PDF generation as fallback
    c.setFont("Helvetica-Bold", 16)
    c.drawString(200, 750, "BRAINOGRAPHY REPORT")
    
    c.setFont("Helvetica", 12)
    y_pos = 700
    
    # Student details
    details = [
        f"Name: {student_data.get('name', '')}",
        f"Analysis No: {student_data.get('analysis_no', '')}",
        f"Left Brain: {left_brain_result}",
        f"Right Brain: {right_brain_result}",
        f"Learning Style - Auditory: {aud_result}",
        f"Learning Style - Visual: {vis_result}",
        f"Learning Style - Kinesthetic: {kin_result}"
    ]
    
    for detail in details:
        c.drawString(50, y_pos, detail)
        y_pos -= 20
    
    # Career recommendations
    y_pos -= 30
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y_pos, "CAREER RECOMMENDATIONS:")
    y_pos -= 20
    
    c.setFont("Helvetica", 10)
    if career_recommendations.get('highly_recommended'):
        c.drawString(50, y_pos, "Highly Recommended:")
        y_pos -= 15
        for career in career_recommendations['highly_recommended'][:10]:
            c.drawString(70, y_pos, f"• {career}")
            y_pos -= 12
    
    c.save()
    buffer.seek(0)
    return buffer

def generate_next_analysis_no(user=None):
    """Generate the next analysis number based on user role and franchise company name"""
    prefix = 'KS'
    
    if user and user.role == 'user' and user.franchise_id:
        franchise = Franchise.query.get(user.franchise_id)
        if franchise and franchise.company_name:
            # Get clean company name
            company_name = franchise.company_name.strip().upper()
            words = company_name.split()
            
            # Basic prefix generation (first approach)
            if len(words[0]) >= 2:
                base_prefix = words[0][:2]
            elif len(words[0]) == 1 and len(words) > 1 and len(words[1]) >= 1:
                base_prefix = words[0][0] + words[1][0]
            else:
                base_prefix = words[0][:2]  # fallback
            
            # Check if this prefix is already used by other franchises
            existing_companies = db.session.query(Franchise.company_name, Franchise.franchise_name).all()
            same_names = [f for f in existing_companies if f[0] and f[0].lower() == company_name.lower() or f[1] and f[1].lower() == company_name.lower()]
            
            # Generate unique letter combination for same company names
            occurrence = 1
            for existing_franchise in same_names:
                existing_franchise_obj = Franchise.query.filter(
                    db.or_(
                        Franchise.company_name == existing_franchise[0],
                        Franchise.franchise_name == existing_franchise[1]
                    )
                ).first()
                
                if existing_franchise_obj and existing_franchise_obj.id < franchise.id:
                    occurrence += 1
            
            # Generate different letter combinations based on occurrence
            clean_name = ''.join(c for c in company_name if c.isalpha()).upper()
            
            if occurrence == 1:
                # First occurrence: use first two letters
                prefix = base_prefix
            elif occurrence == 2:
                # Second occurrence: use first and third letter
                if len(clean_name) >= 3:
                    prefix = clean_name[0] + clean_name[2]
                else:
                    prefix = base_prefix[0] + 'T'  # T for "Two"
            elif occurrence == 3:
                # Third occurrence: use second and third letter
                if len(clean_name) >= 3:
                    prefix = clean_name[1:3]
                else:
                    prefix = base_prefix[0] + 'H'  # H for "tHird"
            elif occurrence == 4:
                # Fourth occurrence: use first and last letter
                if len(clean_name) >= 2:
                    prefix = clean_name[0] + clean_name[-1]
                else:
                    prefix = base_prefix[0] + 'F'  # F for "Fourth"
            else:
                # For 5th+ occurrences: use combination with number
                prefix = base_prefix[0] + str(occurrence - 1)
                if len(prefix) < 2:
                    prefix += 'X'
                prefix = prefix[:2]  # Ensure only 2 characters
                
        else:
            prefix = 'FR'  # fallback prefix for franchises without company name
    else:
        prefix = 'KS'  # Superuser prefix

    # Find the maximum existing analysis number with this prefix
    max_existing = 0
    all_analysis = Assessment.query.with_entities(Assessment.analysis_no).all()
    for (anum,) in all_analysis:
        if anum and anum.startswith(prefix):
            try:
                num_part = anum[len(prefix):]
                num = int(num_part)
                if num > max_existing:
                    max_existing = num
            except ValueError:
                pass
    
    next_num = max_existing + 1
    return f"{prefix}{str(next_num).zfill(4)}"

def calculate_achievement_styles(assessment):
    patterns = []
    for hand in ['l', 'r']:
        for i in range(1, 6):
            pattern = getattr(assessment, f'{hand}{i}_pattern')
            if pattern:
                patterns.append(pattern.upper())
    
    follower_count = sum(1 for p in patterns if p == 'UL' or p == 'FL')
    experimental_count = sum(1 for p in patterns if p.startswith('W'))
    different_count = sum(1 for p in patterns if p == 'RL')
    thoughtful_count = sum(1 for p in patterns if p.startswith('A'))
    
    results = {
        'follower': f'{follower_count * 10}%',
        'experimental': f'{experimental_count * 10}%',
        'different': f'{different_count * 10}%',
        'thoughtful': f'{thoughtful_count * 10}%'
    }
    return results

def calculate_learning_communication_style(percentages):
    fingers_tp = ['l3', 'l4', 'l5', 'r3', 'r4', 'r5']
    tp = 0
    for finger in fingers_tp:
        val = percentages.get(finger)
        if val != 'X':
            tp += val
    tp = round(tp, 3)

    # Kinesthetic
    kin_fingers = ['l3', 'r3']
    A_kin = 0
    B_kin = 0
    for finger in kin_fingers:
        val = percentages.get(finger)
        if val == 'X':
            B_kin += 1
        else:
            A_kin += val
    
    if tp > 0:
        A_kin = round((A_kin / tp) * 100, 2)
    else:
        A_kin = 0
    
    if B_kin > 0:
        if A_kin > 0:
            kin_result = f"{A_kin}+{B_kin}X"
        else:
            kin_result = f"{B_kin}X"
    else:
        kin_result = f"{A_kin}"

    # Auditory
    aud_fingers = ['l4', 'r4']
    A_aud = 0
    B_aud = 0
    for finger in aud_fingers:
        val = percentages.get(finger)
        if val == 'X':
            B_aud += 1
        else:
            A_aud += val
    
    if tp > 0:
        A_aud = round((A_aud / tp) * 100, 2)
    else:
        A_aud = 0
    
    if B_aud > 0:
        if A_aud > 0:
            aud_result = f"{A_aud}+{B_aud}X"
        else:
            aud_result = f"{B_aud}X"
    else:
        aud_result = f"{A_aud}"

    # Visual
    vis_fingers = ['l5', 'r5']
    A_vis = 0
    B_vis = 0
    for finger in vis_fingers:
        val = percentages.get(finger)
        if val == 'X':
            B_vis += 1
        else:
            A_vis += val
    
    if tp > 0:
        A_vis = round((A_vis / tp) * 100, 2)
    else:
        A_vis = 0
    
    if B_vis > 0:
        if A_vis > 0:
            vis_result = f"{A_vis}+{B_vis}X"
        else:
            vis_result = f"{B_vis}X"
    else:
        vis_result = f"{A_vis}"

    return kin_result, aud_result, vis_result

def calculate_work_ability_style(percentages):
    results = {}
    
    # IQ
    iq_fingers = ['r2', 'r4']
    A_iq = 0
    B_iq = 0
    for finger in iq_fingers:
        val = percentages.get(finger)
        if val == 'X':
            B_iq += 1
        else:
            A_iq += val
    A_iq = round(A_iq, 2)
    if B_iq > 0:
        if A_iq > 0:
            results['iq'] = f"{A_iq}+{B_iq}X"
        else:
            results['iq'] = f"{B_iq}X"
    else:
        results['iq'] = f"{A_iq}"

    # AQ
    aq_fingers = ['r5', 'l3']
    A_aq = 0
    B_aq = 0
    for finger in aq_fingers:
        val = percentages.get(finger)
        if val == 'X':
            B_aq += 1
        else:
            A_aq += val
    A_aq = round(A_aq, 2)
    if B_aq > 0:
        if A_aq > 0:
            results['aq'] = f"{A_aq}+{B_aq}X"
        else:
            results['aq'] = f"{B_aq}X"
    else:
        results['aq'] = f"{A_aq}"

    # CQ
    cq_fingers = ['l2', 'l4']
    A_cq = 0
    B_cq = 0
    for finger in cq_fingers:
        val = percentages.get(finger)
        if val == 'X':
            B_cq += 1
        else:
            A_cq += val
    A_cq = round(A_cq, 2)
    if B_cq > 0:
        if A_cq > 0:
            results['cq'] = f"{A_cq}+{B_cq}X"
        else:
            results['cq'] = f"{B_cq}X"
    else:
        results['cq'] = f"{A_cq}"

    # EQ
    eq_fingers = ['r1', 'l1']
    A_eq = 0
    B_eq = 0
    for finger in eq_fingers:
        val = percentages.get(finger)
        if val == 'X':
            B_eq += 1
        else:
            A_eq += val
    A_eq = round(A_eq, 2)
    if B_eq > 0:
        if A_eq > 0:
            results['eq'] = f"{A_eq}+{B_eq}X"
        else:
            results['eq'] = f"{B_eq}X"
    else:
        results['eq'] = f"{A_eq}"

    # VQ
    vq_fingers = ['r3', 'l5']
    A_vq = 0
    B_vq = 0
    for finger in vq_fingers:
        val = percentages.get(finger)
        if val == 'X':
            B_vq += 1
        else:
            A_vq += val
    A_vq = round(A_vq, 2)
    if B_vq > 0:
        if A_vq > 0:
            results['vq'] = f"{A_vq}+{B_vq}X"
        else:
            results['vq'] = f"{B_vq}X"
    else:
        results['vq'] = f"{A_vq}"

    return results

def calculate_personality_features(assessment):
    personality = {}
    r1_pattern = (getattr(assessment, 'r1_pattern') or '').upper()
    l1_pattern = (getattr(assessment, 'l1_pattern') or '').upper()
    
    steady_features = {}
    dominant_features = {}
    influential_features = {}
    conscious_features = {}
    
    # Steady features
    if l1_pattern == 'UL' and r1_pattern in ['UL', 'FL']:
        steady_features['Assertive'] = True
    if l1_pattern == 'UL' and r1_pattern == 'RL':
        steady_features['Different'] = True
    if l1_pattern == 'UL' and r1_pattern.startswith('A'):
        steady_features['Unpredictable'] = True
    if l1_pattern == 'UL' and r1_pattern in ['WS', 'WT', 'WX', 'WE']:
        steady_features['Aggressive'] = True
    if l1_pattern == 'UL' and r1_pattern in ['WC', 'WD', 'WI']:
        steady_features['Smart'] = True
    if l1_pattern == 'UL' and r1_pattern == 'WL':
        steady_features['Wizard'] = True
    if l1_pattern == 'UL' and r1_pattern == 'WP':
        steady_features['Genius'] = True
    if l1_pattern in ['RL', 'FL'] and r1_pattern in ['RL', 'UL', 'WI', 'WS']:
        steady_features['Assertive'] = True
    if l1_pattern in ['RL, FL'] and r1_pattern in ['AS', 'AT', 'AR']:
        steady_features['Different'] = True
    if l1_pattern in ['RL', 'FL'] and r1_pattern == 'FL' :
        steady_features['Unpredictable'] = True
    if l1_pattern in ['RL', 'FL'] and r1_pattern in ['WD', 'WE', 'WL']:
        steady_features['Aggressive'] = True
    if l1_pattern in ['RL', 'FL'] and r1_pattern in ['AU', 'WP']:
        steady_features['Smart'] = True
    if l1_pattern in ['RL', 'FL'] and r1_pattern in ['WT','WX']:
        steady_features['Wizard'] = True
    if l1_pattern in ['RL', 'FL'] and r1_pattern == 'WC':
        steady_features['Genius'] = True

    # Dominant features
    if l1_pattern in ['WS', 'WX'] and r1_pattern in ['UL', 'FL']:
        dominant_features['Assertive'] = True
    if l1_pattern == 'WX' and r1_pattern == 'WS':
        dominant_features['Assertive'] = True
    if l1_pattern in ['WS', 'WT', 'WX', 'WE'] and r1_pattern == 'RL':
        dominant_features['Different'] = True
    if l1_pattern in ['WS', 'WT', 'WX', 'WE'] and r1_pattern.startswith('A'):
        dominant_features['Unpredictable'] = True
    if l1_pattern in ['WS', 'WT', 'WE'] and r1_pattern in ['WS', 'WT', 'WX', 'WE']:
        dominant_features['Aggressive'] = True
    if l1_pattern == 'WX' and r1_pattern in ['WT', 'WX', 'WE']:
        dominant_features['Aggressive'] = True
    if l1_pattern in ['WS', 'WT', 'WX', 'WE'] and r1_pattern in ['WC', 'WD', 'WI']:
        dominant_features['Smart'] = True
    if l1_pattern in ['WS', 'WT', 'WX', 'WE'] and r1_pattern == 'WL':
        dominant_features['Wizard'] = True
    if l1_pattern in ['WS', 'WT', 'WX', 'WE'] and r1_pattern == 'WP':
        dominant_features['Genius'] = True
    if l1_pattern in ['WT', 'WE'] and r1_pattern == 'UL':
        dominant_features['Assertive'] = True
    if l1_pattern in ['WT', 'WE']and r1_pattern == 'FL':
        dominant_features['Unpredictable'] = True

    # Influential features
    if (l1_pattern.startswith('A') or r1_pattern in ['WP', 'WL']) and r1_pattern in ['UL', 'FL']:
        influential_features['Assertive'] = True
    if (l1_pattern.startswith('A') or r1_pattern in ['WP', 'WL']) and r1_pattern == 'RL':
        influential_features['Different'] = True
    if (l1_pattern.startswith('A') or r1_pattern in ['WP', 'WL']) and r1_pattern.startswith('A'):
        influential_features['Unpredictable'] = True
    if (l1_pattern.startswith('A') or r1_pattern in ['WP', 'WL']) and r1_pattern in ['WS', 'WT', 'WX', 'WE']:
        influential_features['Aggressive'] = True
    if (l1_pattern.startswith('A') or r1_pattern in ['WP', 'WL']) and r1_pattern in ['WC', 'WD', 'WI']:
        influential_features['Smart'] = True
    if (l1_pattern.startswith('A') or r1_pattern in ['WP', 'WL']) and r1_pattern == 'WL':
        influential_features['Wizard'] = True
    if (l1_pattern.startswith('A') or r1_pattern in ['WP', 'WL']) and r1_pattern == 'WP':
        influential_features['Genius'] = True

    # Conscious features
    if l1_pattern in ['WD', 'WC', 'WI'] and r1_pattern in ['UL', 'WS', 'FL']:
        conscious_features['Assertive'] = True
    if l1_pattern in ['WD', 'WC', 'WI'] and r1_pattern == 'RL':
        conscious_features['Different'] = True
    if l1_pattern in ['WD', 'WC', 'WI'] and r1_pattern.startswith('A'):
        conscious_features['Unpredictable'] = True
    if l1_pattern in ['WD', 'WC', 'WI'] and r1_pattern in ['WT', 'WX', 'WE']:
        conscious_features['Aggressive'] = True
    if l1_pattern in ['WD', 'WC', 'WI'] and r1_pattern in ['WC', 'WD', 'WI']:
        conscious_features['Smart'] = True
    if l1_pattern in ['WD', 'WC', 'WI'] and r1_pattern == 'WL':
        conscious_features['Wizard'] = True
    if l1_pattern in ['WD', 'WC', 'WI'] and r1_pattern == 'WP':
        conscious_features['Genius'] = True

    if steady_features:
        personality['Steady'] = steady_features
    if dominant_features:
        personality['Dominant'] = dominant_features
    if influential_features:
        personality['Influential'] = influential_features
    if conscious_features:
        personality['Conscious'] = conscious_features

    return personality

@app.route('/calculation_result', methods=['POST'])
def calculation_result():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    data = request.form
    assessment_id = data.get('assessment_id')

    if assessment_id:
        assessment = Assessment.query.get(assessment_id)
    else:
        assessment = None

    if not assessment:
        assessment = Assessment(user_id=user.id)

    # Update assessment data
    assessment.name = data.get('name')
    assessment.parent_name = data.get('parent_name')
    assessment.dob = data.get('dob')
    assessment.class_ = data.get('class')
    assessment.address = data.get('address')
    assessment.institute = data.get('institute')
    assessment.contact = data.get('contact')
    assessment.email = data.get('email')
    assessment.analysis_no = data.get('analysis_no')
    assessment.center_name = data.get('center_name')

    for hand in ['l', 'r']:
        for i in range(1, 6):
            pattern_key = f"{hand}{i}_pattern"
            rc_key = f"{hand}{i}_rc"
            setattr(assessment, pattern_key, data.get(pattern_key))
            rc_value = data.get(rc_key)
            setattr(assessment, rc_key, int(rc_value) if rc_value else None)

    db.session.add(assessment)
    db.session.commit()

    # Calculations
    fingers = ['l1', 'l2', 'l3', 'l4', 'l5', 'r1', 'r2', 'r3', 'r4', 'r5']
    rc_values = {}
    total_rc = 0
    for finger in fingers:
        rc = getattr(assessment, f'{finger}_rc') or 0
        rc_values[finger] = rc
        total_rc += rc

    percentages = {}
    percentages_display = {}
    for finger in fingers:
        rc_value = rc_values[finger]
        if rc_value == 0:
            percentages[finger] = 'X'
            percentages_display[finger] = 'X'
        elif total_rc > 0:
            internal_percentage = round((rc_value / total_rc) * 100, 3)
            percentages[finger] = internal_percentage
            percentages_display[finger] = round(internal_percentage, 2)
        else:
            percentages[finger] = 'X'
            percentages_display[finger] = 'X'

    # Brain analysis
    R_fingers = ['r1', 'r2', 'r3', 'r4', 'r5']
    A_left = 0
    B_left = 0
    for finger in R_fingers:
        val = percentages[finger]
        if val != 'X':
            A_left += val
        else:
            B_left += 1
    A_left = round(A_left, 2)
    if B_left > 0:
        if A_left > 0:
            left_brain_result = f"{A_left}+{B_left}X"
        else:
            left_brain_result = f"{B_left}X"
    else:
        left_brain_result = f"{A_left}"

    L_fingers = ['l1', 'l2', 'l3', 'l4', 'l5']
    A_right = 0
    B_right = 0
    for finger in L_fingers:
        val = percentages[finger]
        if val != 'X':
            A_right += val
        else:
            B_right += 1
    A_right = round(A_right, 2)
    if B_right > 0:
        if A_right > 0:
            right_brain_result = f"{A_right}+{B_right}X"
        else:
            right_brain_result = f"{B_right}X"
    else:
        right_brain_result = f"{A_right}"

    # Career recommendations
    career_recommendations = calculate_career_recommendations(percentages_display, rc_values, total_rc)

    # Use the new standalone functions
    achievement_styles = calculate_achievement_styles(assessment)
    kin_result, aud_result, vis_result = calculate_learning_communication_style(percentages)
    work_ability_results = calculate_work_ability_style(percentages)
    personality_features = calculate_personality_features(assessment)

    student_data = {
        'name': assessment.name or '',
        'parent_name': assessment.parent_name or '',
        'dob': assessment.dob or '',
        'class': assessment.class_ or '',
        'address': assessment.address or '',
        'institute': assessment.institute or '',
        'contact': assessment.contact or '',
        'email': assessment.email or '',
        'analysis_no': assessment.analysis_no or '',
        'center_name': assessment.center_name or ''
    }

    # Store all data in session for PDF generation
    session['current_student_data'] = {
        'name': request.form.get('name', ''),
        'parent_name': request.form.get('parent_name', ''),
        'dob': request.form.get('dob', ''),
        'class': request.form.get('class', ''),
        'institute': request.form.get('institute', ''),
        'contact': request.form.get('contact', ''),
        'email': request.form.get('email', ''),
        'analysis_no': request.form.get('analysis_no', ''),
        'address': request.form.get('address', ''),
        'center_name': ("Kareer Studio" if user.role == 'superuser' else (request.form.get('center_name', '') or '')),
    }
    session['current_percentages_display'] = percentages_display
    session['current_rc_values'] = rc_values
    session['current_total_rc'] = total_rc
    session['current_left_brain_result'] = left_brain_result
    session['current_right_brain_result'] = right_brain_result
    session['current_achievement_styles'] = achievement_styles
    session['current_kin_result'] = kin_result
    session['current_aud_result'] = aud_result
    session['current_vis_result'] = vis_result
    session['current_work_ability_results'] = work_ability_results
    session['current_personality_features'] = personality_features
    session['current_career_recommendations'] = career_recommendations

    flash('Assessment saved and calculated successfully!', 'success')

    # Token deduction and franchise detection (existing logic)
        # Token deduction and franchise detection (FIXED)
    if user.role == 'user' and user.franchise_id:
        franchise_obj = Franchise.query.get(user.franchise_id)
        
        # Calculate tokens_left correctly from TokenPurchase table
        if franchise_obj.parent_franchise_id:
            # Sub-franchise: Get tokens from PARENT's purchases for checking availability
            parent_franchise = Franchise.query.get(franchise_obj.parent_franchise_id)
            purchases = TokenPurchase.query.filter_by(
                franchise_id=parent_franchise.id,
                payment_status='completed'
            ).all()
            total_purchased = sum(p.tokens_bought for p in purchases)
            tokens_used_parent = parent_franchise.tokens_used or 0
            tokens_left = total_purchased - tokens_used_parent
        else:
            # White-label: Get tokens from own purchases
            purchases = TokenPurchase.query.filter_by(
                franchise_id=franchise_obj.id,
                payment_status='completed'
            ).all()
            total_purchased = sum(p.tokens_bought for p in purchases)
            tokens_used_self = franchise_obj.tokens_used or 0
            tokens_left = total_purchased - tokens_used_self
        
        # Check if enough tokens available
        if tokens_left < 1:
            flash('Insufficient tokens. Please purchase tokens.', 'error')
            return redirect(url_for('buy_tokens'))
        
        # Deduct token from the FRANCHISE itself (NOT parent)
        franchise_obj.tokens_used = (franchise_obj.tokens_used or 0) + 1
        db.session.commit()
        tokens_left = tokens_left - 1
    else:
        tokens_left = None

    # Add franchise detection
    host = request.headers.get('Host', '')
    franchise = None
    if host:
        # Clean the host - remove port if present
        clean_host = host.split(':')[0]
        
        # Try exact domain match first
        franchise = Franchise.query.filter(
            db.or_(
                Franchise.website == f'http://{clean_host}',
                Franchise.website == f'https://{clean_host}',
                Franchise.website == clean_host,
                Franchise.website == f'http://www.{clean_host}',
                Franchise.website == f'https://www.{clean_host}',
                Franchise.website == f'www.{clean_host}'
            )
        ).first()
        
        # If no exact match, try partial match as fallback
        if not franchise:
            franchise = Franchise.query.filter(
                db.or_(
                    Franchise.website.contains(clean_host),
                    Franchise.website.contains(clean_host.replace('www.', ''))
                )
            ).first()

    if not franchise and user.role == 'user' and user.franchise_id:
        franchise = Franchise.query.get(user.franchise_id)

    return render_template('calculation_result.html',
                         percentages=percentages,
                         percentages_display=percentages_display,
                         rc_values=rc_values,
                         total_rc=total_rc,
                         student_data=student_data,
                         assessment=assessment,
                         left_brain_result=left_brain_result,
                         right_brain_result=right_brain_result,
                         kin_result=kin_result,
                         aud_result=aud_result,
                         vis_result=vis_result,
                         work_ability_results=work_ability_results,
                         achievement_styles=achievement_styles,
                         personality_features=personality_features,
                         career_recommendations=career_recommendations,
                         user=user,
                         franchise=franchise,
                         tokens_left=tokens_left)

@app.route('/prepare_report/<int:id>', methods=['GET'])
def prepare_report(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    assessment = Assessment.query.get_or_404(id)

    # Security: Only allow own assessment or superuser
    if user.role != 'superuser' and assessment.user_id != user.id:
        flash('Access denied', 'error')
        return redirect(url_for('manage_student'))

    # Prepare session data for PDF generation
    student_data = {
        'name': assessment.name or '',
        'parent_name': assessment.parent_name or '',
        'dob': assessment.dob or '',
        'class': assessment.class_ or '',
        'institute': assessment.institute or '',
        'contact': assessment.contact or '',
        'email': assessment.email or '',
        'analysis_no': assessment.analysis_no or '',
        'address': assessment.address or '',
        'center_name': assessment.center_name or ''
    }

    fingers = ['l1', 'l2', 'l3', 'l4', 'l5', 'r1', 'r2', 'r3', 'r4', 'r5']
    rc_values = {}
    total_rc = 0
    for finger in fingers:
        rc = getattr(assessment, f'{finger}_rc') or 0
        rc_values[finger] = rc
        total_rc += rc

    percentages_display = {}
    percentages = {}
    for finger in fingers:
        rc_value = rc_values[finger]
        if rc_value == 0:
            percentages[finger] = 'X'
            percentages_display[finger] = 'X'
        elif total_rc > 0:
            internal_percentage = round((rc_value / total_rc) * 100, 3)
            percentages[finger] = internal_percentage
            percentages_display[finger] = round(internal_percentage, 2)
        else:
            percentages[finger] = 'X'
            percentages_display[finger] = 'X'

    # Brain analysis
    R_fingers = ['r1', 'r2', 'r3', 'r4', 'r5']
    A_left = 0
    B_left = 0
    for finger in R_fingers:
        val = percentages[finger]
        if val != 'X':
            A_left += val
        else:
            B_left += 1
    A_left = round(A_left, 2)
    if B_left > 0:
        if A_left > 0:
            left_brain_result = f"{A_left}+{B_left}X"
        else:
            left_brain_result = f"{B_left}X"
    else:
        left_brain_result = f"{A_left}"

    L_fingers = ['l1', 'l2', 'l3', 'l4', 'l5']
    A_right = 0
    B_right = 0
    for finger in L_fingers:
        val = percentages[finger]
        if val != 'X':
            A_right += val
        else:
            B_right += 1
    A_right = round(A_right, 2)
    if B_right > 0:
        if A_right > 0:
            right_brain_result = f"{A_right}+{B_right}X"
        else:
            right_brain_result = f"{B_right}X"
    else:
        right_brain_result = f"{A_right}"

    # Calculate other results using the functions we just added
    career_recommendations = calculate_career_recommendations(percentages_display, rc_values, total_rc)
    achievement_styles = calculate_achievement_styles(assessment)
    kin_result, aud_result, vis_result = calculate_learning_communication_style(percentages)
    work_ability_results = calculate_work_ability_style(percentages)
    personality_features = calculate_personality_features(assessment)

    # Store all data in session for PDF generation
    session['current_student_data'] = student_data
    session['current_percentages_display'] = percentages_display
    session['current_rc_values'] = rc_values
    session['current_total_rc'] = total_rc
    session['current_left_brain_result'] = left_brain_result
    session['current_right_brain_result'] = right_brain_result
    session['current_achievement_styles'] = achievement_styles
    session['current_kin_result'] = kin_result
    session['current_aud_result'] = aud_result
    session['current_vis_result'] = vis_result
    session['current_work_ability_results'] = work_ability_results
    session['current_personality_features'] = personality_features
    session['current_career_recommendations'] = career_recommendations

    return redirect(url_for('generate_pdf'))

@app.route('/generate_pdf', methods=['GET', 'POST'])
def generate_pdf():
    try:
        if 'user_id' not in session:
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])

        # Get franchise info for franchise users
        franchise = None
        if user.role == 'user' and user.franchise_id:
            franchise = Franchise.query.get(user.franchise_id)

        # Get data from session with fallback values
        student_data = session.get('current_student_data', {})
        percentages_display = session.get('current_percentages_display', {})
        rc_values = session.get('current_rc_values', {})
        total_rc = session.get('current_total_rc', 0)
        left_brain_result = session.get('current_left_brain_result', 'Not Calculated')
        right_brain_result = session.get('current_right_brain_result', 'Not Calculated')
        achievement_styles = session.get('current_achievement_styles', {})
        kin_result = session.get('current_kin_result', 'Not Calculated')
        aud_result = session.get('current_aud_result', 'Not Calculated')
        vis_result = session.get('current_vis_result', 'Not Calculated')
        work_ability_results = session.get('current_work_ability_results', {})
        personality_features = session.get('current_personality_features', {})
        career_recommendations = session.get('current_career_recommendations', {})

        # Determine template and franchise inclusion based on user type
        include_franchise_details = False
        
        if user.role == 'superuser':
            # Superuser always uses blank template without franchise details
            include_franchise_details = False
        elif user.role == 'user' and user.origin == 'admin_added':
            # Admin-added users use blank template without franchise details
            include_franchise_details = False
        elif user.role == 'user' and user.origin == 'self_registered':
            # Self-registered whitelabel users use IKIGAI template with franchise details
            include_franchise_details = True
        else:
            # Default: use blank template without franchise details
            include_franchise_details = False

        # Generate PDF with franchise info only if needed
        if include_franchise_details:
            pdf_buffer = generate_filled_pdf(
                student_data, percentages_display, rc_values, total_rc,
                left_brain_result, right_brain_result, achievement_styles,
                kin_result, aud_result, vis_result, work_ability_results,
                personality_features, career_recommendations, franchise
            )
        else:
            pdf_buffer = generate_filled_pdf(
                student_data, percentages_display, rc_values, total_rc,
                left_brain_result, right_brain_result, achievement_styles,
                kin_result, aud_result, vis_result, work_ability_results,
                personality_features, career_recommendations, None  # No franchise
            )

        if pdf_buffer is None:
            flash('Error generating PDF. Please try again.', 'error')
            return redirect(url_for('dashboard'))

        student_name = student_data.get('name', 'Student').replace(' ', '_')
        filename = f"Brainography_Report_{student_name}.pdf"

        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )

    except Exception as e:
        print(f"Error in generate_pdf route: {str(e)}")
        flash(f'Error generating PDF: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/preview_pdf')
def preview_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Add franchise detection
    host = request.headers.get('Host', '')
    franchise = None
    if host:
        # Clean the host - remove port if present
        clean_host = host.split(':')[0]
        
        # Try exact domain match first
        franchise = Franchise.query.filter(
            db.or_(
                Franchise.website == f'http://{clean_host}',
                Franchise.website == f'https://{clean_host}',
                Franchise.website == clean_host,
                Franchise.website == f'http://www.{clean_host}',
                Franchise.website == f'https://www.{clean_host}',
                Franchise.website == f'www.{clean_host}'
            )
        ).first()
        
        # If no exact match, try partial match as fallback
        if not franchise:
            franchise = Franchise.query.filter(
                db.or_(
                    Franchise.website.contains(clean_host),
                    Franchise.website.contains(clean_host.replace('www.', ''))
                )
            ).first()
    
    # For franchise users, fallback to their franchise
    if not franchise and user.role == 'user' and user.franchise_id:
        franchise = Franchise.query.get(user.franchise_id)

    return render_template('pdf_preview.html', user=user, franchise=franchise)

@app.route('/buy_tokens', methods=['GET', 'POST'])
def buy_tokens():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    # Only franchise users can buy tokens
    if user.role != 'user' or not user.franchise_id:
        flash('Access denied. Only franchise users can buy tokens.', 'error')
        return redirect(url_for('dashboard'))

    # Get franchise object
    franchise = Franchise.query.get(user.franchise_id)
    
    # For logo display: if sub-franchise, use parent's franchise
    if franchise.parent_franchise_id:
        display_franchise = Franchise.query.get(franchise.parent_franchise_id)
    else:
        display_franchise = franchise

    # Determine user origin for pricing
    user_origin = user.origin or 'self_registered'

    # Default token packages
    token_packages = [
        {'id': 1, 'tokens': 10, 'price': 1000, 'title': '', 'description': 'Perfect for small centers. Add 10 students and generate their reports.', 'savings': ''},
        {'id': 2, 'tokens': 25, 'price': 2300, 'title': '', 'description': 'Best value for growing centers. Add 25 students and save ₹200.', 'savings': 'Save ₹200'},
        {'id': 3, 'tokens': 50, 'price': 4000, 'title': '', 'description': 'Premium pack for large centers. Add 50 students and save ₹1000.', 'savings': 'Save ₹1000'},
        {'id': 4, 'tokens': 100, 'price': 7500, 'title': '', 'description': 'Enterprise solution. Add 100 students and save ₹2500.', 'savings': 'Save ₹2500'}
    ]

    # Lower pricing for admin_added franchises
    if user_origin == 'admin_added':
        admin_pricing = {1: 800, 2: 1800, 3: 3200, 4: 6000}
        admin_savings = {1: '', 2: 'Save ₹500', 3: 'Save ₹1800', 4: 'Save ₹3500'}
        for package in token_packages:
            if package['id'] in admin_pricing:
                package['price'] = admin_pricing[package['id']]
                package['savings'] = admin_savings[package['id']]

    # Query completed purchases from database
    purchases = TokenPurchase.query.filter_by(
        franchise_id=franchise.id,
        payment_status='completed'
    ).order_by(TokenPurchase.purchase_date.desc()).all()
    
    # Calculate totals from actual purchases
    total_purchased = sum(p.tokens_bought for p in purchases)
    
    # For display purposes
    tokens_bought = total_purchased
    tokens_used = franchise.tokens_used or 0
    tokens_left = tokens_bought - tokens_used
    

    if request.method == 'POST':
        package_id = int(request.form.get('package_id'))
        selected_package = next((p for p in token_packages if p['id'] == package_id), None)

        if not selected_package:
            flash('Invalid package selected.', 'error')
            return redirect(url_for('buy_tokens'))

        amount = int(selected_package['price'] * 100)
        franchise_obj = db.session.get(Franchise, user.franchise_id)

        if franchise_obj.parent_franchise_id:
            parent_franchise = db.session.get(Franchise, franchise_obj.parent_franchise_id)
            if parent_franchise and parent_franchise.razorpay_key_id:
                RAZORPAY_KEY_ID = parent_franchise.razorpay_key_id
                RAZORPAY_KEY_SECRET = parent_franchise.razorpay_key_secret
            else:
                flash('Parent franchise has not configured payment settings.', 'error')
                return redirect(url_for('buy_tokens'))
        else:
            RAZORPAY_KEY_ID = app.config['RAZORPAY_KEY_ID']
            RAZORPAY_KEY_SECRET = app.config['RAZORPAY_KEY_SECRET']

        razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

        try:
            razorpay_order = razorpay_client.order.create({'amount': amount, 'currency': 'INR', 'payment_capture': 1})
            return render_template('token_payment.html', order_id=razorpay_order['id'], amount=amount, key_id=app.config['RAZORPAY_KEY_ID'], package=selected_package, franchise=display_franchise)
        except Exception as e:
            flash('Error creating payment order. Please try again.', 'error')
            return redirect(url_for('buy_tokens'))

    return render_template('buy_tokens.html', packages=token_packages, franchise=display_franchise, tokens_bought=tokens_bought, tokens_used=tokens_used, tokens_left=tokens_left, user=user, user_origin=user_origin)

@app.route('/token-payment-success', methods=['POST'])
def token_payment_success():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    franchise = Franchise.query.get(user.franchise_id)
    
    # Verify payment
    payment_id = request.form.get('razorpay_payment_id')
    order_id = request.form.get('razorpay_order_id')
    signature = request.form.get('razorpay_signature')
    tokens_bought = int(request.form.get('tokens_bought'))
    amount_paid = float(request.form.get('amount_paid'))
    
    try:
        # Verify signature
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        })
        
        # ✅ Payment verified successfully - NOW handle token allocation
        if franchise.parent_franchise_id:
            # Sub-franchise: Deduct from parent's pool AFTER payment verification
            parent_franchise = Franchise.query.get(franchise.parent_franchise_id)
            if parent_franchise:
                parent_available = (parent_franchise.tokens_total or 0) - (parent_franchise.tokens_used or 0)
                if parent_available >= tokens_bought:
                    # Deduct from parent's used tokens
                    parent_franchise.tokens_used = (parent_franchise.tokens_used or 0) + tokens_bought
                else:
                    flash(f'Error: Parent franchise only has {parent_available} tokens available.', 'error')
                    return redirect(url_for('buy_tokens'))
        else:
            # White-label: Add to their own pool
            franchise.tokens_total = (franchise.tokens_total or 0) + tokens_bought
        
        # ✅ Create purchase record with payment_status='completed'
        purchase = TokenPurchase(
            franchise_id=franchise.id,
            tokens_bought=tokens_bought,
            amount_paid=amount_paid,
            payment_id=payment_id,
            payment_status='completed'  # ✅ EXPLICITLY SET TO COMPLETED
        )
        db.session.add(purchase)
        db.session.commit()
        
        flash(f'Payment successful! {tokens_bought} tokens added to your account.', 'success')
        return redirect(url_for('buy_tokens'))
        
    except Exception as e:
        flash('Payment verification failed. Please contact support.', 'error')
        return redirect(url_for('buy_tokens'))

@app.route('/billing')
def billing():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Only franchise users can view billing
    if user.role != 'user' or not user.franchise_id:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get franchise from user's franchise_id
    franchise = Franchise.query.get(user.franchise_id)
    if not franchise:
        flash('Franchise not found.', 'error')
        return redirect(url_for('dashboard'))
    
    # Host detection for white-label domain customization
    host = request.headers.get('Host', '')
    franchise_from_host = None
    if host:
        clean_host = host.split(':')[0]
        franchise_from_host = Franchise.query.filter(
            db.or_(
                Franchise.website == f'http://{clean_host}',
                Franchise.website == f'https://{clean_host}',
                Franchise.website == clean_host
            )
        ).first()
    
    # ✅ SHOW PURCHASES FOR BOTH WHITE-LABEL AND SUB-FRANCHISES
    purchases = TokenPurchase.query.filter_by(
        franchise_id=franchise.id,
        payment_status='completed'
    ).order_by(TokenPurchase.purchase_date.desc()).all()

    # ✅ Calculate from actual purchases
    total_purchased = sum(p.tokens_bought for p in purchases)
    total_spent = sum(p.amount_paid for p in purchases)
    
    # For sub-franchises, get parent franchise logo
    parent_logo = None
    if franchise.parent_franchise_id:
        parent_franchise = db.session.get(Franchise, franchise.parent_franchise_id)
        if parent_franchise and parent_franchise.logo_filename:
            parent_logo = parent_franchise.logo_filename
    
    # Use franchise_from_host for logo display if available
    display_franchise = franchise_from_host if franchise_from_host else franchise
    
    return render_template('billing.html',
                         purchases=purchases,
                         franchise=display_franchise,
                         total_spent=total_spent,
                         total_tokens_purchased=total_purchased,  # ✅ FIXED: Use total_purchased
                         user=user,
                         parent_logo=parent_logo)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if user.role != 'user' or not user.franchise_id:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get the franchise data for this user
    franchise = Franchise.query.get(user.franchise_id)
    if not franchise:
        flash('Franchise not found.', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if this is a whitelabel access
    host = request.headers.get('Host', '')
    franchise_context = None
    
    if host:
        clean_host = host.split(':')[0]  # Clean the host - remove port if present
        franchise_context = Franchise.query.filter(
            db.or_(
                Franchise.website == f'http://{clean_host}',
                Franchise.website == f'https://{clean_host}',
                Franchise.website == clean_host,
                Franchise.website == f'http://www.{clean_host}',
                Franchise.website == f'https://www.{clean_host}',
                Franchise.website == f'www.{clean_host}'
            )
        ).first()
        
        if not franchise_context:
            franchise_context = Franchise.query.filter(
                db.or_(
                    Franchise.website.contains(clean_host),
                    Franchise.website.contains(clean_host.replace('www.', ''))
                )
            ).first()
    
    # Determine if we should show company logo field
    if not franchise_context and user.role == 'user' and user.franchise_id:
        franchise_context = Franchise.query.get(user.franchise_id)
    
    if request.method == 'POST':
        # Update only editable fields
        franchise.address = request.form.get('address', '')
        franchise.phone = request.form.get('phone', '')
        franchise.whatsapp_number = request.form.get('whatsapp_number', '')
        
        # Handle logo upload
        logo = request.files.get('logo')
        if logo and logo.filename:
            if len(logo.read()) > 2 * 1024 * 1024:
                flash('Logo size should not exceed 2MB', 'error')
                return render_template('profile.html', user=user, franchise=franchise, franchise_context=franchise_context)
            
            logo.seek(0)
            
            # Remove old logo if exists
            if franchise.logo_filename:
                old_logo_path = os.path.join(app.root_path, 'static', franchise.logo_filename)
                if os.path.exists(old_logo_path):
                    os.remove(old_logo_path)
            
            # Save new logo
            file_extension = logo.filename.rsplit('.', 1)[1].lower()
            logo_filename = f"franchise_logo_{uuid.uuid4().hex[:8]}.{file_extension}"
            static_dir = os.path.join(app.root_path, 'static')
            if not os.path.exists(static_dir):
                os.makedirs(static_dir)
            
            logo.save(os.path.join(static_dir, logo_filename))
            franchise.logo_filename = logo_filename
    
        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating profile. Please try again.', 'error')
    
    return render_template('profile.html', user=user, franchise=franchise, 
                         franchise_context=franchise_context)

@app.route('/set-cookie-preference', methods=['POST'])
def set_cookie_preference():
    """Handle cookie consent preference"""
    preference = request.json.get('preference', 'declined')
    
    response = jsonify({'status': 'success'})
    
    if preference == 'accepted':
        # Set cookie consent for 1 year
        response.set_cookie('cookie_consent', 'accepted', max_age=365*24*60*60)
    else:
        # Set declined preference
        response.set_cookie('cookie_consent', 'declined', max_age=365*24*60*60)
    
    return response

@app.route('/razorpay_settings', methods=['GET', 'POST'])
def razorpay_settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    
    # Only white-label users can set Razorpay credentials
    if user.role != 'user' or not user.franchise_id:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    franchise = db.session.get(Franchise, user.franchise_id)
    
    if request.method == 'POST':
        razorpay_key_id = request.form.get('razorpay_key_id')
        razorpay_key_secret = request.form.get('razorpay_key_secret')
        
        franchise.razorpay_key_id = razorpay_key_id
        franchise.razorpay_key_secret = razorpay_key_secret
        
        db.session.commit()
        flash('Razorpay settings updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('razorpay_settings.html', franchise=franchise, user=user)

@app.route('/whitelabel-tracking')
def whitelabel_tracking():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # ✅ FIXED - Check for correct super-admin role
    if user.role != 'superuser':  # Changed from 'admin' to 'superuser'
        flash('Access denied. Super-admin only.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all white-label franchises (franchises without parent)
    whitelabel_franchises = Franchise.query.filter_by(parent_franchise_id=None).all()
    
    # Prepare tracking data
    tracking_data = []
    for franchise in whitelabel_franchises:
        # Get all completed purchases for this franchise
        purchases = TokenPurchase.query.filter_by(
            franchise_id=franchise.id,
            payment_status='completed'
        ).all()
        
        total_purchased = sum(p.tokens_bought for p in purchases)
        total_used = franchise.tokens_used or 0
        tokens_remaining = total_purchased - total_used
        
        # Get last purchase date
        last_purchase = TokenPurchase.query.filter_by(
            franchise_id=franchise.id,
            payment_status='completed'
        ).order_by(TokenPurchase.purchase_date.desc()).first()
        
        last_purchase_date = last_purchase.purchase_date if last_purchase else None
        
        tracking_data.append({
            'franchise': franchise,
            'total_purchased': total_purchased,
            'total_used': total_used,
            'tokens_remaining': tokens_remaining,
            'last_purchase_date': last_purchase_date,
            'purchase_count': len(purchases)
        })
    
    return render_template('whitelabel_tracking.html', tracking_data=tracking_data, user=user)

if __name__ == '__main__':
    app.run(debug=True)
