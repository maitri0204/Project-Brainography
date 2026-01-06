from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'superuser' or 'user'
    franchise_id = db.Column(db.Integer, db.ForeignKey('franchise.id'))
    force_password_reset = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100))
    reset_token = db.Column(db.String(100))
    reset_token_expiry = db.Column(db.DateTime)
    origin = db.Column(db.String(20), default='self_registered')
    
    assessments = db.relationship('Assessment', backref='user', lazy=True)

class Franchise(db.Model):
    __tablename__ = 'franchise'
    
    id = db.Column(db.Integer, primary_key=True)
    franchise_name = db.Column(db.String(100), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(150), unique=True, nullable=False)
    website = db.Column(db.String(200))
    gst_number = db.Column(db.String(50))
    pan_number = db.Column(db.String(20))
    logo_filename = db.Column(db.String(200))
    whatsapp_number = db.Column(db.String(20))
    payment_status = db.Column(db.String(20), default='pending')
    payment_id = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=False)
    registration_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    tokens_total = db.Column(db.Integer, default=0)
    tokens_used = db.Column(db.Integer, default=0)
    analysis_counter = db.Column(db.Integer, default=0)
    
    # NEW FIELDS FOR HIERARCHY
    parent_franchise_id = db.Column(db.Integer, db.ForeignKey('franchise.id'), nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # NEW FIELDS FOR RAZORPAY
    razorpay_key_id = db.Column(db.String(100), nullable=True)
    razorpay_key_secret = db.Column(db.String(100), nullable=True)
    
    users = db.relationship('User', backref='franchise', lazy=True, foreign_keys=[User.franchise_id])
    sub_franchises = db.relationship('Franchise', backref=db.backref('parent_franchise', remote_side=[id]), lazy=True)

class Assessment(db.Model):
    __tablename__ = 'assessment'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(150))
    parent_name = db.Column(db.String(150))
    dob = db.Column(db.String(50))
    class_ = db.Column(db.String(50))
    address = db.Column(db.String(300))
    institute = db.Column(db.String(150))
    contact = db.Column(db.String(30))
    email = db.Column(db.String(150))
    analysis_no = db.Column(db.String(20), unique=True, nullable=False)
    center_name = db.Column(db.String(150))
    parent_name = db.Column(db.String(100))
    parent_contact = db.Column(db.String(20))
    parent_email = db.Column(db.String(100))
    date = db.Column(db.Date, default=db.func.current_date())
    
    # Finger patterns and RCs
    l1_pattern = db.Column(db.String(5))
    l1_rc = db.Column(db.Integer)
    l2_pattern = db.Column(db.String(5))
    l2_rc = db.Column(db.Integer)
    l3_pattern = db.Column(db.String(5))
    l3_rc = db.Column(db.Integer)
    l4_pattern = db.Column(db.String(5))
    l4_rc = db.Column(db.Integer)
    l5_pattern = db.Column(db.String(5))
    l5_rc = db.Column(db.Integer)
    r1_pattern = db.Column(db.String(5))
    r1_rc = db.Column(db.Integer)
    r2_pattern = db.Column(db.String(5))
    r2_rc = db.Column(db.Integer)
    r3_pattern = db.Column(db.String(5))
    r3_rc = db.Column(db.Integer)
    r4_pattern = db.Column(db.String(5))
    r4_rc = db.Column(db.Integer)
    r5_pattern = db.Column(db.String(5))
    r5_rc = db.Column(db.Integer)

class TokenPurchase(db.Model):
    __tablename__ = 'token_purchase'
    
    id = db.Column(db.Integer, primary_key=True)
    franchise_id = db.Column(db.Integer, db.ForeignKey('franchise.id'), nullable=False)
    tokens_bought = db.Column(db.Integer, nullable=False)
    amount_paid = db.Column(db.Float, nullable=False)
    payment_id = db.Column(db.String(100))
    payment_status = db.Column(db.String(20), default='pending')
    purchase_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    franchise = db.relationship('Franchise', backref='token_purchases', lazy=True)
