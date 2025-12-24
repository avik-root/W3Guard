"""
W3Guard - Phishing Detection System
College Project - Educational Purposes Only
NO MOCK DATA - All data from actual JSON files

SECURITY: Admin credentials stored in data/admin.json
Admin password is managed via admin_config.py script
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError
import json
import os
from datetime import datetime, timedelta
import secrets
import re
from functools import wraps
import uuid
from urllib.parse import urlparse
from datetime import datetime

# Import custom modules
from models import User, Scan, AdminSettings, News, JSONHandler
from features import URLFeatureExtractor
from ml_model import PhishingDetector

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Initialize handlers
user_handler = JSONHandler('data/users.json')
scan_handler = JSONHandler('data/scans.json')
news_handler = JSONHandler('data/news.json')
admin_handler = JSONHandler('data/admin_settings.json')

# Initialize ML model
phishing_detector = PhishingDetector()

# Add Jinja2 global functions
app.jinja_env.globals.update(min=min, max=max, len=len)

# Load admin configuration
def load_admin_config():
    """Load admin configuration from admin.json"""
    admin_file = 'data/admin.json'
    if os.path.exists(admin_file):
        try:
            with open(admin_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    return None

# Maintenance mode decorator
def check_maintenance(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        admin_settings = admin_handler.load_data()
        if admin_settings.get('maintenance_mode', False) and not current_user.is_authenticated:
            return render_template('maintenance.html'), 503
        if admin_settings.get('maintenance_mode', False) and current_user.is_authenticated:
            if not current_user.is_admin:
                return render_template('maintenance.html'), 503
        return func(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    users = user_handler.load_data()
    user_data = users.get(user_id)
    if user_data:
        user = User(
            id=user_id,
            email=user_data['email'],
            password=user_data['password'],
            is_admin=user_data.get('is_admin', False),
            scan_count=user_data.get('scan_count', 0),
            daily_scans=user_data.get('daily_scans', 0),
            last_scan_date=user_data.get('last_scan_date'),
            credit_points=user_data.get('credit_points', 0)
        )
        return user
    return None

@app.context_processor
def inject_current_year():
    return {"current_year": datetime.now().year}

# Generate simple math question
def generate_math_question():
    import random
    operators = ['+', '-', '*']
    operator = random.choice(operators)
    
    if operator == '+':
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)
        answer = num1 + num2
    elif operator == '-':
        num1 = random.randint(1, 20)
        num2 = random.randint(1, num1)
        answer = num1 - num2
    else:  # '*'
        num1 = random.randint(1, 5)
        num2 = random.randint(1, 5)
        answer = num1 * num2
    
    question = f"{num1} {operator} {num2}"
    return question, str(answer)

# Forms
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(), 
        Email(),
        Length(min=6, max=100)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long'),
    ])
    math_answer = StringField('Math Answer', validators=[DataRequired()])
    submit = SubmitField('Register')
    
    def validate_password(self, password):
        pwd = password.data
        if not re.search(r'[A-Z]', pwd):
            raise ValidationError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', pwd):
            raise ValidationError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', pwd):
            raise ValidationError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', pwd):
            raise ValidationError('Password must contain at least one special character')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    math_answer = StringField('Math Answer', validators=[DataRequired()])
    submit = SubmitField('Login')

class ScanForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired()])
    submit = SubmitField('Scan')

class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long'),
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')
    
    def validate_new_password(self, new_password):
        pwd = new_password.data
        if not re.search(r'[A-Z]', pwd):
            raise ValidationError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', pwd):
            raise ValidationError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', pwd):
            raise ValidationError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', pwd):
            raise ValidationError('Password must contain at least one special character')

# Routes
@app.route('/')
@check_maintenance
def index():
    news_data = news_handler.load_data()
    return render_template('index.html', news=news_data.get('articles', []))

@app.route('/register', methods=['GET', 'POST'])
@check_maintenance
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Generate math question for the session
    if 'math_question' not in session:
        question, answer = generate_math_question()
        session['math_question'] = question
        session['math_answer'] = answer
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Verify math answer
        user_answer = form.math_answer.data.strip()
        correct_answer = session.get('math_answer')
        
        if not correct_answer or user_answer != correct_answer:
            flash('Incorrect math answer. Please try again.', 'danger')
            # Generate new question
            question, answer = generate_math_question()
            session['math_question'] = question
            session['math_answer'] = answer
            return render_template('register.html', form=form, math_question=question)
        
        users = user_handler.load_data()
        
        # Check if email exists
        for user_id, user_data in users.items():
            if user_data['email'] == form.email.data:
                flash('Email already registered', 'danger')
                return render_template('register.html', form=form, math_question=session.get('math_question'))
        
        # Create new user
        user_id = str(uuid.uuid4())
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        new_user = {
            'id': user_id,
            'email': form.email.data,
            'password': hashed_password,
            'is_admin': False,
            'created_at': datetime.now().isoformat(),
            'scan_count': 0,
            'daily_scans': 0,
            'last_scan_date': None,
            'credit_points': 0,
            'failed_attempts': 0,
            'locked_until': None
        }
        
        users[user_id] = new_user
        user_handler.save_data(users)
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form, math_question=session.get('math_question'))

@app.route('/login', methods=['GET', 'POST'])
@check_maintenance
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Generate math question for the session
    if 'math_question' not in session:
        question, answer = generate_math_question()
        session['math_question'] = question
        session['math_answer'] = answer
    
    form = LoginForm()
    
    if form.validate_on_submit():
        # Verify math answer
        user_answer = form.math_answer.data.strip()
        correct_answer = session.get('math_answer')
        
        if not correct_answer or user_answer != correct_answer:
            flash('Incorrect math answer. Please try again.', 'danger')
            # Generate new question
            question, answer = generate_math_question()
            session['math_question'] = question
            session['math_answer'] = answer
            return render_template('login.html', form=form, math_question=question)
        
        users = user_handler.load_data()
        
        # Check if this is admin login
        admin_config = load_admin_config()
        is_admin_login = (admin_config and form.email.data == admin_config.get('email'))
        
        # Find user by email
        user_data = None
        user_id = None
        
        if is_admin_login and admin_config:
            # Admin login with admin credentials
            password_hash = admin_config.get('password_hash')
            if password_hash and bcrypt.check_password_hash(password_hash, form.password.data):
                # Create/update admin user in users.json
                admin_email = admin_config.get('email')
                for uid, udata in users.items():
                    if udata.get('is_admin') and udata['email'] == admin_email:
                        user_id = uid
                        user_data = udata
                        break
                
                if not user_data:
                    # Create admin user entry
                    user_id = str(uuid.uuid4())
                    user_data = {
                        'id': user_id,
                        'email': admin_email,
                        'password': password_hash,
                        'is_admin': True,
                        'created_at': datetime.now().isoformat(),
                        'scan_count': 0,
                        'daily_scans': 0,
                        'last_scan_date': None,
                        'credit_points': admin_config.get('credit_points', 1000),
                        'failed_attempts': 0,
                        'locked_until': None
                    }
                    users[user_id] = user_data
                    user_handler.save_data(users)
            else:
                flash('Invalid credentials', 'danger')
                question, answer = generate_math_question()
                session['math_question'] = question
                session['math_answer'] = answer
                return render_template('login.html', form=form, math_question=session.get('math_question'))
        else:
            # Regular user login
            for uid, data in users.items():
                if data['email'] == form.email.data:
                    user_data = data
                    user_id = uid
                    break
        
        if user_data:
            # Check if account is locked
            if user_data.get('locked_until'):
                locked_until = datetime.fromisoformat(user_data['locked_until'])
                if datetime.now() < locked_until:
                    remaining = (locked_until - datetime.now()).seconds // 60
                    flash(f'Account locked. Try again in {remaining} minutes', 'danger')
                    return render_template('login.html', form=form, math_question=session.get('math_question'))
            
            # Verify password
            if bcrypt.check_password_hash(user_data['password'], form.password.data):
                # Reset failed attempts
                user_data['failed_attempts'] = 0
                user_data['locked_until'] = None
                users[user_id] = user_data
                user_handler.save_data(users)
                
                # Create user object and login
                user = User(
                    id=user_id,
                    email=user_data['email'],
                    password=user_data['password'],
                    is_admin=user_data.get('is_admin', False),
                    scan_count=user_data.get('scan_count', 0),
                    daily_scans=user_data.get('daily_scans', 0),
                    last_scan_date=user_data.get('last_scan_date'),
                    credit_points=user_data.get('credit_points', 0)
                )
                
                login_user(user, remember=True)
                flash('Login successful!', 'success')
                
                # Redirect based on user type
                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('dashboard'))
            else:
                # Increment failed attempts
                user_data['failed_attempts'] = user_data.get('failed_attempts', 0) + 1
                
                # Lock account after 5 failed attempts
                if user_data['failed_attempts'] >= 5:
                    lock_time = datetime.now() + timedelta(minutes=15)
                    user_data['locked_until'] = lock_time.isoformat()
                    flash('Too many failed attempts. Account locked for 15 minutes.', 'danger')
                else:
                    flash(f'Invalid credentials. {5 - user_data["failed_attempts"]} attempts remaining', 'danger')
                
                users[user_id] = user_data
                user_handler.save_data(users)
        else:
            flash('Invalid credentials', 'danger')
        
        # Generate new math question for next attempt
        question, answer = generate_math_question()
        session['math_question'] = question
        session['math_answer'] = answer
    
    return render_template('login.html', form=form, math_question=session.get('math_question'))

@app.route('/new_math_question')
def new_math_question():
    question, answer = generate_math_question()
    session['math_question'] = question
    session['math_answer'] = answer
    return jsonify({'question': question})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Check daily scan reset
    today = datetime.now().date()
    if current_user.last_scan_date:
        last_scan_date = datetime.fromisoformat(current_user.last_scan_date).date()
        if last_scan_date != today:
            # Reset daily scans
            users = user_handler.load_data()
            if current_user.id in users:
                users[current_user.id]['daily_scans'] = 0
                users[current_user.id]['last_scan_date'] = today.isoformat()
                user_handler.save_data(users)
                current_user.daily_scans = 0
    
    # Get user's recent scans (LAST 5 REAL SCANS)
    scans = scan_handler.load_data()
    user_scans = [
        scan for scan in scans.values() 
        if scan['user_id'] == current_user.id
    ]
    user_scans.sort(key=lambda x: x['timestamp'], reverse=True)
    
    remaining_scans = max(0, 10 - current_user.daily_scans)
    
    # Calculate user's safe vs phishing counts (REAL DATA)
    safe_count = sum(1 for scan in user_scans if scan.get('result') == 'safe')
    phishing_count = sum(1 for scan in user_scans if scan.get('result') == 'phishing')
    
    return render_template('dashboard.html', 
                         remaining_scans=remaining_scans,
                         scans=user_scans[:5],
                         safe_count=safe_count,
                         phishing_count=phishing_count,
                         total_scans=len(user_scans))

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    # Check daily limit
    if current_user.daily_scans >= 10:
        flash('Daily scan limit reached (10 scans per day)', 'warning')
        return redirect(url_for('dashboard'))
    
    form = ScanForm()
    
    if form.validate_on_submit():
        url = form.url.data
        
        # Check URL format
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Extract features
        extractor = URLFeatureExtractor(url)
        features = extractor.extract_all_features()
        
        # Predict using ML model
        prediction, confidence, details = phishing_detector.predict(features)
        
        # Create scan record
        scan_id = str(uuid.uuid4())
        scan_record = {
            'id': scan_id,
            'user_id': current_user.id,
            'url': url,
            'result': 'phishing' if prediction == 1 else 'safe',
            'confidence': float(confidence),
            'details': details,
            'timestamp': datetime.now().isoformat(),
            'features': features
        }
        
        # Save scan
        scans = scan_handler.load_data()
        scans[scan_id] = scan_record
        scan_handler.save_data(scans)
        
        # Update user stats
        users = user_handler.load_data()
        if current_user.id in users:
            users[current_user.id]['scan_count'] = users[current_user.id].get('scan_count', 0) + 1
            users[current_user.id]['daily_scans'] = users[current_user.id].get('daily_scans', 0) + 1
            users[current_user.id]['last_scan_date'] = datetime.now().isoformat()
            user_handler.save_data(users)
        
        return redirect(url_for('scan_results', scan_id=scan_id))
    
    # Get user's recent scans (REAL DATA)
    scans = scan_handler.load_data()
    user_scans = [
        scan for scan in scans.values() 
        if scan['user_id'] == current_user.id
    ]
    user_scans.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('scan.html', form=form, scans=user_scans[:5])

@app.route('/results/<scan_id>')
@login_required
def scan_results(scan_id):
    scans = scan_handler.load_data()
    scan_data = scans.get(scan_id)
    
    if not scan_data or scan_data['user_id'] != current_user.id:
        flash('Scan not found', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('results.html', scan=scan_data)

@app.route('/history')
@login_required
def scan_history():
    scans = scan_handler.load_data()
    user_scans = [
        scan for scan in scans.values() 
        if scan['user_id'] == current_user.id
    ]
    user_scans.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Calculate statistics (REAL DATA)
    total_scans = len(user_scans)
    safe_scans = sum(1 for scan in user_scans if scan.get('result') == 'safe')
    phishing_scans = sum(1 for scan in user_scans if scan.get('result') == 'phishing')
    
    return render_template('history.html', 
                         scans=user_scans,
                         total_scans=total_scans,
                         safe_scans=safe_scans,
                         phishing_scans=phishing_scans)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = PasswordChangeForm()
    
    if form.validate_on_submit():
        if form.new_password.data != form.confirm_password.data:
            flash('New passwords do not match', 'danger')
        else:
            users = user_handler.load_data()
            user_data = users.get(current_user.id)
            
            if user_data and bcrypt.check_password_hash(user_data['password'], form.current_password.data):
                # Update password
                users[current_user.id]['password'] = bcrypt.generate_password_hash(
                    form.new_password.data
                ).decode('utf-8')
                user_handler.save_data(users)
                flash('Password updated successfully', 'success')
            else:
                flash('Current password is incorrect', 'danger')
    
    return render_template('settings.html', form=form)

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    # Load all data
    users = user_handler.load_data()
    scans = scan_handler.load_data()
    news = news_handler.load_data()
    admin_settings = admin_handler.load_data()
    
    # Calculate statistics (REAL DATA)
    total_users = len(users)
    total_scans = len(scans)
    
    # Daily scans
    today = datetime.now().date()
    daily_scans = sum(
        1 for scan in scans.values()
        if datetime.fromisoformat(scan['timestamp']).date() == today
    )
    
    # Success rate (safe scans)
    safe_scans = sum(1 for scan in scans.values() if scan['result'] == 'safe')
    success_rate = (safe_scans / total_scans * 100) if total_scans > 0 else 0
    
    # Most searched domains (REAL DATA)
    domain_count = {}
    for scan in scans.values():
        try:
            domain = urlparse(scan['url']).netloc
            if domain:
                domain_count[domain] = domain_count.get(domain, 0) + 1
        except:
            continue
    
    top_domains = sorted(domain_count.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Recent scans
    recent_scans = sorted(scans.values(), key=lambda x: x['timestamp'], reverse=True)[:10]
    
    # Create a user email lookup for recent scans
    user_emails = {user_id: user_data['email'] for user_id, user_data in users.items()}
    
    # User activity (REAL DATA)
    active_users = []
    for user_id, user_data in users.items():
        user_scans = sum(1 for scan in scans.values() if scan['user_id'] == user_id)
        active_users.append({
            'id': user_id,
            'email': user_data['email'],
            'total_scans': user_scans,
            'credit_points': user_data.get('credit_points', 0),
            'last_active': max(
                [scan['timestamp'] for scan in scans.values() if scan['user_id'] == user_id],
                default=None
            )
        })
    
    active_users.sort(key=lambda x: x['total_scans'], reverse=True)
    
    # Last 7 days statistics (REAL DATA)
    last_7_days = []
    last_7_days_safe = []
    last_7_days_phishing = []
    
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_str = day.strftime('%Y-%m-%d')
        
        day_safe = 0
        day_phishing = 0
        
        for scan in scans.values():
            try:
                scan_date = datetime.fromisoformat(scan['timestamp']).date()
                if scan_date == day:
                    if scan['result'] == 'safe':
                        day_safe += 1
                    else:
                        day_phishing += 1
            except:
                continue
        
        last_7_days.append(day_str[-5:])  # Get just MM-DD
        last_7_days_safe.append(day_safe)
        last_7_days_phishing.append(day_phishing)
    
    return render_template('admin/dashboard.html',
                         users=users,
                         user_emails=user_emails,
                         total_users=total_users,
                         total_scans=total_scans,
                         daily_scans=daily_scans,
                         success_rate=round(success_rate, 2),
                         top_domains=top_domains,
                         recent_scans=recent_scans,
                         active_users=active_users[:10],
                         admin_settings=admin_settings,
                         last_7_days=last_7_days,
                         last_7_days_safe=last_7_days_safe,
                         last_7_days_phishing=last_7_days_phishing)

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    users = user_handler.load_data()
    scans = scan_handler.load_data()
    
    # Add scan count to each user (REAL DATA)
    user_list = []
    for user_id, user_data in users.items():
        user_data_copy = user_data.copy()
        user_data_copy['scan_count'] = sum(
            1 for scan in scans.values() if scan['user_id'] == user_id
        )
        user_data_copy['id'] = user_id
        user_list.append(user_data_copy)
    
    # Calculate today's scans
    today = datetime.now().date()
    today_scans = sum(
        1 for scan in scans.values()
        if datetime.fromisoformat(scan['timestamp']).date() == today
    )
    
    return render_template('admin/users.html', 
                         users=users, 
                         user_list=user_list,
                         today_scans=today_scans)

@app.route('/admin/user/<user_id>', methods=['POST'])
@login_required
def admin_user_action(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    users = user_handler.load_data()
    
    if user_id not in users:
        return jsonify({'error': 'User not found'}), 404
    
    action = request.json.get('action')
    
    if action == 'delete':
        # Delete user scans first
        scans = scan_handler.load_data()
        scans = {sid: scan for sid, scan in scans.items() if scan['user_id'] != user_id}
        scan_handler.save_data(scans)
        
        # Delete user
        del users[user_id]
        user_handler.save_data(users)
        return jsonify({'message': 'User deleted successfully'})
    
    elif action == 'update':
        new_email = request.json.get('email')
        credit_points = request.json.get('credit_points')
        is_admin = request.json.get('is_admin')
        
        if new_email:
            users[user_id]['email'] = new_email
        if credit_points is not None:
            users[user_id]['credit_points'] = int(credit_points)
        if is_admin is not None:
            users[user_id]['is_admin'] = bool(is_admin)
        
        user_handler.save_data(users)
        return jsonify({'message': 'User updated successfully'})
    
    return jsonify({'error': 'Invalid action'}), 400

@app.route('/admin/maintenance', methods=['POST'])
@login_required
def toggle_maintenance():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    admin_settings = admin_handler.load_data()
    admin_settings['maintenance_mode'] = not admin_settings.get('maintenance_mode', False)
    admin_handler.save_data(admin_settings)
    
    return jsonify({
        'maintenance_mode': admin_settings['maintenance_mode']
    })

@app.route('/admin/news', methods=['POST'])
@login_required
def add_news():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    news = news_handler.load_data()
    if 'articles' not in news:
        news['articles'] = []
    
    new_article = {
        'id': str(uuid.uuid4()),
        'title': request.json.get('title'),
        'content': request.json.get('content'),
        'date': datetime.now().isoformat(),
        'author': 'Admin'
    }
    
    news['articles'].insert(0, new_article)
    # Keep only latest 10 articles
    news['articles'] = news['articles'][:10]
    
    news_handler.save_data(news)
    return jsonify({'message': 'News added successfully'})

@app.route('/admin/settings')
@login_required
def admin_settings():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    admin_settings = admin_handler.load_data()
    users = user_handler.load_data()
    scans = scan_handler.load_data()
    
    # Calculate real statistics
    total_users = len(users)
    total_scans = len(scans)
    
    # Get system information
    import platform
    import sys
    system_info = {
        'python_version': sys.version,
        'platform': platform.platform(),
        'flask_version': '3.0.0'
    }
    
    return render_template('admin/settings.html', 
                         settings=admin_settings,
                         total_users=total_users,
                         total_scans=total_scans,
                         system_info=system_info)

@app.route('/admin/update_settings', methods=['POST'])
@login_required
def update_admin_settings():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    admin_settings = admin_handler.load_data()
    
    # Update settings from form
    for key in ['site_name', 'contact_email', 'max_scans_per_day', 'default_credits', 'site_description']:
        if key in request.form:
            admin_settings[key] = request.form[key]
    
    admin_handler.save_data(admin_settings)
    flash('Settings updated successfully', 'success')
    return redirect(url_for('admin_settings'))

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('data', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('templates/admin', exist_ok=True)
    os.makedirs('ml_model', exist_ok=True)
    
    # Initialize data files if they don't exist
    if not os.path.exists('data/users.json'):
        with open('data/users.json', 'w') as f:
            json.dump({}, f)
    
    if not os.path.exists('data/scans.json'):
        with open('data/scans.json', 'w') as f:
            json.dump({}, f)
    
    if not os.path.exists('data/news.json'):
        with open('data/news.json', 'w') as f:
            json.dump({'articles': []}, f)
    
    if not os.path.exists('data/admin_settings.json'):
        with open('data/admin_settings.json', 'w') as f:
            json.dump({
                'maintenance_mode': False,
                'site_name': 'W3Guard',
                'contact_email': 'admin@w3guard.edu',
                'max_scans_per_day': 10,
                'default_credits': 10,
                'site_description': 'Advanced Phishing Detection System'
            }, f)
    
    # Initialize admin.json if it doesn't exist
    if not os.path.exists('data/admin.json'):
        print(f"\n{'='*60}")
        print(f"ADMIN CONFIGURATION NOT FOUND")
        print(f"{'='*60}")
        print(f"To initialize admin credentials, run:")
        print(f"  python admin_config.py init")
        print(f"\nOr for custom email:")
        print(f"  python admin_config.py email your-email@example.com")
        print(f"  python admin_config.py password YourPassword123!")
        print(f"{'='*60}\n")
    
    app.run(debug=True, host='0.0.0.0', port=5900)
