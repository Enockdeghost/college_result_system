# JRIIT Academic Result Management System (JARMS)
# Modern Flask-based system for JRIIT Arusha, Tanzania

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
import os
import uuid

# App Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jriit_results.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads/profiles'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'teacher', 'academic', 'student'
    email = db.Column(db.String(120), unique=True, nullable=True)
    full_name = db.Column(db.String(100), nullable=False)
    profile_picture = db.Column(db.String(200), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    must_change_password = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    registration_number = db.Column(db.String(20), unique=True, nullable=False)
    current_semester = db.Column(db.Integer, default=1)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'suspended'
    date_of_birth = db.Column(db.Date, nullable=True)
    phone_number = db.Column(db.String(15), nullable=True)
    address = db.Column(db.Text, nullable=True)
    
    user = db.relationship('User', backref='student_profile')
    
    def __repr__(self):
        return f'<Student {self.registration_number}>'

class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    department = db.Column(db.String(100), nullable=True)
    qualification = db.Column(db.String(200), nullable=True)
    phone_number = db.Column(db.String(15), nullable=True)
    
    user = db.relationship('User', backref='teacher_profile')
    
    def __repr__(self):
        return f'<Teacher {self.employee_id}>'

class Academic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    department = db.Column(db.String(100), nullable=True)
    
    user = db.relationship('User', backref='academic_profile')
    
    def __repr__(self):
        return f'<Academic {self.employee_id}>'

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_code = db.Column(db.String(20), unique=True, nullable=False)
    subject_name = db.Column(db.String(100), nullable=False)
    semester = db.Column(db.Integer, nullable=False)  # 1-6
    credit_hours = db.Column(db.Integer, default=3)
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Subject {self.subject_code}>'

class TeacherSubject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    teacher = db.relationship('Teacher', backref='assigned_subjects')
    subject = db.relationship('Subject', backref='assigned_teachers')

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)
    marks = db.Column(db.Float, nullable=False)
    grade = db.Column(db.String(2), nullable=False)
    semester = db.Column(db.Integer, nullable=False)
    academic_year = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), default='submitted')  # 'submitted', 'approved', 'rejected'
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    
    student = db.relationship('Student', backref='results')
    subject = db.relationship('Subject', backref='results')
    teacher = db.relationship('Teacher', backref='submitted_results')
    
    def __repr__(self):
        return f'<Result {self.student_id}-{self.subject_id}>'

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='activity_logs')

# Utility Functions
def log_activity(user_id, action, description, ip_address=None):
    """Log user activity"""
    log = ActivityLog(
        user_id=user_id,
        action=action,
        description=description,
        ip_address=ip_address or request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

def calculate_grade(marks):
    """Calculate letter grade based on marks"""
    if marks >= 80:
        return 'A'
    elif marks >= 70:
        return 'B+'
    elif marks >= 60:
        return 'B'
    elif marks >= 50:
        return 'C+'
    elif marks >= 40:
        return 'C'
    elif marks >= 30:
        return 'D+'
    elif marks >= 25:
        return 'D'
    else:
        return 'F'

def allowed_file(filename):
    """Check if file extension is allowed"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in roles:
                flash('Access denied: Insufficient permissions', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def password_change_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get('user_id'))
        if user and user.must_change_password:
            flash('You must change your password before proceeding', 'warning')
            return redirect(url_for('change_password'))
        return f(*args, **kwargs)
    return decorated_function

def student_approved_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') == 'student':
            student = Student.query.filter_by(user_id=session.get('user_id')).first()
            if not student or student.status != 'approved':
                flash('Your account is pending approval by admin', 'info')
                return render_template('student_pending.html')
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['full_name'] = user.full_name
            
            log_activity(user.id, 'LOGIN', f'User {user.username} logged in')
            
            flash(f'Welcome back, {user.full_name}!', 'success')
            
            if user.must_change_password:
                return redirect(url_for('change_password'))
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        full_name = request.form['full_name'].strip()
        email = request.form.get('email', '').strip()
        registration_number = request.form['registration_number'].strip()
        phone_number = request.form.get('phone_number', '').strip()
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return render_template('register.html')
        
        # Check if username or registration number already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')
        
        if Student.query.filter_by(registration_number=registration_number).first():
            flash('Registration number already exists', 'danger')
            return render_template('register.html')
        
        # Create user account
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            password=hashed_password,
            role='student',
            full_name=full_name,
            email=email,
            must_change_password=False
        )
        
        db.session.add(new_user)
        db.session.flush()  # To get the user ID
        
        # Create student profile
        new_student = Student(
            user_id=new_user.id,
            registration_number=registration_number,
            phone_number=phone_number,
            status='pending'
        )
        
        db.session.add(new_student)
        db.session.commit()
        
        log_activity(new_user.id, 'REGISTER', f'Student {registration_number} registered')
        
        flash('Registration successful! Please wait for admin approval.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    log_activity(session.get('user_id'), 'LOGOUT', f'User {session.get("username")} logged out')
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        new_username = request.form.get('new_username', '').strip()
        
        user = User.query.get(session['user_id'])
        
        # Verify current password
        if not check_password_hash(user.password, current_password):
            flash('Current password is incorrect', 'danger')
            return render_template('change_password.html')
        
        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return render_template('change_password.html')
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return render_template('change_password.html')
        
        # Check if new username is available (if provided)
        if new_username and new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                flash('Username already exists', 'danger')
                return render_template('change_password.html')
            user.username = new_username
            session['username'] = new_username
        
        # Update password
        user.password = generate_password_hash(new_password)
        user.must_change_password = False
        db.session.commit()
        
        log_activity(user.id, 'PASSWORD_CHANGE', 'Password changed successfully')
        
        flash('Password updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/dashboard')
@login_required
@student_approved_required
@password_change_required
def dashboard():
    role = session.get('role')
    
    if role == 'admin':
        # Admin dashboard stats
        total_users = User.query.count()
        pending_students = Student.query.filter_by(status='pending').count()
        total_subjects = Subject.query.count()
        recent_activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
        
        return render_template('admin_dashboard.html',
                             total_users=total_users,
                             pending_students=pending_students,
                             total_subjects=total_subjects,
                             recent_activities=recent_activities)
    
    elif role == 'teacher':
        teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
        assigned_subjects = TeacherSubject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
        pending_results = Result.query.filter_by(teacher_id=teacher.id, status='submitted').count()
        
        return render_template('teacher_dashboard.html',
                             teacher=teacher,
                             assigned_subjects=assigned_subjects,
                             pending_results=pending_results)
    
    elif role == 'academic':
        pending_results = Result.query.filter_by(status='submitted').count()
        approved_results = Result.query.filter_by(status='approved').count()
        total_subjects = Subject.query.count()
        
        return render_template('academic_dashboard.html',
                             pending_results=pending_results,
                             approved_results=approved_results,
                             total_subjects=total_subjects)
    
    elif role == 'student':
        student = Student.query.filter_by(user_id=session['user_id']).first()
        results = Result.query.filter_by(student_id=student.id, status='approved').all()
        
        # Calculate GPA
        total_points = 0
        total_credits = 0
        for result in results:
            grade_points = {'A': 4.0, 'B+': 3.5, 'B': 3.0, 'C+': 2.5, 'C': 2.0, 'D+': 1.5, 'D': 1.0, 'F': 0.0}
            points = grade_points.get(result.grade, 0.0)
            credits = result.subject.credit_hours
            total_points += points * credits
            total_credits += credits
        
        gpa = total_points / total_credits if total_credits > 0 else 0.0
        
        return render_template('student_dashboard.html',
                             student=student,
                             results=results,
                             gpa=round(gpa, 2))

# Admin Routes
@app.route('/admin/users')
@login_required
@role_required(['admin'])
@password_change_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
@password_change_required
def admin_add_user():
    if request.method == 'POST':
        role = request.form['role']
        username = request.form['username'].strip()
        full_name = request.form['full_name'].strip()
        email = request.form.get('email', '').strip()
        password = request.form['password']
        
        # Check if username exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('admin_add_user.html')
        
        # Create user
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            password=hashed_password,
            role=role,
            full_name=full_name,
            email=email,
            must_change_password=True,
            created_by=session['user_id']
        )
        
        db.session.add(new_user)
        db.session.flush()
        
        # Create profile based on role
        if role == 'teacher':
            employee_id = request.form['employee_id']
            department = request.form.get('department', '')
            
            teacher_profile = Teacher(
                user_id=new_user.id,
                employee_id=employee_id,
                department=department
            )
            db.session.add(teacher_profile)
        
        elif role == 'academic':
            employee_id = request.form['employee_id']
            department = request.form.get('department', '')
            
            academic_profile = Academic(
                user_id=new_user.id,
                employee_id=employee_id,
                department=department
            )
            db.session.add(academic_profile)
        
        db.session.commit()
        
        log_activity(session['user_id'], 'CREATE_USER', f'Created {role} account: {username}')
        
        flash(f'{role.title()} account created successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin_add_user.html')

@app.route('/admin/pending_students')
@login_required
@role_required(['admin'])
@password_change_required
def admin_pending_students():
    pending_students = Student.query.filter_by(status='pending').all()
    return render_template('admin_pending_students.html', students=pending_students)

@app.route('/admin/approve_student/<int:student_id>')
@login_required
@role_required(['admin'])
@password_change_required
def admin_approve_student(student_id):
    student = Student.query.get_or_404(student_id)
    student.status = 'approved'
    db.session.commit()
    
    log_activity(session['user_id'], 'APPROVE_STUDENT', f'Approved student: {student.registration_number}')
    
    flash(f'Student {student.registration_number} approved successfully!', 'success')
    return redirect(url_for('admin_pending_students'))

@app.route('/admin/reject_student/<int:student_id>')
@login_required
@role_required(['admin'])
@password_change_required
def admin_reject_student(student_id):
    student = Student.query.get_or_404(student_id)
    user = User.query.get(student.user_id)
    
    # Log before deletion
    log_activity(session['user_id'], 'REJECT_STUDENT', f'Rejected student: {student.registration_number}')
    
    # Delete student and user records
    db.session.delete(student)
    db.session.delete(user)
    db.session.commit()
    
    flash('Student registration rejected and removed', 'info')
    return redirect(url_for('admin_pending_students'))

# Teacher Routes
@app.route('/teacher/subjects')
@login_required
@role_required(['teacher'])
@password_change_required
def teacher_subjects():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    assigned_subjects = TeacherSubject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
    return render_template('teacher_subjects.html', assigned_subjects=assigned_subjects)

@app.route('/teacher/add_result', methods=['GET', 'POST'])
@login_required
@role_required(['teacher'])
@password_change_required
def teacher_add_result():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'POST':
        registration_number = request.form['registration_number'].strip()
        subject_id = int(request.form['subject_id'])
        marks = float(request.form['marks'])
        academic_year = request.form['academic_year']
        
        # Find student
        student = Student.query.filter_by(registration_number=registration_number, status='approved').first()
        if not student:
            flash('Student not found or not approved', 'danger')
            return redirect(url_for('teacher_add_result'))
        
        # Get subject and validate semester
        subject = Subject.query.get(subject_id)
        semester = subject.semester
        
        # Validate marks
        if marks < 0 or marks > 100:
            flash('Marks must be between 0 and 100', 'danger')
            return redirect(url_for('teacher_add_result'))
        
        # Calculate grade
        grade = calculate_grade(marks)
        
        # Check if result already exists
        existing_result = Result.query.filter_by(
            student_id=student.id,
            subject_id=subject_id,
            semester=semester,
            academic_year=academic_year
        ).first()
        
        if existing_result:
            if existing_result.status != 'submitted':
                flash('Result already approved and cannot be modified', 'danger')
                return redirect(url_for('teacher_add_result'))
            
            # Update existing result
            existing_result.marks = marks
            existing_result.grade = grade
            existing_result.submitted_at = datetime.utcnow()
            
            log_activity(session['user_id'], 'UPDATE_RESULT', 
                        f'Updated result for {registration_number} in {subject.subject_code}')
            flash('Result updated successfully', 'success')
        else:
            # Create new result
            new_result = Result(
                student_id=student.id,
                subject_id=subject_id,
                teacher_id=teacher.id,
                marks=marks,
                grade=grade,
                semester=semester,
                academic_year=academic_year,
                status='submitted'
            )
            db.session.add(new_result)
            
            log_activity(session['user_id'], 'ADD_RESULT', 
                        f'Added result for {registration_number} in {subject.subject_code}')
            flash('Result submitted successfully', 'success')
        
        db.session.commit()
        return redirect(url_for('teacher_subjects'))
    
    # Get assigned subjects
    assigned_subjects = TeacherSubject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
    return render_template('teacher_add_result.html', assigned_subjects=assigned_subjects)

# Academic Routes
@app.route('/academic/results')
@login_required
@role_required(['academic'])
@password_change_required
def academic_results():
    results = Result.query.filter_by(status='submitted').all()
    return render_template('academic_results.html', results=results)

@app.route('/academic/approve_result/<int:result_id>')
@login_required
@role_required(['academic'])
@password_change_required
def academic_approve_result(result_id):
    result = Result.query.get_or_404(result_id)
    result.status = 'approved'
    result.reviewed_by = session['user_id']
    result.reviewed_at = datetime.utcnow()
    db.session.commit()
    
    log_activity(session['user_id'], 'APPROVE_RESULT', 
                f'Approved result for student {result.student.registration_number}')
    
    flash('Result approved successfully', 'success')
    return redirect(url_for('academic_results'))

@app.route('/academic/subjects')
@login_required
@role_required(['academic', 'admin'])
@password_change_required
def academic_subjects():
    subjects = Subject.query.all()
    return render_template('academic_subjects.html', subjects=subjects)

@app.route('/academic/add_subject', methods=['GET', 'POST'])
@login_required
@role_required(['academic', 'admin'])
@password_change_required
def academic_add_subject():
    if request.method == 'POST':
        subject_code = request.form['subject_code'].strip().upper()
        subject_name = request.form['subject_name'].strip()
        semester = int(request.form['semester'])
        credit_hours = int(request.form['credit_hours'])
        
        # Check if subject code exists
        if Subject.query.filter_by(subject_code=subject_code).first():
            flash('Subject code already exists', 'danger')
            return render_template('academic_add_subject.html')
        
        # Create subject
        new_subject = Subject(
            subject_code=subject_code,
            subject_name=subject_name,
            semester=semester,
            credit_hours=credit_hours,
            created_by=session['user_id']
        )
        
        db.session.add(new_subject)
        db.session.commit()
        
        log_activity(session['user_id'], 'ADD_SUBJECT', f'Added subject: {subject_code}')
        
        flash('Subject added successfully', 'success')
        return redirect(url_for('academic_subjects'))
    
    return render_template('academic_add_subject.html')

# Profile Management
@app.route('/profile', methods=['GET', 'POST'])
@login_required
@password_change_required
def profile():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        # Handle profile picture upload
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename and allowed_file(file.filename):
                filename = str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower()
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # Delete old profile picture
                if user.profile_picture:
                    old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_picture)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                
                user.profile_picture = filename
                db.session.commit()
                
                log_activity(user.id, 'UPDATE_PROFILE', 'Updated profile picture')
                flash('Profile picture updated successfully', 'success')
        
        # Handle other profile updates
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        
        if full_name:
            user.full_name = full_name
            session['full_name'] = full_name
        
        if email:
            user.email = email
        
        db.session.commit()
        log_activity(user.id, 'UPDATE_PROFILE', 'Updated profile information')
        flash('Profile updated successfully', 'success')
        
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user)

# API Routes for AJAX requests
@app.route('/api/search_students')
@login_required
@role_required(['teacher', 'academic', 'admin'])
def api_search_students():
    query = request.args.get('q', '').strip()
    if len(query) < 2:
        return jsonify([])
    
    students = Student.query.filter(
        Student.registration_number.contains(query),
        Student.status == 'approved'
    ).limit(10).all()
    
    results = []
    for student in students:
        results.append({
            'id': student.id,
            'registration_number': student.registration_number,
            'name': student.user.full_name,
            'semester': student.current_semester
        })
    
    return jsonify(results)

@app.route('/api/subject_teachers/<int:subject_id>')
@login_required
@role_required(['academic', 'admin'])
def api_subject_teachers(subject_id):
    assigned_teachers = TeacherSubject.query.filter_by(
        subject_id=subject_id, 
        is_active=True
    ).all()
    
    results = []
    for assignment in assigned_teachers:
        results.append({
            'teacher_id': assignment.teacher.id,
            'teacher_name': assignment.teacher.user.full_name,
            'employee_id': assignment.teacher.employee_id
        })
    
    return jsonify(results)

# Reports and Analytics
@app.route('/reports')
@login_required
@role_required(['admin', 'academic'])
@password_change_required
def reports():
    # Performance statistics
    total_students = Student.query.filter_by(status='approved').count()
    total_results = Result.query.filter_by(status='approved').count()
    pending_results = Result.query.filter_by(status='submitted').count()
    
    # Grade distribution
    grade_distribution = {}
    grades = ['A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'F']
    for grade in grades:
        count = Result.query.filter_by(grade=grade, status='approved').count()
        grade_distribution[grade] = count
    
    # Top performing students
    top_students = db.session.query(
        Student.registration_number,
        User.full_name,
        db.func.avg(Result.marks).label('avg_marks')
    ).join(User).join(Result).filter(
        Result.status == 'approved'
    ).group_by(
        Student.id
    ).order_by(
        db.func.avg(Result.marks).desc()
    ).limit(10).all()
    
    return render_template('reports.html',
                         total_students=total_students,
                         total_results=total_results,
                         pending_results=pending_results,
                         grade_distribution=grade_distribution,
                         top_students=top_students)

@app.route('/assign_teacher', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'academic'])
@password_change_required
def assign_teacher():
    if request.method == 'POST':
        teacher_id = int(request.form['teacher_id'])
        subject_id = int(request.form['subject_id'])
        
        # Check if assignment already exists
        existing = TeacherSubject.query.filter_by(
            teacher_id=teacher_id,
            subject_id=subject_id,
            is_active=True
        ).first()
        
        if existing:
            flash('Teacher is already assigned to this subject', 'warning')
        else:
            assignment = TeacherSubject(
                teacher_id=teacher_id,
                subject_id=subject_id,
                assigned_by=session['user_id']
            )
            db.session.add(assignment)
            db.session.commit()
            
            teacher = Teacher.query.get(teacher_id)
            subject = Subject.query.get(subject_id)
            
            log_activity(session['user_id'], 'ASSIGN_TEACHER', 
                        f'Assigned {teacher.user.full_name} to {subject.subject_code}')
            
            flash('Teacher assigned successfully', 'success')
        
        return redirect(url_for('assign_teacher'))
    
    teachers = Teacher.query.all()
    subjects = Subject.query.all()
    assignments = TeacherSubject.query.filter_by(is_active=True).all()
    
    return render_template('assign_teacher.html', 
                         teachers=teachers, 
                         subjects=subjects, 
                         assignments=assignments)

@app.route('/remove_teacher_assignment/<int:assignment_id>')
@login_required
@role_required(['admin', 'academic'])
@password_change_required
def remove_teacher_assignment(assignment_id):
    assignment = TeacherSubject.query.get_or_404(assignment_id)
    assignment.is_active = False
    db.session.commit()
    
    log_activity(session['user_id'], 'REMOVE_ASSIGNMENT', 
                f'Removed teacher assignment: {assignment.teacher.user.full_name} from {assignment.subject.subject_code}')
    
    flash('Teacher assignment removed', 'success')
    return redirect(url_for('assign_teacher'))

@app.route('/system_logs')
@login_required
@role_required(['admin'])
@password_change_required
def system_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    logs = ActivityLog.query.order_by(
        ActivityLog.timestamp.desc()
    ).paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )
    
    return render_template('system_logs.html', logs=logs)

@app.route('/toggle_user_status/<int:user_id>')
@login_required
@role_required(['admin'])
@password_change_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == session['user_id']:
        flash('You cannot deactivate your own account', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_active = not user.is_active
    status = 'activated' if user.is_active else 'deactivated'
    
    db.session.commit()
    
    log_activity(session['user_id'], 'TOGGLE_USER_STATUS', 
                f'User {user.username} {status}')
    
    flash(f'User {user.username} has been {status}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/academic/edit_result/<int:result_id>', methods=['GET', 'POST'])
@login_required
@role_required(['academic'])
@password_change_required
def academic_edit_result(result_id):
    result = Result.query.get_or_404(result_id)
    
    if request.method == 'POST':
        new_marks = float(request.form['marks'])
        comments = request.form.get('comments', '').strip()
        
        if new_marks < 0 or new_marks > 100:
            flash('Marks must be between 0 and 100', 'danger')
            return render_template('academic_edit_result.html', result=result)
        
        old_marks = result.marks
        result.marks = new_marks
        result.grade = calculate_grade(new_marks)
        result.comments = comments
        result.reviewed_by = session['user_id']
        result.reviewed_at = datetime.utcnow()
        
        db.session.commit()
        
        log_activity(session['user_id'], 'EDIT_RESULT', 
                    f'Modified result for {result.student.registration_number}: {old_marks} -> {new_marks}')
        
        flash('Result updated successfully', 'success')
        return redirect(url_for('academic_results'))
    
    return render_template('academic_edit_result.html', result=result)

@app.route('/academic/reject_result/<int:result_id>', methods=['POST'])
@login_required
@role_required(['academic'])
@password_change_required
def academic_reject_result(result_id):
    result = Result.query.get_or_404(result_id)
    comments = request.form.get('comments', '').strip()
    
    result.status = 'rejected'
    result.comments = comments
    result.reviewed_by = session['user_id']
    result.reviewed_at = datetime.utcnow()
    
    db.session.commit()
    
    log_activity(session['user_id'], 'REJECT_RESULT', 
                f'Rejected result for {result.student.registration_number}')
    
    flash('Result rejected and sent back to teacher', 'info')
    return redirect(url_for('academic_results'))

@app.route('/teacher/rejected_results')
@login_required
@role_required(['teacher'])
@password_change_required
def teacher_rejected_results():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    rejected_results = Result.query.filter_by(
        teacher_id=teacher.id, 
        status='rejected'
    ).all()
    
    return render_template('teacher_rejected_results.html', 
                         rejected_results=rejected_results)

@app.route('/teacher/resubmit_result/<int:result_id>', methods=['POST'])
@login_required
@role_required(['teacher'])
@password_change_required
def teacher_resubmit_result(result_id):
    result = Result.query.get_or_404(result_id)
    
    if result.status != 'rejected':
        flash('This result cannot be resubmitted', 'danger')
        return redirect(url_for('teacher_rejected_results'))
    
    new_marks = float(request.form['marks'])
    
    if new_marks < 0 or new_marks > 100:
        flash('Marks must be between 0 and 100', 'danger')
        return redirect(url_for('teacher_rejected_results'))
    
    result.marks = new_marks
    result.grade = calculate_grade(new_marks)
    result.status = 'submitted'
    result.submitted_at = datetime.utcnow()
    result.comments = None  # Clear previous comments
    
    db.session.commit()
    
    log_activity(session['user_id'], 'RESUBMIT_RESULT', 
                f'Resubmitted result for {result.student.registration_number}')
    
    flash('Result resubmitted successfully', 'success')
    return redirect(url_for('teacher_rejected_results'))

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# Initialize Database
def init_db():
    """Initialize database with default admin user"""
    with app.app_context():
        db.create_all()
        
        # Create default admin if not exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            default_admin = User(
                username='admin',
                password=generate_password_hash('admin123'),
                role='admin',
                full_name='System Administrator',
                email='admin@jriit.ac.tz',
                must_change_password=True,
                is_active=True
            )
            db.session.add(default_admin)
            
            # Add some sample subjects
            subjects_data = [
                ('CS101', 'Introduction to Computer Science', 1, 3),
                ('MATH101', 'Calculus I', 1, 4),
                ('ENG101', 'English Communication', 1, 2),
                ('CS201', 'Data Structures', 2, 3),
                ('MATH201', 'Calculus II', 2, 4),
                ('CS301', 'Database Systems', 3, 3),
                ('CS302', 'Software Engineering', 3, 4),
                ('CS401', 'Machine Learning', 4, 3),
                ('CS501', 'Advanced Algorithms', 5, 4),
                ('CS601', 'Final Year Project', 6, 6),
            ]
            
            for code, name, semester, credits in subjects_data:
                subject = Subject(
                    subject_code=code,
                    subject_name=name,
                    semester=semester,
                    credit_hours=credits,
                    created_by=1  # Will be created after admin user
                )
                db.session.add(subject)
            
            db.session.commit()
            print("Database initialized with default admin user (username: admin, password: admin123)")
            print("Please change the default password after first login!")

# Application startup
if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
