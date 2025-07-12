# import module 
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
import osll
# database 
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jriit_results.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads/profiles'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# DATABASE MODELS 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'teacher', 'academic', 'student'
    first_login = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)
    profile_picture = db.Column(db.String(200), default='default.png')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    roll_number = db.Column(db.String(20), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    course = db.Column(db.String(50), nullable=False)
    semester = db.Column(db.Integer, nullable=False)  # 1-6
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship('User', backref='student_profile', foreign_keys=[user_id])

class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    full_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(100), nullable=True)
    
    user = db.relationship('User', backref='teacher_profile', foreign_keys=[user_id])

class Academic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    full_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    
    user = db.relationship('User', backref='academic_profile', foreign_keys=[user_id])

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_code = db.Column(db.String(20), unique=True, nullable=False)
    subject_name = db.Column(db.String(100), nullable=False)
    semester = db.Column(db.Integer, nullable=False)  # 1-6
    course = db.Column(db.String(50), nullable=False)
    credits = db.Column(db.Integer, default=3)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=True)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    teacher = db.relationship('Teacher', backref='subjects')

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    marks = db.Column(db.Float, nullable=False)
    grade = db.Column(db.String(2), nullable=False)
    gpa = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    submitted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    is_final = db.Column(db.Boolean, default=False)  # Once approved, becomes final
    
    student = db.relationship('Student', backref='results')
    subject = db.relationship('Subject', backref='results')

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    
    user = db.relationship('User', backref='activity_logs')

# ===== CONSTANTS =====
COURSES = [
    'Cyber Security',
    'Tourism',
    'Information Technology (IT)',
    'Graphics Design',
    'Electronics',
    'Business Studies'
]

DEPARTMENTS = [
    'Computer Science',
    'Tourism & Hospitality',
    'Electronics Engineering',
    'Business Administration',
    'Design & Media'
]

# ===== UTILITY FUNCTIONS =====
def log_activity(user_id, action, details=None, ip_address=None):
    """Log user activity"""
    log = ActivityLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip_address
    )
    db.session.add(log)
    db.session.commit()

def calculate_grade_and_gpa(marks):
    """Calculate grade and GPA based on marks"""
    if marks >= 90:
        return 'A+', 4.0
    elif marks >= 85:
        return 'A', 3.7
    elif marks >= 80:
        return 'A-', 3.3
    elif marks >= 75:
        return 'B+', 3.0
    elif marks >= 70:
        return 'B', 2.7
    elif marks >= 65:
        return 'B-', 2.3
    elif marks >= 60:
        return 'C+', 2.0
    elif marks >= 55:
        return 'C', 1.7
    elif marks >= 50:
        return 'C-', 1.3
    elif marks >= 45:
        return 'D+', 1.0
    elif marks >= 40:
        return 'D', 0.7
    else:
        return 'F', 0.0

def allowed_file(filename):
    """Check if uploaded file is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# ===== DECORATORS =====
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in roles:
                flash('Access denied: Insufficient permissions', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def first_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get('user_id'))
        if user and user.first_login:
            return redirect(url_for('change_credentials'))
        return f(*args, **kwargs)
    return decorated_function

def student_approved_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') == 'student':
            student = Student.query.filter_by(user_id=session.get('user_id')).first()
            if not student or student.status != 'approved':
                flash('Your account is pending approval. Please wait for admin approval.', 'warning')
                return redirect(url_for('pending_approval'))
        return f(*args, **kwargs)
    return decorated_function

# ===== MAIN ROUTES =====
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
            
            # Log activity
            log_activity(user.id, 'Login', f'User {username} logged in', request.remote_addr)
            
            flash('Login successful!', 'success')
            
            # Check if first login
            if user.first_login:
                return redirect(url_for('change_credentials'))
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    user_id = session.get('user_id')
    
    # Log activity
    if user_id:
        log_activity(user_id, 'Logout', f'User {username} logged out', request.remote_addr)
    
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/change-credentials', methods=['GET', 'POST'])
@login_required
def change_credentials():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        new_username = request.form['username'].strip()
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('change_credentials.html', user=user)
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('change_credentials.html', user=user)
        
        # Check if username is already taken
        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user and existing_user.id != user.id:
            flash('Username already exists', 'error')
            return render_template('change_credentials.html', user=user)
        
        # Update credentials
        user.username = new_username
        user.password = generate_password_hash(new_password)
        user.first_login = False
        
        db.session.commit()
        
        # Update session
        session['username'] = new_username
        
        # Log activity
        log_activity(user.id, 'Credentials Changed', 'User changed username and password', request.remote_addr)
        
        flash('Credentials updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_credentials.html', user=user)

@app.route('/upload-profile-picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('profile'))
    
    file = request.files['profile_picture']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('profile'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(f"user_{session['user_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file.filename.rsplit('.', 1)[1].lower()}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Update user profile
        user = User.query.get(session['user_id'])
        user.profile_picture = filename
        db.session.commit()
        
        # Log activity
        log_activity(session['user_id'], 'Profile Picture Updated', 'User uploaded new profile picture', request.remote_addr)
        
        flash('Profile picture updated successfully!', 'success')
    else:
        flash('Invalid file type. Please upload PNG, JPG, JPEG, or GIF files only.', 'error')
    
    return redirect(url_for('profile'))

@app.route('/profile')
@login_required
@first_login_required
def profile():
    user = User.query.get(session['user_id'])
    role_profile = None
    
    if user.role == 'teacher':
        role_profile = Teacher.query.filter_by(user_id=user.id).first()
    elif user.role == 'academic':
        role_profile = Academic.query.filter_by(user_id=user.id).first()
    elif user.role == 'student':
        role_profile = Student.query.filter_by(user_id=user.id).first()
    
    return render_template('profile.html', user=user, role_profile=role_profile)

# ===== DASHBOARD ROUTES =====
@app.route('/dashboard')
@login_required
@first_login_required
@student_approved_required
def dashboard():
    role = session.get('role')
    
    if role == 'admin':
        return admin_dashboard()
    elif role == 'teacher':
        return teacher_dashboard()
    elif role == 'academic':
        return academic_dashboard()
    elif role == 'student':
        return student_dashboard()
    else:
        flash('Invalid role', 'error')
        return redirect(url_for('logout'))

def admin_dashboard():
    # Get statistics
    total_users = User.query.count()
    pending_students = Student.query.filter_by(status='pending').count()
    total_teachers = Teacher.query.count()
    total_subjects = Subject.query.count()
    total_results = Result.query.count()
    
    # Recent activities
    recent_activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    
    # Pending students
    pending_students_list = Student.query.filter_by(status='pending').all()
    
    # System overview
    courses_stats = {}
    for course in COURSES:
        courses_stats[course] = {
            'students': Student.query.filter_by(course=course, status='approved').count(),
            'subjects': Subject.query.filter_by(course=course).count()
        }
    
    return render_template('admin_dashboard.html', 
                         total_users=total_users,
                         pending_students=pending_students,
                         total_teachers=total_teachers,
                         total_subjects=total_subjects,
                         total_results=total_results,
                         recent_activities=recent_activities,
                         pending_students_list=pending_students_list,
                         courses_stats=courses_stats)

def teacher_dashboard():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    if not teacher:
        flash('Teacher profile not found', 'error')
        return redirect(url_for('logout'))
    
    # Get assigned subjects
    subjects = Subject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
    
    # Get statistics
    total_subjects = len(subjects)
    pending_results = Result.query.filter_by(submitted_by=session['user_id'], status='pending').count()
    approved_results = Result.query.filter_by(submitted_by=session['user_id'], status='approved').count()
    
    # Get students in teacher's subjects
    students_count = db.session.query(Student).join(Result).join(Subject).filter(
        Subject.teacher_id == teacher.id,
        Student.status == 'approved'
    ).distinct().count()
    
    return render_template('teacher_dashboard.html', 
                         teacher=teacher,
                         subjects=subjects,
                         total_subjects=total_subjects,
                         pending_results=pending_results,
                         approved_results=approved_results,
                         students_count=students_count)

def academic_dashboard():
    academic = Academic.query.filter_by(user_id=session['user_id']).first()
    if not academic:
        flash('Academic profile not found', 'error')
        return redirect(url_for('logout'))
    
    # Get pending results for review
    pending_results = Result.query.filter_by(status='pending').count()
    approved_results = Result.query.filter_by(status='approved').count()
    rejected_results = Result.query.filter_by(status='rejected').count()
    
    # Get subjects without teachers
    unassigned_subjects = Subject.query.filter_by(teacher_id=None, is_active=True).count()
    
    # Get recent pending results
    recent_pending = Result.query.filter_by(status='pending').order_by(Result.submitted_at.desc()).limit(5).all()
    
    return render_template('academic_dashboard.html',
                         academic=academic,
                         pending_results=pending_results,
                         approved_results=approved_results,
                         rejected_results=rejected_results,
                         unassigned_subjects=unassigned_subjects,
                         recent_pending=recent_pending)

def student_dashboard():
    student = Student.query.filter_by(user_id=session['user_id']).first()
    if not student:
        flash('Student profile not found', 'error')
        return redirect(url_for('logout'))
    
    # Get approved results
    results = db.session.query(Result, Subject).join(Subject).filter(
        Result.student_id == student.id,
        Result.status == 'approved'
    ).order_by(Subject.semester, Subject.subject_name).all()
    
    # Group results by semester
    results_by_semester = {}
    total_gpa = 0
    total_credits = 0
    
    for result, subject in results:
        semester = subject.semester
        if semester not in results_by_semester:
            results_by_semester[semester] = {
                'results': [],
                'semester_gpa': 0,
                'semester_credits': 0
            }
        
        results_by_semester[semester]['results'].append({
            'subject': subject,
            'result': result
        })
        
        # Calculate GPA
        results_by_semester[semester]['semester_gpa'] += result.gpa * subject.credits
        results_by_semester[semester]['semester_credits'] += subject.credits
        total_gpa += result.gpa * subject.credits
        total_credits += subject.credits
    
    # Calculate semester GPAs
    for semester in results_by_semester:
        if results_by_semester[semester]['semester_credits'] > 0:
            results_by_semester[semester]['semester_gpa'] /= results_by_semester[semester]['semester_credits']
    
    # Calculate overall GPA
    overall_gpa = total_gpa / total_credits if total_credits > 0 else 0
    
    return render_template('student_dashboard.html',
                         student=student,
                         results_by_semester=results_by_semester,
                         overall_gpa=round(overall_gpa, 2),
                         total_credits=total_credits)

@app.route('/pending-approval')
@login_required
def pending_approval():
    if session.get('role') != 'student':
        return redirect(url_for('dashboard'))
    
    student = Student.query.filter_by(user_id=session['user_id']).first()
    return render_template('pending_approval.html', student=student)

# ===== ADMIN ROUTES =====
@app.route('/admin/create-user', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
@first_login_required
def create_user():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        role = request.form['role']
        full_name = request.form['full_name']
        
        # Check if username exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('create_user.html', courses=COURSES, departments=DEPARTMENTS)
        
        # Create user
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            password=hashed_password,
            role=role,
            created_by=session['user_id']
        )
        db.session.add(new_user)
        db.session.flush()  # Get the user ID
        
        # Create role-specific profile
        if role == 'teacher':
            department = request.form['department']
            phone = request.form.get('phone', '')
            email = request.form.get('email', '')
            teacher = Teacher(
                user_id=new_user.id,
                full_name=full_name,
                department=department,
                phone=phone,
                email=email
            )
            db.session.add(teacher)
        elif role == 'academic':
            department = request.form['department']
            academic = Academic(
                user_id=new_user.id,
                full_name=full_name,
                department=department
            )
            db.session.add(academic)
        
        db.session.commit()
        
        # Log activity
        log_activity(session['user_id'], 'User Created', 
                    f'Created {role} account for {full_name} ({username})', 
                    request.remote_addr)
        
        flash(f'{role.title()} account created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('create_user.html', courses=COURSES, departments=DEPARTMENTS)

@app.route('/admin/manage-users')
@login_required
@role_required(['admin'])
@first_login_required
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/approve-student/<int:student_id>')
@login_required
@role_required(['admin'])
@first_login_required
def approve_student(student_id):
    student = Student.query.get_or_404(student_id)
    student.status = 'approved'
    student.approved_by = session['user_id']
    student.approved_at = datetime.utcnow()
    
    db.session.commit()
    
    # Log activity
    log_activity(session['user_id'], 'Student Approved', 
                f'Approved student {student.full_name} ({student.roll_number})', 
                request.remote_addr)
    
    flash('Student approved successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject-student/<int:student_id>')
@login_required
@role_required(['admin'])
@first_login_required
def reject_student(student_id):
    student = Student.query.get_or_404(student_id)
    student.status = 'rejected'
    
    db.session.commit()
    
    # Log activity
    log_activity(session['user_id'], 'Student Rejected', 
                f'Rejected student {student.full_name} ({student.roll_number})', 
                request.remote_addr)
    
    flash('Student rejected!', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle-user/<int:user_id>')
@login_required
@role_required(['admin'])
@first_login_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == session['user_id']:
        flash('You cannot deactivate your own account!', 'error')
        return redirect(url_for('manage_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    log_activity(session['user_id'], f'User {status.title()}', 
                f'{status.title()} user {user.username}', 
                request.remote_addr)
    
    flash(f'User {status} successfully!', 'success')
    return redirect(url_for('manage_users'))

# ===== TEACHER ROUTES =====
@app.route('/teacher/subjects')
@login_required
@role_required(['teacher'])
@first_login_required
def teacher_subjects():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    subjects = Subject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
    return render_template('teacher_subjects.html', subjects=subjects, teacher=teacher)

@app.route('/teacher/add-result', methods=['GET', 'POST'])
@login_required
@role_required(['teacher'])
@first_login_required
def add_result():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'POST':
        student_id = request.form['student_id']
        subject_id = request.form['subject_id']
        marks = float(request.form['marks'])
        comments = request.form.get('comments', '')
        
        # Validate marks
        if marks < 0 or marks > 100:
            flash('Marks must be between 0 and 100', 'error')
            return redirect(url_for('add_result'))
        
        # Check if result already exists
        existing_result = Result.query.filter_by(student_id=student_id, subject_id=subject_id).first()
        if existing_result:
            flash('Result already exists for this student and subject', 'error')
            return redirect(url_for('add_result'))
        
        # Calculate grade and GPA
        grade, gpa = calculate_grade_and_gpa(marks)
        
        # Create result
        result = Result(
            student_id=student_id,
            subject_id=subject_id,
            marks=marks,
            grade=grade,
            gpa=gpa,
            submitted_by=session['user_id'],
            comments=comments
        )
        
        db.session.add(result)
        db.session.commit()
        
        # Log activity
        student = Student.query.get(student_id)
        subject = Subject.query.get(subject_id)
        log_activity(session['user_id'], 'Result Added', 
                    f'Added result for {student.full_name} in {subject.subject_name} - Grade: {grade}', 
                    request.remote_addr)
        
        flash('Result added successfully! Waiting for academic approval.', 'success')
        return redirect(url_for('teacher_subjects'))
    
    # Get teacher's subjects and students
    subjects = Subject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
    
    # Get students for the teacher's subjects
    students = db.session.query(Student).join(Result, Student.id == Result.student_id, isouter=True).join(
        Subject, Result.subject_id == Subject.id, isouter=True
    ).filter(
        Student.status == 'approved',
        Student.course.in_([s.course for s in subjects])
    ).distinct().all()
    
    return render_template('add_result.html', subjects=subjects, students=students, teacher=teacher)

@app.route('/teacher/my-results')
@login_required
@role_required(['teacher'])
@first_login_required
def teacher_results():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    # Get results submitted by this teacher
    results = db.session.query(Result, Student, Subject).join(
        Student, Result.student_id == Student.id
    ).join(
        Subject, Result.subject_id == Subject.id
    ).filter(
        Result.submitted_by == session['user_id']
    ).order_by(Result.submitted_at.desc()).all()
    
    return render_template('teacher_results.html', results=results, teacher=teacher)

# ===== ACADEMIC ROUTES =====
@app.route('/academic/subjects')
@login_required
@role_required(['academic'])
@first_login_required
def academic_subjects():
    subjects = Subject.query.filter_by(is_active=True).all()
    teachers = Teacher.query.all()
    return render_template('academic_subjects.html', subjects=subjects, teachers=teachers)

@app.route('/academic/add-subject', methods=['GET', 'POST'])
@login_required
@role_required(['academic'])
@first_login_required
def add_subject():
    if request.method == 'POST':
        subject_code = request.form['subject_code'].strip().upper()
        subject_name = request.form['subject_name'].strip()
        semester = int(request.form['semester'])
        course = request.form['course']
        credits = int(request.form.get('credits', 3))
        teacher_id = request.form.get('teacher_id')
        
        # Check if subject code exists
        existing_subject = Subject.query.filter_by(subject_code=subject_code).first()
        if existing_subject:
            flash('Subject code already exists', 'error')
            return redirect(url_for('add_subject'))
        
        # Create subject
        subject = Subject(
            subject_code=subject_code,
            subject_name=subject_name,
            semester=semester,
            course=course,
            credits=credits,
            teacher_id=teacher_id if teacher_id else None,
            assigned_by=session['user_id']
        )
        
        db.session.add(subject)
        db.session.commit()
        
        # Log activity
        teacher_name = Teacher.query.get(teacher_id).full_name if teacher_id else 'Unassigned'
        log_activity(session['user_id'], 'Subject Added', 
                    f'Added subject {subject_name} ({subject_code}) - Teacher: {teacher_name}', 
                    request.remote_addr)
        
        flash('Subject added successfully!', 'success')
        return redirect(url_for('academic_subjects'))
    
    teachers = Teacher.query.all()
    return render_template('add_subject.html', courses=COURSES, teachers=teachers)

@app.route('/academic/assign-teacher/<int:subject_id>', methods=['POST'])
@login_required
@role_required(['academic'])
@first_login_required
def assign_teacher(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    teacher_id = request.form['teacher_id']
    
    if teacher_id:
        teacher = Teacher.query.get(teacher_id)
        subject.teacher_id = teacher_id
        db.session.commit()
        
        # Log activity
        log_activity(session['user_id'], 'Teacher Assigned', 
                    f'Assigned {teacher.full_name} to {subject.subject_name}', 
                    request.remote_addr)
        
        flash('Teacher assigned successfully!', 'success')
    else:
        subject.teacher_id = None
        db.session.commit()
        flash('Teacher unassigned from subject', 'info')
    
    return redirect(url_for('academic_subjects'))

@app.route('/academic/review-results')
@login_required
@role_required(['academic'])
@first_login_required
def review_results():
    # Get pending results
    pending_results = db.session.query(Result, Student, Subject, Teacher).join(
        Student, Result.student_id == Student.id
    ).join(
        Subject, Result.subject_id == Subject.id
    ).join(
        Teacher, Subject.teacher_id == Teacher.id
    ).filter(
        Result.status == 'pending'
    ).order_by(Result.submitted_at.asc()).all()
    
    return render_template('review_results.html', pending_results=pending_results)

@app.route('/academic/approve-result/<int:result_id>')
@login_required
@role_required(['academic'])
@first_login_required
def approve_result(result_id):
    result = Result.query.get_or_404(result_id)
    
    # Check if result is already final
    if result.is_final:
        flash('This result is already final and cannot be modified', 'error')
        return redirect(url_for('review_results'))
    
    result.status = 'approved'
    result.approved_by = session['user_id']
    result.approved_at = datetime.utcnow()
    result.is_final = True  # Make it final once approved
    
    db.session.commit()
    
    # Log activity
    student = Student.query.get(result.student_id)
    subject = Subject.query.get(result.subject_id)
    log_activity(session['user_id'], 'Result Approved', 
                f'Approved result for {student.full_name} in {subject.subject_name} - Grade: {result.grade}', 
                request.remote_addr)
    
    flash('Result approved successfully!', 'success')
    return redirect(url_for('review_results'))

@app.route('/academic/reject-result/<int:result_id>', methods=['POST'])
@login_required
@role_required(['academic'])
@first_login_required
def reject_result(result_id):
    result = Result.query.get_or_404(result_id)
    comments = request.form.get('rejection_comments', '')
    
    # Check if result is already final
    if result.is_final:
        flash('This result is already final and cannot be modified', 'error')
        return redirect(url_for('review_results'))
    
    result.status = 'rejected'
    result.approved_by = session['user_id']
    result.approved_at = datetime.utcnow()
    result.comments = comments
    
    db.session.commit()
    
    # Log activity
    student = Student.query.get(result.student_id)
    subject = Subject.query.get(result.subject_id)
    log_activity(session['user_id'], 'Result Rejected', 
                f'Rejected result for {student.full_name} in {subject.subject_name} - Reason: {comments}', 
                request.remote_addr)
    
    flash('Result rejected!', 'info')
    return redirect(url_for('review_results'))

@app.route('/academic/all-results')
@login_required
@role_required(['academic'])
@first_login_required
def all_results():
    # Get all results with filters
    course_filter = request.args.get('course', '')
    semester_filter = request.args.get('semester', '')
    status_filter = request.args.get('status', '')
    
    query = db.session.query(Result, Student, Subject, Teacher).join(
        Student, Result.student_id == Student.id
    ).join(
        Subject, Result.subject_id == Subject.id
    ).join(
        Teacher, Subject.teacher_id == Teacher.id, isouter=True
    )
    
    if course_filter:
        query = query.filter(Subject.course == course_filter)
    if semester_filter:
        query = query.filter(Subject.semester == int(semester_filter))
    if status_filter:
        query = query.filter(Result.status == status_filter)
    
    results = query.order_by(Result.submitted_at.desc()).all()
    
    return render_template('all_results.html', 
                         results=results, 
                         courses=COURSES, 
                         course_filter=course_filter, 
                         semester_filter=semester_filter, 
                         status_filter=status_filter)

# ===== STUDENT ROUTES =====
@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        roll_number = request.form['roll_number'].strip().upper()
        full_name = request.form['full_name'].strip()
        course = request.form['course']
        semester = int(request.form['semester'])
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('student_register.html', courses=COURSES)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('student_register.html', courses=COURSES)
        
        # Check if username or roll number exists
        existing_user = User.query.filter_by(username=username).first()
        existing_student = Student.query.filter_by(roll_number=roll_number).first()
        
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('student_register.html', courses=COURSES)
        
        if existing_student:
            flash('Roll number already exists', 'error')
            return render_template('student_register.html', courses=COURSES)
        
        # Create user account
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            password=hashed_password,
            role='student',
            first_login=False  # Students don't need to change credentials initially
        )
        db.session.add(new_user)
        db.session.flush()
        
        # Create student profile
        student = Student(
            user_id=new_user.id,
            roll_number=roll_number,
            full_name=full_name,
            course=course,
            semester=semester
        )
        db.session.add(student)
        db.session.commit()
        
        # Log activity
        log_activity(new_user.id, 'Student Registration', 
                    f'Student {full_name} ({roll_number}) registered for {course}', 
                    request.remote_addr)
        
        flash('Registration successful! Please wait for admin approval before logging in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('student_register.html', courses=COURSES)

@app.route('/student/transcript')
@login_required
@role_required(['student'])
@first_login_required
@student_approved_required
def student_transcript():
    student = Student.query.filter_by(user_id=session['user_id']).first()
    
    # Get all approved results
    results = db.session.query(Result, Subject).join(Subject).filter(
        Result.student_id == student.id,
        Result.status == 'approved'
    ).order_by(Subject.semester, Subject.subject_name).all()
    
    # Calculate GPA by semester and overall
    transcript_data = {}
    overall_gpa = 0
    overall_credits = 0
    
    for result, subject in results:
        semester = subject.semester
        if semester not in transcript_data:
            transcript_data[semester] = {
                'subjects': [],
                'semester_gpa': 0,
                'semester_credits': 0
            }
        
        transcript_data[semester]['subjects'].append({
            'subject_code': subject.subject_code,
            'subject_name': subject.subject_name,
            'credits': subject.credits,
            'grade': result.grade,
            'gpa': result.gpa,
            'marks': result.marks
        })
        
        transcript_data[semester]['semester_gpa'] += result.gpa * subject.credits
        transcript_data[semester]['semester_credits'] += subject.credits
        overall_gpa += result.gpa * subject.credits
        overall_credits += subject.credits
    
    # Calculate final semester GPAs
    for semester in transcript_data:
        if transcript_data[semester]['semester_credits'] > 0:
            transcript_data[semester]['semester_gpa'] /= transcript_data[semester]['semester_credits']
            transcript_data[semester]['semester_gpa'] = round(transcript_data[semester]['semester_gpa'], 2)
    
    # Calculate overall GPA
    overall_gpa = round(overall_gpa / overall_credits, 2) if overall_credits > 0 else 0
    
    return render_template('student_transcript.html', 
                         student=student, 
                         transcript_data=transcript_data, 
                         overall_gpa=overall_gpa, 
                         overall_credits=overall_credits)

# ===== API ROUTES =====
@app.route('/api/students-by-course/<course>')
@login_required
@role_required(['teacher', 'academic'])
def api_students_by_course(course):
    students = Student.query.filter_by(course=course, status='approved').all()
    return jsonify([{
        'id': s.id,
        'roll_number': s.roll_number,
        'full_name': s.full_name,
        'semester': s.semester
    } for s in students])

@app.route('/api/subjects-by-course-semester')
@login_required
@role_required(['teacher', 'academic'])
def api_subjects_by_course_semester():
    course = request.args.get('course')
    semester = request.args.get('semester')
    
    query = Subject.query.filter_by(is_active=True)
    if course:
        query = query.filter_by(course=course)
    if semester:
        query = query.filter_by(semester=int(semester))
    
    subjects = query.all()
    return jsonify([{
        'id': s.id,
        'subject_code': s.subject_code,
        'subject_name': s.subject_name,
        'credits': s.credits
    } for s in subjects])

# ===== REPORTS ROUTES =====
@app.route('/reports')
@login_required
@role_required(['admin', 'academic'])
@first_login_required
def reports():
    return render_template('reports.html')

@app.route('/reports/course-performance')
@login_required
@role_required(['admin', 'academic'])
@first_login_required
def course_performance_report():
    # Get performance statistics by course
    course_stats = {}
    
    for course in COURSES:
        # Get approved results for this course
        results = db.session.query(Result, Subject, Student).join(
            Subject, Result.subject_id == Subject.id
        ).join(
            Student, Result.student_id == Student.id
        ).filter(
            Subject.course == course,
            Result.status == 'approved'
        ).all()
        
        if results:
            total_students = len(set([r[2].id for r in results]))
            total_marks = sum([r[0].marks for r in results])
            average_marks = total_marks / len(results)
            
            # Grade distribution
            grades = {}
            for result, _, _ in results:
                grade = result.grade
                grades[grade] = grades.get(grade, 0) + 1
            
            course_stats[course] = {
                'total_students': total_students,
                'total_results': len(results),
                'average_marks': round(average_marks, 2),
                'grade_distribution': grades
            }
    
    return render_template('course_performance_report.html', course_stats=course_stats)

@app.route('/reports/teacher-performance')
@login_required
@role_required(['admin', 'academic'])
@first_login_required
def teacher_performance_report():
    # Get performance statistics by teacher
    teachers = Teacher.query.all()
    teacher_stats = {}
    
    for teacher in teachers:
        # Get results submitted by this teacher
        results = db.session.query(Result, Subject).join(
            Subject, Result.subject_id == Subject.id
        ).filter(
            Subject.teacher_id == teacher.id,
            Result.status == 'approved'
        ).all()
        
        if results:
            total_results = len(results)
            total_marks = sum([r[0].marks for r in results])
            average_marks = total_marks / total_results
            
            # Get subjects taught
            subjects = Subject.query.filter_by(teacher_id=teacher.id, is_active=True).count()
            
            teacher_stats[teacher.id] = {
                'teacher': teacher,
                'subjects_taught': subjects,
                'total_results': total_results,
                'average_marks': round(average_marks, 2)
            }
    
    return render_template('teacher_performance_report.html', teacher_stats=teacher_stats)

# ===== ERROR HANDLERS =====
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # error
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_user = User(
                username='admin',
                password=generate_password_hash('admin123'),
                role='admin',
                first_login=False
            )
            db.session.add(admin_user)
            db.session.commit()
            
    
    app.run(debug=True, host='0.0.0.0', port=5000)
