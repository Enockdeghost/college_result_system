#import libraries 
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///college_result.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Login Manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------- mfumo wa db----------

# User model (base for Admin, Teacher, Student)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin,mwalimu mwanafunzi
    status = db.Column(db.String(20), default='pending')  # kuruhusiwa au kukataliwa na admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    student_info = db.relationship('Student', backref='user', uselist=False, cascade="all, delete-orphan")
    teacher_info = db.relationship('Teacher', backref='user', uselist=False, cascade="all, delete-orphan")
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Student model
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    roll_number = db.Column(db.String(20), unique=True, nullable=False)
    batch = db.Column(db.String(20), nullable=False)
    program = db.Column(db.String(50), nullable=False)
    semester = db.Column(db.Integer, nullable=False)
    
    # Relationships
    enrollments = db.relationship('Enrollment', backref='student', cascade="all, delete-orphan")
    results = db.relationship('Result', backref='student', cascade="all, delete-orphan")

# Teacher model
class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    department = db.Column(db.String(50), nullable=False)
    designation = db.Column(db.String(50), nullable=False)
    
    # Relationships
    courses = db.relationship('Course', backref='teacher', cascade="all, delete-orphan")

# Course model
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_code = db.Column(db.String(20), unique=True, nullable=False)
    course_name = db.Column(db.String(100), nullable=False)
    credit_hours = db.Column(db.Float, nullable=False)
    semester = db.Column(db.Integer, nullable=False)
    program = db.Column(db.String(50), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)
    
    # Relationships
    enrollments = db.relationship('Enrollment', backref='course', cascade="all, delete-orphan")
    results = db.relationship('Result', backref='course', cascade="all, delete-orphan")

# Enrollment model
class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    semester = db.Column(db.Integer, nullable=False)
    academic_year = db.Column(db.String(20), nullable=False)
    enrollment_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint to prevent duplicate enrollments
    __table_args__ = (db.UniqueConstraint('student_id', 'course_id', 'semester', 'academic_year', name='_student_course_sem_year_uc'),)

# Result model
class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    midterm_marks = db.Column(db.Float, nullable=True)
    final_marks = db.Column(db.Float, nullable=True)
    assignment_marks = db.Column(db.Float, nullable=True)
    attendance_marks = db.Column(db.Float, nullable=True)
    total_marks = db.Column(db.Float, nullable=True)
    grade = db.Column(db.String(2), nullable=True)
    grade_point = db.Column(db.Float, nullable=True)
    remarks = db.Column(db.String(100), nullable=True)
    semester = db.Column(db.Integer, nullable=False)
    academic_year = db.Column(db.String(20), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, published
    
    # Unique constraint to prevent duplicate results
    __table_args__ = (db.UniqueConstraint('student_id', 'course_id', 'semester', 'academic_year', name='_student_course_result_uc'),)

# Notification model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    link = db.Column(db.String(255), nullable=True)

# -login user loger..mmh fix bug haa
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------- Routes ----------

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if user.status == 'approved':
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Your account is pending approval. Please wait for admin approval.', 'warning')
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Student Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        roll_number = request.form.get('roll_number')
        batch = request.form.get('batch')
        program = request.form.get('program')
        semester = request.form.get('semester')
        
        # Check if username or email exists
        user_exists = User.query.filter((User.username == username) | (User.email == email)).first()
        roll_exists = Student.query.filter_by(roll_number=roll_number).first()
        
        if user_exists:
            flash('Username or email already exists', 'danger')
            return render_template('register.html')
        
        if roll_exists:
            flash('Roll number already exists', 'danger')
            return render_template('register.html')
        
        # Create user
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            role='student',
            status='pending'
        )
        new_user.set_password(password)
        
        # Create student profile
        new_student = Student(
            user=new_user,
            roll_number=roll_number,
            batch=batch,
            program=program,
            semester=int(semester)
        )
        
        # Save to database
        db.session.add(new_user)
        db.session.add(new_student)
        db.session.commit()
        
        # Create admin notification
        admin_users = User.query.filter_by(role='admin').all()
        for admin in admin_users:
            notification = Notification(
                user_id=admin.id,
                message=f"New student registration: {full_name}",
                link=url_for('admin_approve_user', user_id=new_user.id)
            )
            db.session.add(notification)
        
        db.session.commit()
        
        flash('Registration successful! Please wait for admin approval.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Dashboard route - redirects based on user role
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    elif current_user.role == 'student':
        return redirect(url_for('student_dashboard'))
    else:
        return redirect(url_for('index'))

# ---------- Admin Routes ----------

# Admin Dashboard
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get counts for dashboard
    pending_users = User.query.filter_by(status='pending').count()
    total_students = User.query.filter_by(role='student', status='approved').count()
    total_teachers = User.query.filter_by(role='teacher', status='approved').count()
    total_courses = Course.query.count()
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', 
                          pending_users=pending_users,
                          total_students=total_students,
                          total_teachers=total_teachers,
                          total_courses=total_courses,
                          recent_users=recent_users)

# Admin - Pending Users
@app.route('/admin/pending-users')
@login_required
def admin_pending_users():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    pending_users = User.query.filter_by(status='pending').all()
    return render_template('admin/pending_users.html', pending_users=pending_users)

# Admin - Approve/Reject User
@app.route('/admin/user/<int:user_id>/approve', methods=['POST'])
@login_required
def admin_approve_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    action = request.form.get('action')
    
    if action == 'approve':
        user.status = 'approved'
        flash(f'User {user.username} has been approved', 'success')
        
        # Notify user
        notification = Notification(
            user_id=user.id,
            message="Your account has been approved. You can now log in.",
            link=url_for('login')
        )
        db.session.add(notification)
    
    elif action == 'reject':
        user.status = 'rejected'
        flash(f'User {user.username} has been rejected', 'warning')
        
        # Notify user
        notification = Notification(
            user_id=user.id,
            message="Your account registration has been rejected.",
            link=url_for('login')
        )
        db.session.add(notification)
    
    db.session.commit()
    return redirect(url_for('admin_pending_users'))

# Admin - Manage Users
@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    role = request.args.get('role', 'all')
    
    if role == 'student':
        users = User.query.filter_by(role='student').all()
    elif role == 'teacher':
        users = User.query.filter_by(role='teacher').all()
    else:
        users = User.query.filter(User.role != 'admin').all()
    
    return render_template('admin/users.html', users=users, selected_role=role)

# Admin - Add Teacher
@app.route('/admin/add-teacher', methods=['GET', 'POST'])
@login_required
def admin_add_teacher():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        employee_id = request.form.get('employee_id')
        department = request.form.get('department')
        designation = request.form.get('designation')
        
        # Check if username or email exists
        user_exists = User.query.filter((User.username == username) | (User.email == email)).first()
        employee_exists = Teacher.query.filter_by(employee_id=employee_id).first()
        
        if user_exists:
            flash('Username or email already exists', 'danger')
            return render_template('admin/add_teacher.html')
        
        if employee_exists:
            flash('Employee ID already exists', 'danger')
            return render_template('admin/add_teacher.html')
        
        # Create user
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            role='teacher',
            status='approved'  # Admin-added teachers are automatically approved
        )
        new_user.set_password(password)
        
        # Create teacher profile
        new_teacher = Teacher(
            user=new_user,
            employee_id=employee_id,
            department=department,
            designation=designation
        )
        
        # Save to database
        db.session.add(new_user)
        db.session.add(new_teacher)
        db.session.commit()
        
        flash('Teacher added successfully!', 'success')
        return redirect(url_for('admin_users', role='teacher'))
    
    return render_template('admin/add_teacher.html')

# Admin - Manage Courses
@app.route('/admin/courses')
@login_required
def admin_courses():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    courses = Course.query.all()
    return render_template('admin/courses.html', courses=courses)

# Admin - View Results
@app.route('/admin/results')
@login_required
def admin_results():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    # Filter options
    program = request.args.get('program', '')
    semester = request.args.get('semester', '')
    status = request.args.get('status', '')
    
    # Base query
    query = Result.query.join(Student, Result.student_id == Student.id).join(Course, Result.course_id == Course.id)
    
    # Apply filters
    if program:
        query = query.filter(Student.program == program)
    if semester:
        query = query.filter(Result.semester == int(semester))
    if status:
        query = query.filter(Result.status == status)
    
    results = query.all()
    
    # Get unique programs for filter dropdown
    programs = db.session.query(Student.program).distinct().all()
    programs = [p[0] for p in programs]
    
    return render_template('admin/results.html', 
                          results=results, 
                          programs=programs,
                          selected_program=program,
                          selected_semester=semester,
                          selected_status=status)

# Admin - Publish Results
@app.route('/admin/results/publish', methods=['POST'])
@login_required
def admin_publish_results():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get IDs of results to publish
    result_ids = request.form.getlist('result_ids')
    
    if not result_ids:
        flash('No results selected', 'warning')
        return redirect(url_for('admin_results'))
    
    # Update status of selected results
    for result_id in result_ids:
        result = Result.query.get(int(result_id))
        result.status = 'published'
        
        # Create notification for student
        student = Student.query.get(result.student_id)
        course = Course.query.get(result.course_id)
        
        notification = Notification(
            user_id=student.user_id,
            message=f"Your result for {course.course_name} has been published",
            link=url_for('student_results')
        )
        db.session.add(notification)
    
    db.session.commit()
    flash('Selected results have been published', 'success')
    return redirect(url_for('admin_results'))

# ---------- Teacher Routes ----------

# Teacher Dashboard
@app.route('/teacher/dashboard')
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    
    # Count courses taught by teacher
    courses_count = Course.query.filter_by(teacher_id=teacher.id).count()
    
    # Count students enrolled in teacher's courses
    students_count = db.session.query(Enrollment.student_id).distinct().join(
        Course, Enrollment.course_id == Course.id
    ).filter(Course.teacher_id == teacher.id).count()
    
    # Count pending results (entered but not published)
    pending_results = Result.query.join(
        Course, Result.course_id == Course.id
    ).filter(
        Course.teacher_id == teacher.id,
        Result.status == 'pending'
    ).count()
    
    # Get recent results added
    recent_results = Result.query.join(
        Course, Result.course_id == Course.id
    ).filter(
        Course.teacher_id == teacher.id
    ).order_by(Result.date_added.desc()).limit(5).all()
    
    return render_template('teacher/dashboard.html',
                          teacher=teacher,
                          courses_count=courses_count,
                          students_count=students_count,
                          pending_results=pending_results,
                          recent_results=recent_results)

# Teacher - Manage Courses
@app.route('/teacher/courses')
@login_required
def teacher_courses():
    if current_user.role != 'teacher':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    courses = Course.query.filter_by(teacher_id=teacher.id).all()
    
    return render_template('teacher/courses.html', courses=courses)

# Teacher - Add Course
@app.route('/teacher/courses/add', methods=['GET', 'POST'])
@login_required
def teacher_add_course():
    if current_user.role != 'teacher':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    
    if request.method == 'POST':
        course_code = request.form.get('course_code')
        course_name = request.form.get('course_name')
        credit_hours = float(request.form.get('credit_hours'))
        semester = int(request.form.get('semester'))
        program = request.form.get('program')
        
        # Check if course code exists
        course_exists = Course.query.filter_by(course_code=course_code).first()
        
        if course_exists:
            flash('Course code already exists', 'danger')
            return render_template('teacher/add_course.html')
        
        # Create course
        new_course = Course(
            course_code=course_code,
            course_name=course_name,
            credit_hours=credit_hours,
            semester=semester,
            program=program,
            teacher_id=teacher.id
        )
        
        # Save to database
        db.session.add(new_course)
        db.session.commit()
        
        flash('Course added successfully!', 'success')
        return redirect(url_for('teacher_courses'))
    
    return render_template('teacher/add_course.html')

# Teacher - Course Students
@app.route('/teacher/course/<int:course_id>/students')
@login_required
def teacher_course_students(course_id):
    if current_user.role != 'teacher':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    course = Course.query.filter_by(id=course_id, teacher_id=teacher.id).first_or_404()
    
    enrollments = Enrollment.query.filter_by(course_id=course.id).all()
    
    return render_template('teacher/course_students.html', course=course, enrollments=enrollments)

# Teacher - Enter Results
@app.route('/teacher/course/<int:course_id>/results', methods=['GET', 'POST'])
@login_required
def teacher_course_results(course_id):
    if current_user.role != 'teacher':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    course = Course.query.filter_by(id=course_id, teacher_id=teacher.id).first_or_404()
    
    if request.method == 'POST':
        student_id = int(request.form.get('student_id'))
        midterm_marks = float(request.form.get('midterm_marks', 0))
        final_marks = float(request.form.get('final_marks', 0))
        assignment_marks = float(request.form.get('assignment_marks', 0))
        attendance_marks = float(request.form.get('attendance_marks', 0))
        semester = int(request.form.get('semester'))
        academic_year = request.form.get('academic_year')
        remarks = request.form.get('remarks', '')
        
        # Calculate total marks and grade
        total_marks = midterm_marks + final_marks + assignment_marks + attendance_marks
        
        # Determine grade based on total marks
        grade = ""
        grade_point = 0.0
        
        if total_marks >= 90:
            grade = "A+"
            grade_point = 4.0
        elif total_marks >= 85:
            grade = "A"
            grade_point = 3.7
        elif total_marks >= 80:
            grade = "A-"
            grade_point = 3.5
        elif total_marks >= 75:
            grade = "B+"
            grade_point = 3.3
        elif total_marks >= 70:
            grade = "B"
            grade_point = 3.0
        elif total_marks >= 65:
            grade = "B-"
            grade_point = 2.7
        elif total_marks >= 60:
            grade = "C+"
            grade_point = 2.3
        elif total_marks >= 55:
            grade = "C"
            grade_point = 2.0
        elif total_marks >= 50:
            grade = "D"
            grade_point = 1.0
        else:
            grade = "F"
            grade_point = 0.0
        
        # Check if result already exists
        existing_result = Result.query.filter_by(
            student_id=student_id,
            course_id=course_id,
            semester=semester,
            academic_year=academic_year
        ).first()
        
        if existing_result:
            # Update existing result
            existing_result.midterm_marks = midterm_marks
            existing_result.final_marks = final_marks
            existing_result.assignment_marks = assignment_marks
            existing_result.attendance_marks = attendance_marks
            existing_result.total_marks = total_marks
            existing_result.grade = grade
            existing_result.grade_point = grade_point
            existing_result.remarks = remarks
            existing_result.date_added = datetime.utcnow()
            
            flash('Result updated successfully!', 'success')
        else:
            # Create new result
            new_result = Result(
                student_id=student_id,
                course_id=course_id,
                midterm_marks=midterm_marks,
                final_marks=final_marks,
                assignment_marks=assignment_marks,
                attendance_marks=attendance_marks,
                total_marks=total_marks,
                grade=grade,
                grade_point=grade_point,
                remarks=remarks,
                semester=semester,
                academic_year=academic_year,
                status='pending'
            )
            
            db.session.add(new_result)
            flash('Result added successfully!', 'success')
        
        # Create notification for admin
        admin_users = User.query.filter_by(role='admin').all()
        student = Student.query.get(student_id)
        
        for admin in admin_users:
            notification = Notification(
                user_id=admin.id,
                message=f"New result added for {student.user.full_name} in {course.course_name}",
                link=url_for('admin_results')
            )
            db.session.add(notification)
        
        db.session.commit()
        return redirect(url_for('teacher_course_results', course_id=course_id))
    
    # Get students enrolled in this course
    enrollments = Enrollment.query.filter_by(course_id=course.id).all()
    
    # Get existing results for this course
    results = Result.query.filter_by(course_id=course.id).all()
    
    return render_template('teacher/course_results.html', 
                          course=course, 
                          enrollments=enrollments,
                          results=results)

# ---------- Student 

# Student Dashboard
@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    student = Student.query.filter_by(user_id=current_user.id).first()
    
    # Count enrolled courses
    enrolled_courses = Enrollment.query.filter_by(student_id=student.id).count()
    
    # Count published results
    published_results = Result.query.filter_by(student_id=student.id, status='published').count()
    
    # Calculate CGPA from published results
    results = Result.query.filter_by(student_id=student.id, status='published').all()
    
    total_credit_points = 0
    total_credits = 0
    
    for result in results:
        course = Course.query.get(result.course_id)
        total_credit_points += result.grade_point * course.credit_hours
        total_credits += course.credit_hours
    
    cgpa = total_credit_points / total_credits if total_credits > 0 else 0
    
    # Get recent results
    recent_results = Result.query.filter_by(
        student_id=student.id, 
        status='published'
    ).order_by(Result.date_added.desc()).limit(5).all()
    
    return render_template('student/dashboard.html',
                          student=student,
                          enrolled_courses=enrolled_courses,
                          published_results=published_results,
                          cgpa=round(cgpa, 2),
                          recent_results=recent_results)

# Student - View Courses
@app.route('/student/courses')
@login_required
def student_courses():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    student = Student.query.filter_by(user_id=current_user.id).first()
    
    # Get courses for current semester
    current_semester = student.semester
    
    # Get enrolled courses
    enrollments = Enrollment.query.filter_by(student_id=student.id).all()
    enrolled_course_ids = [e.course_id for e in enrollments]
    
    # Get available courses for enrollment (not already enrolled)
    available_courses = Course.query.filter(
        Course.program == student.program,
        Course.semester == current_semester,
        ~Course.id.in_(enrolled_course_ids) if enrolled_course_ids else True
    ).all()
    
    return render_template('student/courses.html', 
                          student=student,
                          enrollments=enrollments,
                          available_courses=available_courses)

# Student - Enroll in Course
@app.route('/student/enroll', methods=['POST'])
@login_required
def student_enroll():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    student = Student.query.filter_by(user_id=current_user.id).first()
    course_id = int(request.form.get('course_id'))
    
    # Check if already enrolled
    existing_enrollment = Enrollment.query.filter_by(
        student_id=student.id,
        course_id=course_id
    ).first()
    
    if existing_enrollment:
        flash('You are already enrolled in this course', 'warning')
        return redirect(url_for('student_courses'))
    
    # Get course info
    course = Course.query.get_or_404(course_id)
    
    # Create enrollment
    academic_year = datetime.utcnow().strftime('%Y-%Y')  # Current academic year
    new_enrollment = Enrollment(
        student_id=student.id,
        course_id=course_id,
        semester=student.semester,
        academic_year=academic_year
    )
    
    db.session.add(new_enrollment)
    
    # Notify teacher
    teacher = Teacher.query.get(course.teacher_id)
    notification = Notification(
        user_id=teacher.user_id,
        message=f"{student.user.full_name} has enrolled in your course: {course.course_name}",
        link=url_for('teacher_course_students', course_id=course.id)
    )
    db.session.add(notification)
    
    db.session.commit()
    flash(f'Successfully enrolled in {course.course_name}', 'success')
    return redirect(url_for('student_courses'))

# Student - View Results
@app.route('/student/results')
@login_required
def student_results():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    student = Student.query.filter_by(user_id=current_user.id).first()
    
    # Get published results
    results = Result.query.filter_by(student_id=student.id, status='published').all()
    
    # Calculate semester-wise GPA
    semesters = {}
    for result in results:
        if result.semester not in semesters:
            semesters[result.semester] = {
                'results': [],
                'total_credit_points': 0,
                'total_credits': 0,
                'gpa': 0
            }
        
        semesters[result.semester]['results'].append(result)
        course = Course.query.get(result.course_id)
        semesters[result.semester]['total_credit_points'] += result.grade_point * course.credit_hours
        semesters[result.semester]['total_credits'] += course.credit_hours
    
    # Calculate GPA for each semester
    for semester in semesters:
        if semesters[semester]['total_credits'] > 0:
            semesters[semester]['gpa'] = round(semesters[semester]['total_credit_points'] / semesters[semester]['total_credits'], 2)
    
    # Calculate overall CGPA
    total_credit_points = sum(sem['total_credit_points'] for sem in semesters.values())
    total_credits = sum(sem['total_credits'] for sem in semesters.values())
    cgpa = round(total_credit_points / total_credits, 2) if total_credits > 0 else 0
    
    return render_template('student/results.html', 
                          student=student,
                          semesters=semesters,
                          cgpa=cgpa)

# ---------- Notification Routes ----------

# Notifications view
@app.route('/notifications')
@login_required
def notifications():
    user_notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.created_at.desc()).all()
    
    # Mark notifications as read
    for notification in user_notifications:
        if not notification.is_read:
            notification.is_read = True
    
    db.session.commit()
    
    return render_template('notifications.html', notifications=user_notifications)

#app entry point ----------

@app.context_processor
def inject_unread_notifications():
    """Inject unread notifications count into all templates"""
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).count()
        return {'unread_notifications': unread_count}
    return {'unread_notifications': 0}

# Initialize the database
def create_admin():
    """Create admin user if not exists"""
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin_user = User(
            username='admin',
            email='admin@college.edu',
            full_name='System Administrator',
            role='admin',
            status='approved'
        )
        admin_user.set_password('admin123')  # Default password
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created!")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()
    app.run(debug=True)
