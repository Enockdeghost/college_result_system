# import libraries 
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

#confgrations
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///college_results.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'teacher' or 'student'
    
    def __repr__(self):
        return f'<User {self.username}>'

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    roll_number = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    
    def __repr__(self):
        return f'<Student {self.name}>'

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_code = db.Column(db.String(20), unique=True, nullable=False)
    course_name = db.Column(db.String(100), nullable=False)
    
    def __repr__(self):
        return f'<Course {self.course_name}>'

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    marks = db.Column(db.Float, nullable=False)
    grade = db.Column(db.String(2), nullable=False)
    semester = db.Column(db.String(20), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f'<Result {self.student_id}-{self.course_id}>'

# Decorators for role-based access control
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'teacher':
            flash('Access denied: Teacher permissions required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Create new user
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        
        # If student, collect additional information
        if role == 'student':
            name = request.form['name']
            roll_number = request.form['roll_number']
            
            # Check if roll number already exists
            existing_student = Student.query.filter_by(roll_number=roll_number).first()
            if existing_student:
                flash('Roll number already exists', 'danger')
                return redirect(url_for('register'))
            
            db.session.flush()  # To get the user ID
            new_student = Student(user_id=new_user.id, name=name, roll_number=roll_number)
            db.session.add(new_student)
        
        db.session.commit()
        flash('Registration successful! You can now login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if session['role'] == 'teacher':
        # For teachers, show list of courses and option to post results
        courses = Course.query.all()
        return render_template('teacher_dashboard.html', courses=courses)
    else:
        # For students, show their results
        student = Student.query.filter_by(user_id=session['user_id']).first()
        if student:
            results = Result.query.filter_by(student_id=student.id).all()
            result_data = []
            for result in results:
                course = Course.query.get(result.course_id)
                result_data.append({
                    'course_code': course.course_code,
                    'course_name': course.course_name,
                    'marks': result.marks,
                    'grade': result.grade,
                    'semester': result.semester
                })
            return render_template('student_dashboard.html', student=student, results=result_data)
        else:
            flash('Student profile not found', 'danger')
            return redirect(url_for('logout'))

@app.route('/course/add', methods=['GET', 'POST'])
@login_required
@teacher_required
def add_course():
    if request.method == 'POST':
        course_code = request.form['course_code']
        course_name = request.form['course_name']
        
        # Check if course already exists
        existing_course = Course.query.filter_by(course_code=course_code).first()
        if existing_course:
            flash('Course already exists', 'danger')
            return redirect(url_for('add_course'))
        
        new_course = Course(course_code=course_code, course_name=course_name)
        db.session.add(new_course)
        db.session.commit()
        
        flash('Course added successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_course.html')

@app.route('/result/add', methods=['GET', 'POST'])
@login_required
@teacher_required
def add_result():
    if request.method == 'POST':
        roll_number = request.form['roll_number']
        course_id = request.form['course_id']
        marks = float(request.form['marks'])
        semester = request.form['semester']
        
        # Calculate grade based on marks
        if marks >= 90:
            grade = 'A+'
        elif marks >= 80:
            grade = 'A'
        elif marks >= 70:
            grade = 'B'
        elif marks >= 60:
            grade = 'C'
        elif marks >= 50:
            grade = 'D'
        else:
            grade = 'F'
        
        # Find student by roll number
        student = Student.query.filter_by(roll_number=roll_number).first()
        if not student:
            flash('Student not found with the given roll number', 'danger')
            return redirect(url_for('add_result'))
        
        # Check if result already exists
        existing_result = Result.query.filter_by(
            student_id=student.id,
            course_id=course_id,
            semester=semester
        ).first()
        
        if existing_result:
            # Update existing result
            existing_result.marks = marks
            existing_result.grade = grade
            existing_result.created_by = session['user_id']
            flash('Result updated successfully', 'success')
        else:
            # Create new result
            new_result = Result(
                student_id=student.id,
                course_id=course_id,
                marks=marks,
                grade=grade,
                semester=semester,
                created_by=session['user_id']
            )
            db.session.add(new_result)
            flash('Result added successfully', 'success')
        
        db.session.commit()
        return redirect(url_for('dashboard'))
    
    courses = Course.query.all()
    return render_template('add_result.html', courses=courses)

@app.route('/students')
@login_required
@teacher_required
def view_students():
    students = Student.query.all()
    return render_template('students.html', students=students)

# Create the database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
