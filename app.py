# app.py — Secure Student Portal for Lab 08
# Author: Your Name
# Roll No: i221760

from flask import Flask, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp
from flask_bcrypt import Bcrypt
import os

# -------------------------------------------------
# 1️⃣ Application Configuration
# -------------------------------------------------
app = Flask(__name__)

# Secret key (required for CSRF + sessions)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key')

# Ensure instance folder exists
os.makedirs('instance', exist_ok=True)
base_dir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(base_dir, 'instance', 'student.db')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secure session cookie settings
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False     # True only with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# -------------------------------------------------
# 2️⃣ Database Model
# -------------------------------------------------
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    roll_no = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

# -------------------------------------------------
# 3️⃣ WTForms Classes for Input Validation
# -------------------------------------------------
class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=2, max=50),
        Regexp(r'^[A-Za-z\s\-]+$', message="Only letters, spaces, and hyphens allowed.")
    ])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    roll_no = StringField('Roll No', validators=[
        DataRequired(), Length(min=2, max=20),
        Regexp(r'^[A-Za-z0-9\-]+$', message="Only letters, numbers, and hyphens allowed.")
    ])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128)])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class ProfileUpdateForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=2, max=50),
        Regexp(r'^[A-Za-z\s\-]+$', message="Only letters, spaces, and hyphens allowed.")
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    roll_no = StringField('Roll No', validators=[
        DataRequired(), Length(min=2, max=20),
        Regexp(r'^[A-Za-z0-9\-]+$', message="Only letters, numbers, and hyphens allowed.")
    ])
    password = PasswordField('New Password (optional)', validators=[Length(max=128)])
    submit = SubmitField('Update')

# -------------------------------------------------
# 4️⃣ Routes — Register, Login, Profile
# -------------------------------------------------

# 🔹 Registration Route
@app.route('/', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if user already exists
        existing_email = Student.query.filter_by(email=form.email.data.lower()).first()
        existing_roll = Student.query.filter_by(roll_no=form.roll_no.data.strip()).first()

        if existing_email or existing_roll:
            flash('User already exists with this email or roll number ❌', 'warning')
            return redirect(url_for('register'))

        # Hash password securely
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        # Create new student (SQLAlchemy uses parameterized queries internally)
        user = Student(
            name=form.name.data.strip(),
            email=form.email.data.lower(),
            roll_no=form.roll_no.data.strip(),
            password_hash=hashed_pw
        )

        db.session.add(user)
        db.session.commit()
        flash('Account created successfully ✅ Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# 🔹 Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Student.query.filter_by(email=form.email.data.lower()).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            session.permanent = True
            session['user_id'] = user.id
            session['user_name'] = user.name
            flash('Login successful ✅', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid email or password ❌', 'error')
    return render_template('login.html', form=form)


# 🔹 Profile Route (View + Update)
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))

    user = Student.query.get(session['user_id'])
    form = ProfileUpdateForm(obj=user)

    if form.validate_on_submit():
        # Check for duplicate roll_no (secure ORM query)
        existing_roll = Student.query.filter(
            Student.roll_no == form.roll_no.data,
            Student.id != user.id
        ).first()
        if existing_roll:
            flash('Roll number already taken by another user.', 'warning')
            return redirect(url_for('profile'))

        # Update fields
        user.name = form.name.data.strip()
        user.roll_no = form.roll_no.data.strip()

        # Update password if provided
        if form.password.data:
            user.password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        db.session.commit()
        flash('Profile updated securely ✅', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', form=form, user=user)


# 🔹 Logout Route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# -------------------------------------------------
# 5️⃣ Secure Error Handling (No Info Disclosure)
# -------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    app.logger.exception('Server Error: %s', e)
    return render_template('errors/500.html'), 500

# -------------------------------------------------
# 6️⃣ Run the App
# -------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)

