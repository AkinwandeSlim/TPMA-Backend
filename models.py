from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    surname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    matric_number = db.Column(db.String(20), unique=True)
    staff_id = db.Column(db.String(20), unique=True)

class StudentProfile(db.Model):
    __tablename__ = 'student_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    gender = db.Column(db.String(20))
    address = db.Column(db.Text)
    place_of_tp = db.Column(db.String(100))

class SupervisorProfile(db.Model):
    __tablename__ = 'supervisor_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    gender = db.Column(db.String(20))
    address = db.Column(db.Text)
    department = db.Column(db.String(100))

class TPAssignment(db.Model):
    __tablename__ = 'tp_assignments'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    supervisor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)

class LessonPlan(db.Model):
    __tablename__ = 'lesson_plans'
    id = db.Column(db.Integer, primary_key=True)
    tp_assignment_id = db.Column(db.Integer, db.ForeignKey('tp_assignments.id'), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    topic = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=False)

class Observation(db.Model):
    __tablename__ = 'observations'
    id = db.Column(db.Integer, primary_key=True)
    tp_assignment_id = db.Column(db.Integer, db.ForeignKey('tp_assignments.id'), nullable=False)
    observation_date = db.Column(db.Date, nullable=False)
    observation_time = db.Column(db.Time, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')

class Feedback(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    observation_id = db.Column(db.Integer, db.ForeignKey('observations.id'), nullable=False)
    comments = db.Column(db.Text, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=False)

class StudentEvaluation(db.Model):
    __tablename__ = 'student_evaluations'
    id = db.Column(db.Integer, primary_key=True)
    tp_assignment_id = db.Column(db.Integer, db.ForeignKey('tp_assignments.id'), unique=True, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    comments = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, nullable=False)

class SupervisorEvaluation(db.Model):
    __tablename__ = 'supervisor_evaluations'
    id = db.Column(db.Integer, primary_key=True)
    supervisor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comments = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, nullable=False)

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    event_date = db.Column(db.Date, nullable=False)
    event_time = db.Column(db.Time)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    event_type = db.Column(db.String(20), nullable=False)
    tp_assignment_id = db.Column(db.Integer, db.ForeignKey('tp_assignments.id'))

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, default=False)