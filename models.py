# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

# Initialize SQLAlchemy instance here, but don't associate it with the app yet.
# This allows main.py to import 'db' before the app is fully configured.
db = SQLAlchemy()

# User Model - Inherits UserMixin for Flask-Login session management
# The @login_manager.user_loader callback is defined in main.py
class User(db.Model, UserMixin):
    __tablename__ = 'user' # Optional: explicitly define table name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False) # Store hashed password

    # Relationship: A user can create multiple forms
    # backref='author' creates a virtual 'author' attribute on the Form model
    # lazy=True means SQLAlchemy will load the related forms only when accessed
    # cascade='all, delete-orphan' means if a user is deleted, their forms are also deleted.
    forms = db.relationship('Form', backref='author', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        # Represents the object when printed
        return f"User('{self.username}', '{self.email}')"

# Form Model
class Form(db.Model):
    __tablename__ = 'form'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # unique_key will be used for embedding/accessing the public form page
    unique_key = db.Column(db.String(32), unique=True, nullable=False) # Need a way to generate this

    # Foreign key: Links this form to the user who created it
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationship: A form contains multiple fields
    fields = db.relationship('Field', backref='form', lazy=True, cascade="all, delete-orphan")
    # Relationship: A form can receive multiple submissions
    submissions = db.relationship('Submission', backref='form', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"Form('{self.title}', Key: '{self.unique_key}')"

# Field Model (Defines the input fields within a Form)
class Field(db.Model):
    __tablename__ = 'field'
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(100), nullable=False)
    # Example field types: 'text', 'email', 'textarea', 'checkbox', 'radio', 'select', 'number', 'date'
    field_type = db.Column(db.String(50), nullable=False)
    required = db.Column(db.Boolean, default=False, nullable=False)
    # Options (e.g., for radio/select) can be stored as a simple delimited string or JSON string
    options = db.Column(db.Text, nullable=True)

    # Foreign key: Links this field back to its parent Form
    form_id = db.Column(db.Integer, db.ForeignKey('form.id'), nullable=False)

    def __repr__(self):
        return f"Field('{self.label}', Type: '{self.field_type}')"

# Submission Model (Stores the data submitted through a specific Form)
class Submission(db.Model):
    __tablename__ = 'submission'
    id = db.Column(db.Integer, primary_key=True)
    submitted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Foreign key: Links this submission back to the Form it belongs to
    form_id = db.Column(db.Integer, db.ForeignKey('form.id'), nullable=False)

    # Store submitted data flexibly as a JSON string in a Text field
    # Example: '{"field_label_1": "value1", "field_label_2": "value2"}'
    data = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"Submission(Form ID: {self.form_id}, Submitted: {self.submitted_at})"
