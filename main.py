# main.py
import os
from flask import Flask, render_template, redirect, url_for, flash, request
import json
import uuid
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from models import db, User, Form, Field, Submission # Import db and models directly now
from forms import RegistrationForm, LoginForm # Import our new forms
import secrets
from flask_wtf.csrf import validate_csrf 
from wtforms.validators import ValidationError
from flask_wtf.csrf import CSRFProtect

# Initialize Flask App
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_dev_only_398u3nf')

# --- DATABASE CONFIGURATION ---
# Use DATABASE_URL from environment variables if available (for Railway/production)
# Otherwise, fall back to local sqlite file (for Replit/development)
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres'):
    # Railway provides a postgres URL, but SQLAlchemy needs 'postgresql'
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
else:
    # Fallback for local development (Replit)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize CSRF Protection AFTER setting SECRET_KEY ---
csrf = CSRFProtect(app)
# You could also use CSRFProtect().init_app(app) later, but this is common.
# --- END CSRF Initialization ---

# Initialize Extensions
# db defined in models.py, initialize it with the app
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect to 'login' view if user needs to log in
login_manager.login_message_category = 'info' # Flash message category

# Configure the user loader function required by Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define allowed field types (used in the template dropdown)
ALLOWED_FIELD_TYPES = [
    'text', 'email', 'textarea', 'number', 'date',
    'checkbox', 'radio', 'select'
]
# --- Routes ---

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html', title='Home')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home')) # Already logged in users redirect home
    form = RegistrationForm()
    if form.validate_on_submit():
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # Create new user
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard')) # Already logged in users redirect to dashboard
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # Check if user exists and password matches
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login successful!', 'success')
            # Redirect to the page user was trying to access, or dashboard
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch forms created by the current user, order by newest first
    user_forms = Form.query.filter_by(user_id=current_user.id).order_by(Form.created_at.desc()).all()
    return render_template('dashboard.html', title='Dashboard', user_forms=user_forms)

@app.route('/create_form', methods=['GET', 'POST'])
@login_required
def create_form():
    if request.method == 'POST':
        form_title = request.form.get('form_title')
        form_description = request.form.get('form_description') # Get optional description

        # Basic validation
        if not form_title:
            flash('Form title is required.', 'warning')
            # Pass submitted values back to template if re-rendering
            return render_template('create_form.html', title='Create Form', current_title=form_title, current_description=form_description)

        # Generate a unique key using secrets module
        form_key = secrets.token_urlsafe(16)

        # Create the new form object using your defined model
        new_form = Form(title=form_title,
                        description=form_description,
                        user_id=current_user.id, # Use user_id as defined in your Form model
                        unique_key=form_key)
                        # created_at has a default in your model

        try:
            db.session.add(new_form)
            db.session.commit()
            flash(f'Form "{form_title}" created successfully! Now add some fields.', 'success')
            # Redirect to the dashboard for now. We'll add an edit link there.
            return redirect(url_for('dashboard'))
            # Alternative: Redirect directly to edit page:
            # return redirect(url_for('edit_form', form_id=new_form.id))
        except Exception as e:
            db.session.rollback() # Roll back in case of error
            flash(f'Error creating form. Please try again. {e}', 'danger')
            # Log the error for your debugging (visible in Replit console)
            print(f"Error creating form: {e}")

    # If GET request, just show the form creation page
    return render_template('create_form.html', title='Create Form')

# --- EDIT FORM Route (Handles Adding Fields and Displaying) ---
@app.route('/edit_form/<int:form_id>', methods=['GET', 'POST'])
@login_required
def edit_form(form_id):
     form = Form.query.get_or_404(form_id)

     # Check ownership
     if form.author != current_user:
          flash('You do not have permission to edit this form.', 'danger')
          return redirect(url_for('dashboard'))

     # --- Handle ADDING a new field (POST request) ---
     if request.method == 'POST':
          field_label = request.form.get('field_label')
          field_type = request.form.get('field_type')
          # Checkbox value: present in form data if checked, absent if not
          field_required = 'field_required' in request.form
          # TODO: Handle 'options' later if field_type is 'radio' or 'select'
          field_options = request.form.get('field_options') # Basic handling for now

          # Validation
          if not field_label:
               flash('Field label is required.', 'warning')
          elif field_type not in ALLOWED_FIELD_TYPES:
               flash('Invalid field type selected.', 'warning')
          else:
               # Create new Field object
               new_field = Field(label=field_label,
                                 field_type=field_type,
                                 required=field_required,
                                 options=field_options if field_type in ['radio', 'select'] else None,
                                 form_id=form.id)
               try:
                    db.session.add(new_field)
                    db.session.commit()
                    flash(f'Field "{field_label}" added successfully.', 'success')
               except Exception as e:
                    db.session.rollback()
                    flash(f'Error adding field: {e}', 'danger')
                    print(f"Error adding field: {e}")

          # Redirect back to the same edit page to see the updated list
          return redirect(url_for('edit_form', form_id=form.id))

     # --- GET Request: Display form info and existing fields ---
     # Query existing fields for this form
     existing_fields = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()

     return render_template('edit_form.html',
                            title=f'Edit Form: {form.title}',
                            form=form,
                            fields=existing_fields, # Pass fields to template
                            allowed_field_types=ALLOWED_FIELD_TYPES) # Pass types for dropdown


# --- DELETE FIELD Route ---
@app.route('/delete_field/<int:field_id>', methods=['POST'])
@login_required
def delete_field(field_id):
    # *** CSRF Check START ***
    try:
        validate_csrf(request.form.get('csrf_token'))
    except ValidationError:
        flash('Invalid CSRF token. Please try again.', 'danger')
        # Redirect back to dashboard or maybe previous page if possible?
        # For simplicity, redirecting to dashboard.
        return redirect(url_for('dashboard'))
    # *** CSRF Check END ***
    
    field_to_delete = Field.query.get_or_404(field_id)
    form_id_redirect = field_to_delete.form_id # Get form ID before deleting field

    # IMPORTANT: Verify ownership of the PARENT FORM
    if field_to_delete.form.author != current_user:
        flash('You do not have permission to delete this field.', 'danger')
        return redirect(url_for('dashboard')) # Or redirect back to edit form?

    try:
        db.session.delete(field_to_delete)
        db.session.commit()
        flash(f'Field "{field_to_delete.label}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting field: {e}', 'danger')
        print(f"Error deleting field: {e}")

    # Redirect back to the edit form page where the field was deleted
    return redirect(url_for('edit_form', form_id=form_id_redirect))

# --- DELETE FORM Route ---
@app.route('/delete_form/<int:form_id>', methods=['POST']) # Use POST for safety
@login_required
def delete_form(form_id):
    # *** CSRF Check START ***
    try:
        # Validates the token submitted in the form against the session token
        validate_csrf(request.form.get('csrf_token'))
    except ValidationError:
        flash('Invalid CSRF token. Please try again.', 'danger')
        return redirect(url_for('dashboard'))
    # *** CSRF Check END ***
    
    form_to_delete = Form.query.get_or_404(form_id)

    # IMPORTANT: Verify ownership
    if form_to_delete.author != current_user:
        flash('You do not have permission to delete this form.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        form_title = form_to_delete.title # Get title before deleting for flash message
        # Delete the form object from the database session
        db.session.delete(form_to_delete)
        # Commit the change (SQLAlchemy cascades should delete related fields/submissions)
        db.session.commit()
        flash(f'Form "{form_title}" and all its data deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting form: {e}', 'danger')
        print(f"Error deleting form ID {form_id}: {e}")

    # Redirect back to the dashboard after deletion
    return redirect(url_for('dashboard'))

# --- PUBLIC FORM DISPLAY & SUBMISSION Route ---
@app.route('/form/<string:form_key>', methods=['GET', 'POST'])
def public_form(form_key):
    # Find the form by its unique key, return 404 if not found
    form = Form.query.filter_by(unique_key=form_key).first_or_404()

    # --- Handle form SUBMISSION (POST request) ---
    if request.method == 'POST':
        # Fetch the fields associated with this form again for validation
        fields = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()
        submitted_data = request.form # Get submitted data
        errors = {} # Dictionary to store validation errors

        # --- Server-Side Validation Loop ---
        for field in fields:
            field_name = f"field_{field.id}"
            value = submitted_data.get(field_name)

            if field.required:
                is_missing = False
                if field.field_type == 'checkbox':
                    # Required checkbox must be present in the form data
                    if field_name not in submitted_data:
                        is_missing = True
                elif not value: # Check if value is None or empty string for others
                    is_missing = True

                if is_missing:
                    errors[field_name] = "This field is required."
            # --- Add other validations later if needed (e.g., email format) ---

        # --- Check if any errors occurred ---
        if errors:
            flash('Please correct the errors below.', 'warning')
            # Re-render the form template, passing errors and submitted data back
            return render_template('public_form.html',
                                   form=form,
                                   fields=fields,
                                   errors=errors, # Pass errors dict
                                   submitted_data=submitted_data) # Pass submitted data

        # --- If validation passed, proceed to save submission ---
        submission_data_dict = {}
        try:
            for field in fields:
                field_name = f"field_{field.id}"
                if field.field_type == 'checkbox':
                    value = 'true' if field_name in submitted_data else 'false'
                else:
                    value = submitted_data.get(field_name)
                submission_data_dict[field_name] = value # Use field_ID key for robustness

            data_json = json.dumps(submission_data_dict)
            new_submission = Submission(form_id=form.id, data=data_json)
            db.session.add(new_submission)
            db.session.commit()
            flash('Thank you! Your submission has been recorded.', 'success')
            # Redirect after successful submission (prevents re-posting on refresh)
            return redirect(url_for('public_form', form_key=form_key))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while saving the submission. Error: {e}', 'danger')
            print(f"Error saving submission for form {form.id}: {e}")
            # Re-render form even on save error, potentially with data? Or redirect?
            # Re-rendering might be better here to avoid losing data if possible.
            return render_template('public_form.html',
                                   form=form,
                                   fields=fields,
                                   errors={"_save_error": "Could not save submission."}, # Generic save error
                                   submitted_data=submitted_data)

    # --- Display the form (GET request) ---
    # Fetch fields for display if it's a GET request
    fields_for_display = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()
    return render_template('public_form.html',
                           form=form,
                           fields=fields_for_display,
                           errors={}, # <-- Add this: Pass empty dict for errors
                           submitted_data={}) # <-- Add this: Pass empty dict for submitted_data

# --- VIEW SUBMISSIONS Route ---
@app.route('/form/<int:form_id>/submissions')
@login_required
def view_submissions(form_id):
    form = Form.query.get_or_404(form_id)

    # Check ownership
    if form.author != current_user:
        flash('You do not have permission to view submissions for this form.', 'danger')
        return redirect(url_for('dashboard'))

    # Fetch form fields to use as table headers (ordered)
    fields = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()

    # Fetch submissions for this form, newest first
    submissions_raw = Submission.query.filter_by(form_id=form.id).order_by(Submission.submitted_at.desc()).all()

    # Process submissions: parse JSON data
    parsed_submissions = []
    for sub in submissions_raw:
        try:
            # Load the JSON string from the 'data' column into a Python dict
            data_dict = json.loads(sub.data)
        except json.JSONDecodeError:
            # Handle cases where data might not be valid JSON
            data_dict = {"error": "Could not parse submission data."}
            print(f"Warning: Could not parse JSON for submission ID {sub.id}")

        parsed_submissions.append({
            'id': sub.id,
            'submitted_at': sub.submitted_at,
            'data': data_dict # Store the parsed dictionary
        })

    return render_template('view_submissions.html',
                           title=f'Submissions for {form.title}',
                           form=form,
                           fields=fields, # For table headers
                           submissions=parsed_submissions) # Parsed data

# --- EDIT FIELD Route ---
@app.route('/edit_field/<int:field_id>', methods=['GET', 'POST'])
@login_required
def edit_field(field_id):
    field_to_edit = Field.query.get_or_404(field_id)
    parent_form = field_to_edit.form # Get the parent form

    # IMPORTANT: Verify ownership of the PARENT FORM
    if parent_form.author != current_user:
        flash('You do not have permission to edit this field.', 'danger')
        return redirect(url_for('dashboard'))

    # --- Handle SAVING changes (POST request) ---
    if request.method == 'POST':
        new_label = request.form.get('field_label')
        new_type = request.form.get('field_type')
        new_required = 'field_required' in request.form
        new_options = request.form.get('field_options')

        # Validation
        if not new_label:
            flash('Field label is required.', 'warning')
            # Re-render edit page with error (could also pass back submitted values)
            return render_template('edit_field.html',
                                   title=f'Edit Field: {field_to_edit.label}',
                                   field=field_to_edit,
                                   allowed_field_types=ALLOWED_FIELD_TYPES)
        elif new_type not in ALLOWED_FIELD_TYPES:
            flash('Invalid field type selected.', 'warning')
            return render_template('edit_field.html',
                                   title=f'Edit Field: {field_to_edit.label}',
                                   field=field_to_edit,
                                   allowed_field_types=ALLOWED_FIELD_TYPES)
        else:
            # Update the field object's attributes
            field_to_edit.label = new_label
            field_to_edit.field_type = new_type
            field_to_edit.required = new_required
            # Only update options if the type supports it, clear otherwise
            field_to_edit.options = new_options if new_type in ['radio', 'select'] else None

            try:
                db.session.commit() # Commit the changes to the existing field object
                flash(f'Field "{new_label}" updated successfully.', 'success')
                # Redirect back to the parent form's field management page
                return redirect(url_for('edit_form', form_id=parent_form.id))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating field: {e}', 'danger')
                print(f"Error updating field ID {field_id}: {e}")
                # Redirect back to edit_form on error too? Or re-render edit_field?
                return redirect(url_for('edit_form', form_id=parent_form.id))

    # --- Display the edit form (GET request) ---
    return render_template('edit_field.html',
                           title=f'Edit Field: {field_to_edit.label}',
                           field=field_to_edit, # Pass the field object to pre-fill form
                           allowed_field_types=ALLOWED_FIELD_TYPES) # For the type dropdown

if __name__ == '__main__':
    # Ensure database tables are created before running the app for the first time
    # with app.app_context():
        # db.drop_all() # Use this carefully only if you need to reset the DB structure
        # db.create_all()
       # print("Database tables checked/created.")
    app.run(host='0.0.0.0', port=81) # Standard Replit config
