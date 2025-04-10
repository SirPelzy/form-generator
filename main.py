# main.py
import os
from flask import Flask, render_template, redirect, url_for, flash, request, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import uuid
import hmac
import hashlib
import time # Might be needed for timestamp checking depending on Paddle's method
from flask import request, abort, jsonify, flash, redirect, url_for # Import request, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from models import db, User, Form, Field, Submission # Import db and models directly now
from forms import RegistrationForm, LoginForm # Import our new forms
import secrets
from flask_wtf.csrf import validate_csrf 
from wtforms.validators import ValidationError
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, date
import requests
import csv
import io # Input/Output operations
from flask import Response # To build the CSV response
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content

# --- Load Paddle Configuration ---
PADDLE_VENDOR_ID = os.environ.get('PADDLE_VENDOR_ID')
PADDLE_API_KEY = os.environ.get('PADDLE_API_KEY')
PADDLE_PRO_PRICE_ID = os.environ.get('PADDLE_PRO_PRICE_ID')
# We'll need this later for webhook security
PADDLE_WEBHOOK_SECRET = os.environ.get('PADDLE_WEBHOOK_SECRET')

# Optional: Check if essential Paddle vars are set (won't crash app here)
if not all([PADDLE_VENDOR_ID, PADDLE_API_KEY, PADDLE_PRO_PRICE_ID]):
     print("WARNING: Paddle environment variables (Vendor ID, API Key, Price ID) are not fully set.")
     print("         Subscription features will not work correctly.")
# --- End Paddle Configuration ---

# --- Define Tier Limits ---
MAX_FORMS_FREE_TIER = 3
MAX_SUBMISSIONS_FREE_TIER = 100
# --- End Tier Limits ---

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

# --- START: Ensure this Limiter block is PRESENT and HERE ---
limiter = Limiter(
    get_remote_address, # Use IP address to identify users for limiting
    app=app,
    default_limits=["200 per day", "50 per hour"], # Default limits for all routes
    storage_uri="memory://", # Use in-memory storage (Note: limits reset on app restart)
)
# --- END: Limiter Initialization ---

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

# --- Email Sending Helper ---
def send_notification_email(to_email, subject, html_content):
    # Ensure required env vars are set
    sg_api_key = os.environ.get('SENDGRID_API_KEY')
    from_email_addr = os.environ.get('MAIL_FROM_EMAIL')

    if not sg_api_key or not from_email_addr:
        print("ERROR: SendGrid API Key or From Email not configured. Cannot send email.")
        return False # Indicate failure

    sg = sendgrid.SendGridAPIClient(api_key=sg_api_key)
    from_email = Email(from_email_addr)
    to_email_obj = To(to_email) # Use To helper for clarity
    content = Content("text/html", html_content)
    mail = Mail(from_email, to_email_obj, subject, content)

    try:
        print(f"Attempting to send email notification to {to_email}...")
        response = sg.client.mail.send.post(request_body=mail.get())
        print(f"SendGrid response status code: {response.status_code}")
        if 200 <= response.status_code < 300:
             print("Email sent successfully!")
             return True
        else:
             print(f"SendGrid error: Status Code {response.status_code}")
             print(f"Response Body: {response.body}")
             return False
    except Exception as e:
        print(f"ERROR sending email via SendGrid: {e}")
        return False
# --- End Email Helper ---

TEMPLATES = {
    'contact_us': {
        'name': 'Contact Us Form',
        'description': 'A standard contact form with Name, Email, and Message fields.',
        'fields': [
            {'label': 'Name', 'field_type': 'text', 'required': True, 'options': None},
            {'label': 'Email', 'field_type': 'email', 'required': True, 'options': None},
            {'label': 'Message', 'field_type': 'textarea', 'required': True, 'options': None},
        ]
    },
    'simple_feedback': {
        'name': 'Simple Feedback Form',
        'description': 'Collect general feedback with optional contact info.',
        'fields': [
            {'label': 'Feedback', 'field_type': 'textarea', 'required': True, 'options': None},
            {'label': 'Rating (1-5)', 'field_type': 'select', 'required': False, 'options': '1,2,3,4,5'},
            {'label': 'Name (Optional)', 'field_type': 'text', 'required': False, 'options': None},
            {'label': 'Email (Optional)', 'field_type': 'email', 'required': False, 'options': None},
        ]
    },
    'event_rsvp': {
        'name': 'Event RSVP Form',
        'description': 'Collect attendance confirmation and guest count for an event.',
        'fields': [
            {'label': 'Name', 'field_type': 'text', 'required': True, 'options': None},
            {'label': 'Email', 'field_type': 'email', 'required': True, 'options': None},
            {'label': 'Attending?', 'field_type': 'radio', 'required': True, 'options': 'Yes, I will attend,No, I cannot attend'},
            {'label': 'Number of Guests (including yourself)', 'field_type': 'number', 'required': False, 'options': None},
        ]
    }
    # Add more templates here later
}
# --- End Templates ---

# --- Routes ---
@app.route('/')
@app.route('/home')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    # Pass a more descriptive title for SEO
    return render_template('home.html', title='Easy Online Form Builder - Create Free Web Forms')

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
        # --- CSRF Check ---
        try:
            validate_csrf(request.form.get('csrf_token'))
        except ValidationError:
             flash('Invalid CSRF token.', 'danger'); return redirect(url_for('dashboard'))

        # --- Check Action Type ---
        action = request.form.get('action')

        # --- Form Limit Check (Apply to BOTH actions) ---
        form_created = False # Flag to track if we should proceed
        if current_user.plan == 'free':
            current_form_count = Form.query.filter_by(user_id=current_user.id).count()
            if current_form_count >= MAX_FORMS_FREE_TIER:
                flash(f"You have reached the limit of {MAX_FORMS_FREE_TIER} forms for the free tier.", "warning")
                return redirect(url_for('dashboard'))
            else:
                 form_created = True # Allow creation below limit
        else: # Pro users can always create
            form_created = True

        if not form_created: # Should theoretically not be reached if check above redirects
             return redirect(url_for('dashboard'))

        # --- Process Based on Action ---
        try:
            if action == 'create_blank':
                # --- Create Blank Form Logic ---
                form_title = request.form.get('form_title')
                form_description = request.form.get('form_description')
                if not form_title:
                    flash('Form title is required.', 'warning')
                    # Re-render options page with error and previous input
                    return render_template('create_options.html', title='Create Form', templates=TEMPLATES,
                                           current_title=form_title, current_description=form_description)

                form_key = secrets.token_urlsafe(16)
                new_form = Form(title=form_title, description=form_description,
                                user_id=current_user.id, unique_key=form_key)
                db.session.add(new_form)
                db.session.commit()
                flash(f'Form "{form_title}" created successfully! Now add some fields.', 'success')
                return redirect(url_for('edit_form', form_id=new_form.id)) # Redirect to edit page

            elif action == 'create_from_template':
                # --- Create Form From Template Logic ---
                template_id = request.form.get('template_id')
                template_data = TEMPLATES.get(template_id)

                if not template_data:
                    flash('Invalid template selected.', 'warning')
                    return redirect(url_for('create_form')) # Back to options page

                form_key = secrets.token_urlsafe(16)
                # Create the form first
                new_form = Form(title=f"{template_data['name']}", # Use template name as title
                                description=template_data['description'], # Use template description
                                user_id=current_user.id, unique_key=form_key)
                db.session.add(new_form)
                # We need the ID before adding fields, commit or flush here
                db.session.commit() # Commit here to get ID reliably

                # Create fields based on template definition
                new_fields = []
                for field_def in template_data['fields']:
                    new_field = Field(
                        label=field_def['label'],
                        field_type=field_def['field_type'],
                        required=field_def['required'],
                        options=field_def.get('options'), # Use .get() for optional options
                        form_id=new_form.id # Link to the new form
                    )
                    new_fields.append(new_field)

                if new_fields:
                    db.session.add_all(new_fields)
                    db.session.commit() # Commit the new fields

                flash(f'Form "{new_form.title}" created from template! You can customize it now.', 'success')
                return redirect(url_for('edit_form', form_id=new_form.id)) # Redirect to edit page

            else:
                # Unknown action
                flash('Invalid action.', 'warning')
                return redirect(url_for('create_form'))

        except Exception as e:
            # General error handling during creation
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')
            print(f"Error during form creation (action: {action}): {e}")
            return redirect(url_for('create_form'))

    # --- GET Request ---
    # Show the page with template options and the blank form creation section
    return render_template('create_options.html', title='Create Form', templates=TEMPLATES)

# --- End of create_form function ---

# --- EDIT FORM Route (Handles Adding Fields and Displaying) ---

@app.route('/edit_form/<int:form_id>', methods=['GET', 'POST'])
@login_required
def edit_form(form_id):
    form_to_edit = Form.query.get_or_404(form_id)
    if form_to_edit.author != current_user:
        flash('You do not have permission to edit this form.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Single CSRF check for any POST to this route
        try:
            validate_csrf(request.form.get('csrf_token'))
        except ValidationError:
            flash('Invalid CSRF token.', 'danger')
            return redirect(url_for('edit_form', form_id=form_id))

        action = request.form.get('action') # Check which form was submitted

        # --- Handle Settings Update ---
        if action == 'update_settings':
            print(f"DEBUG: Updating settings for form {form_id}")
            # Basic validation for title
            new_title = request.form.get('form_title')
            if not new_title:
                flash('Form title is required.', 'warning')
            else:
                form_to_edit.title = new_title
                form_to_edit.description = request.form.get('form_description')
                # Save Pro fields only if user is Pro
                if current_user.plan == 'pro' and current_user.subscription_status == 'active':
                    # Optional: Add URL validation here (e.g., check if valid format)
                    form_to_edit.redirect_url = request.form.get('redirect_url') or None # Save None if empty
                    form_to_edit.webhook_url = request.form.get('webhook_url') or None # Save None if empty
                try:
                    db.session.commit()
                    flash("Form settings updated successfully.", "success")
                except Exception as e:
                    db.session.rollback()
                    flash(f"Error updating settings: {e}", "danger")
                    print(f"Error updating settings form {form_id}: {e}")
            # Redirect back to edit page after attempting save
            return redirect(url_for('edit_form', form_id=form_id))

        # --- Handle Adding a New Field ---
        elif action == 'add_field':
            print(f"DEBUG: Adding field to form {form_id}")
            # Keep existing logic for adding field using request.form
            field_label = request.form.get('field_label')
            field_type = request.form.get('field_type')
            field_required = 'field_required' in request.form
            field_options = request.form.get('field_options')

            if not field_label: flash('Field label is required.', 'warning')
            elif field_type not in ALLOWED_FIELD_TYPES: flash('Invalid field type selected.', 'warning')
            else:
                options = field_options if field_type in ['radio', 'select'] else None
                new_field = Field(label=field_label, field_type=field_type, required=field_required,
                                  options=options, form_id=form_id)
                try:
                    db.session.add(new_field)
                    db.session.commit()
                    flash(f'Field "{field_label}" added successfully.', 'success')
                except Exception as e:
                    db.session.rollback(); flash(f'Error adding field: {e}', 'danger'); print(f"Error adding field: {e}")
            # Redirect back to edit page after attempting add
            return redirect(url_for('edit_form', form_id=form_id))
        else:
            # Unknown action
            flash("Invalid form action submitted.", "warning")
            return redirect(url_for('edit_form', form_id=form_id))

    # --- Display Page (GET request) ---
    fields = Field.query.filter_by(form_id=form_id).order_by(Field.id).all()
    return render_template('edit_form.html',
                           title=f'Edit Form: {form_to_edit.title}',
                           form=form_to_edit, # Pass the Form model object
                           fields=fields,
                           allowed_field_types=ALLOWED_FIELD_TYPES)


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

@app.route('/form/<string:form_key>', methods=['GET', 'POST'])
@limiter.limit("60 per hour", methods=['POST']) # Rate limit POST requests
def public_form(form_key):
    # Find the form by its unique key, return 404 if not found
    # Eager load the author to avoid extra query later when checking plan
    form = Form.query.options(db.joinedload(Form.author)).filter_by(unique_key=form_key).first_or_404()
    # Fetch fields once for use in both GET and POST logic
    fields = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()

    # --- Handle form SUBMISSION (POST request) ---
    if request.method == 'POST': # Indent Level 1
        # --- CSRF Check ---
        try: # Indent Level 2
            validate_csrf(request.form.get('csrf_token'))
        except ValidationError: # Indent Level 2
            flash('Invalid submission token.', 'warning')
            # Pass necessary variables back for re-rendering
            return render_template('public_form.html', form=form, fields=fields, errors={}, submitted_data=request.form)

        # --- Initialize variables --- (Indent Level 2)
        submitted_data = request.form
        errors = {} # Define errors dict before checks
        limit_reached = False
        form_owner = form.author # Get owner (already loaded)

        # --- START: Updated Submission Limit Check --- (Indent Level 2)
        if form_owner and form_owner.plan == 'free': # Check actual plan (Indent Level 3)
            today = date.today() # Indent Level 4
            start_of_month = datetime(today.year, today.month, 1)

            submission_count = db.session.query(Submission.id).join(Form).filter( # Indent Level 4
                Form.user_id == form_owner.id,
                Submission.submitted_at >= start_of_month
            ).count()

            if submission_count >= MAX_SUBMISSIONS_FREE_TIER: # Indent Level 4
                limit_reached = True # Indent Level 5
                print(f"User {form_owner.id} (Free Tier) hit submission limit ({submission_count}/{MAX_SUBMISSIONS_FREE_TIER}) for form {form.id}")
                errors['_limit_error'] = f"This form cannot accept submissions right now (monthly limit reached)."
                flash('Monthly submission limit reached for this form.', 'warning')
                # Fall through to the error check below to re-render form
        # --- END: Updated Submission Limit Check ---

        # --- Server-Side Validation Loop (Run if limit not reached) --- (Indent Level 2)
        if not limit_reached:
            for field in fields: # Indent Level 3
                field_name = f"field_{field.id}" # Indent Level 4
                value = submitted_data.get(field_name)
                if field.required: # Indent Level 4
                    is_missing = False # Indent Level 5
                    if field.field_type == 'checkbox': # Indent Level 5
                        if field_name not in submitted_data: is_missing = True # Indent Level 6
                    elif not value: # Indent Level 5
                        is_missing = True # Indent Level 6
                    if is_missing: # Indent Level 5
                        errors[field_name] = "This field is required." # Indent Level 6

        # --- Check if any errors occurred (limit OR validation) --- (Indent Level 2)
        if errors:
            if not limit_reached: # Indent Level 3
                flash('Please correct the errors below.', 'warning')
            return render_template('public_form.html', form=form, fields=fields, errors=errors, submitted_data=submitted_data) # Indent Level 3

        # --- If NO errors (limit or validation), proceed to save --- (Indent Level 2)
        submission_data_dict = {}
        new_submission = None # Define before try block
        try: # Indent Level 3
            for field in fields: # Indent Level 4
                field_name = f"field_{field.id}" # Indent Level 5
                if field.field_type == 'checkbox': value = 'true' if field_name in submitted_data else 'false'
                else: value = submitted_data.get(field_name)
                submission_data_dict[field_name] = value # Indent Level 5

            data_json = json.dumps(submission_data_dict) # Indent Level 4
            new_submission = Submission(form_id=form.id, data=data_json)
            db.session.add(new_submission)
            db.session.commit() # Commit FIRST
            print(f"Submission {new_submission.id} saved successfully for form {form.id}") # Indent Level 4

            # --- Actions AFTER successful commit --- (Indent Level 4)

            # --- START: Send Email Notification ---
            # Ensure form_owner is defined (it should be from earlier)
            if form_owner and form_owner.plan == 'pro' and form_owner.subscription_status == 'active':
                # ---> Indent this block (Level 5)
                print(f"User {form_owner.id} is Pro, attempting email notification...")
                subject = f"New Submission for '{form.title}'"
                email_body_html = f"..." # Keep your HTML generation logic here
                for field in fields:
                    field_key = f"field_{field.id}"
                    value = submission_data_dict.get(field_key, '(empty)')
                    email_body_html += f"<li><strong>{field.label}:</strong> {value}</li>"
                email_body_html += "</ul><hr>"
                view_link = url_for('view_submissions', form_id=form.id, _external=True)
                email_body_html += f"<p><a href='{view_link}'>View all submissions in dashboard</a></p>"
                try:
                    # ---> Indent this block (Level 6)
                    send_notification_email(form_owner.email, subject, email_body_html)
                except Exception as mail_e:
                     # ---> Indent this line (Level 6)
                    print(f"ERROR: Exception occurred during email send call: {mail_e}")
            # --- END: Send Email Notification ---

            # --- START: Send Outbound Webhook --- (Indent Level 4)
            if form_owner and form_owner.plan == 'pro' and form_owner.subscription_status == 'active' and form.webhook_url:
                 # ---> Indent this block (Level 5)
                webhook_payload = { # Indent Level 6
                    'form_id': form.id,
                    'form_title': form.title,
                    'submission_id': new_submission.id,
                    'submitted_at': new_submission.submitted_at.isoformat() + 'Z',
                    'data': submission_data_dict
                }
                try: # Indent Level 6
                    # ---> Indent this block (Level 7)
                    print(f"DEBUG: Sending webhook for sub {new_submission.id} to {form.webhook_url}")
                    response = requests.post(form.webhook_url, json=webhook_payload, timeout=5)
                    print(f"DEBUG: Webhook response status: {response.status_code}")
                except requests.exceptions.RequestException as webhook_e: # Indent Level 6
                     # ---> Indent this line (Level 7)
                    print(f"ERROR: Failed to send webhook (network) to {form.webhook_url}: {webhook_e}")
                except Exception as webhook_e: # Indent Level 6
                     # ---> Indent this line (Level 7)
                     print(f"ERROR: Unexpected error sending webhook: {webhook_e}")
            # --- END: Send Outbound Webhook ---

            # --- START: Custom Redirect Logic --- (Indent Level 4)
            if form_owner and form_owner.plan == 'pro' and form_owner.subscription_status == 'active' and form.redirect_url:
                # ---> Indent this block (Level 5)
                print(f"DEBUG: Pro user has redirect URL. Redirecting to: {form.redirect_url}")
                if form.redirect_url.lower().startswith(('http://', 'https://')): # Indent Level 6
                     return redirect(form.redirect_url) # Indent Level 7
                else: # Indent Level 6
                     print(f"WARN: Invalid redirect URL protocol for form {form.id}: {form.redirect_url}") # Indent Level 7
                     flash('Submission recorded successfully. Invalid redirect URL configured by form owner.', 'info')
                     return redirect(url_for('public_form', form_key=form_key)) # Indent Level 7
            else: # Indent Level 4 (matches 'if form_owner and ...')
                 # ---> Indent this block (Level 5)
                 # Default redirect
                 flash('Thank you! Your submission has been recorded.', 'success')
                 return redirect(url_for('public_form', form_key=form_key))
            # --- END: Custom Redirect Logic ---

        except Exception as e: # Indent Level 3 (matches 'try' for saving)
            # Handle potential database errors during save
             # ---> Indent this block (Level 4)
            db.session.rollback()
            flash(f'An error occurred while saving submission: {e}', 'danger')
            print(f"Error saving submission form {form.id}: {e}")
            errors["_save_error"] = "Could not save submission due to a server error."
            return render_template('public_form.html', form=form, fields=fields, errors=errors, submitted_data=submitted_data)
        # --- End of try/except for saving ---
    # --- End of 'if request.method == POST' block ---

    # --- Display the form (GET request) --- (Indent Level 1)
    # Use fields fetched at the start
    print(f"DEBUG: Rendering public form {form.id}. Author ID: {form.author.id if form.author else 'None'}, Author Plan: '{form.author.plan if form.author else 'N/A'}', Author Status: '{form.author.subscription_status if form.author else 'N/A'}'")
    return render_template('public_form.html',
                           form=form,
                           fields=fields, # Use fields fetched at start
                           errors={}, # Pass empty dict for errors on initial load
                           submitted_data={}) # Pass empty dict for submitted data on initial load

# --- End of public_form function ---

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

@app.route('/pricing')
def pricing():
    # Get necessary Paddle config from environment variables
    client_token = os.environ.get('PADDLE_CLIENT_SIDE_TOKEN')
    pro_price_id = os.environ.get('PADDLE_PRO_PRICE_ID')

    # Get user email only if authenticated (for pre-filling checkout)
    user_email = current_user.email if current_user.is_authenticated else None
    is_authenticated = current_user.is_authenticated

    if not client_token or not pro_price_id:
        print("ERROR: PADDLE_CLIENT_SIDE_TOKEN or PADDLE_PRO_PRICE_ID missing from env vars!")
        # Handle missing config - maybe disable upgrade button in template?
        # For now, template JS will handle button state if IDs missing

    return render_template(
        'pricing.html',
        title='Pricing',
        client_token=client_token,
        pro_price_id=pro_price_id,
        user_email=user_email,
        is_authenticated=is_authenticated
    )

# main.py -> Replace the entire old paddle_webhook function with this one

@app.route('/webhooks/paddle', methods=['POST'])
@csrf.exempt # Keep webhook exempt from CSRF
def paddle_webhook():
    # 1. Verify Signature (Keep existing, verified logic)
    webhook_secret = os.environ.get('PADDLE_WEBHOOK_SECRET')
    if not webhook_secret:
        print("ERROR: PADDLE_WEBHOOK_SECRET environment variable not set.")
        abort(500)
    signature_header = request.headers.get('Paddle-Signature')
    if not signature_header:
        print("WARN: Missing Paddle-Signature header from incoming webhook.")
        abort(400)
    try:
        sig_parts = {p.split('=')[0]: p.split('=')[1] for p in signature_header.split(';')}
        timestamp_str = sig_parts.get('ts'); signature_hash = sig_parts.get('h1')
        if not timestamp_str or not signature_hash: raise ValueError("Missing ts or h1")
        timestamp = int(timestamp_str)
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300: # 5 min tolerance
            print(f"WARN: Paddle webhook timestamp difference too large: {abs(current_time - timestamp)}s.")
            abort(400)
        request_body_bytes = request.get_data()
        signed_payload = f"{timestamp}:{request_body_bytes.decode('utf-8')}"
        expected_signature = hmac.new(webhook_secret.encode('utf-8'), signed_payload.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, signature_hash):
             print("WARN: Invalid Paddle webhook signature.")
             abort(400)
        print("DEBUG: Paddle webhook signature verified successfully.")
    except Exception as e:
        print(f"ERROR: Webhook signature verification failed: {e}")
        abort(400)
    # --- END: Signature Verification ---

    # 2. Process the Event Payload
    try:
        event_data = request.json
        if not event_data:
             print("ERROR: Empty JSON payload received in webhook.")
             abort(400)

        event_type = event_data.get('event_type')
        event_payload = event_data.get('data', {})
        print(f"DEBUG: Received Paddle webhook event: {event_type}")

        # --- Find Corresponding User ---
        user_id_from_custom = event_payload.get('custom_data', {}).get('user_id')
        user = None
        if user_id_from_custom:
            try:
                user = User.query.get(int(user_id_from_custom))
                if not user: print(f"ERROR: User ID {user_id_from_custom} from custom_data not found.")
            except ValueError: print(f"ERROR: Invalid user_id format in custom_data: {user_id_from_custom}")
        # Fallback using customer_id only if custom_data lookup failed
        if not user:
             paddle_customer_id = event_payload.get('customer_id')
             if paddle_customer_id:
                 user = User.query.filter_by(paddle_customer_code=paddle_customer_id).first()
                 if not user: print(f"ERROR: Paddle Customer ID {paddle_customer_id} not found.")
             else:
                  print("ERROR: Webhook missing user_id in custom_data and customer_id. Cannot link.")

        # --- Handle Events ONLY if User Found ---
        if user:
            print(f"DEBUG: Webhook linked to User ID: {user.id}, Email: {user.email}")
            needs_commit = False
            paddle_sub_id = event_payload.get('id') # Common field for subscription events
            new_status = event_payload.get('status') # Common field for subscription events

            # --- Subscription Activation Events ---
            # Using transaction.completed OR subscription.activated
            if event_type == 'transaction.completed' and event_payload.get('origin') == 'subscription_charge':
                 # Check if this transaction activates *our* target subscription for this user
                 # Paddle Billing often includes subscription details or links transaction to it
                 linked_subscription_id = event_payload.get('subscription_id')
                 # Only activate if status isn't already active/pro
                 if linked_subscription_id and (user.plan != 'pro' or user.subscription_status != 'active'):
                     print(f"INFO: Processing {event_type} potentially activating subscription {linked_subscription_id} for user {user.id}")
                     # Fetch management URLs here via API if needed, or wait for updated event
                     user.plan = 'pro'
                     user.subscription_status = 'active' # Assume active on completion
                     user.paddle_subscription_id = linked_subscription_id # Store the actual subscription ID
                     needs_commit = True
                     print(f"INFO: User {user.id} set to Pro based on transaction completion.")

            elif event_type == 'subscription.activated':
                 if user.paddle_subscription_id == paddle_sub_id and user.subscription_status != 'active':
                     print(f"INFO: Processing {event_type} for user {user.id}, sub {paddle_sub_id}")
                     user.plan = 'pro' # Ensure plan is set
                     if new_status: user.subscription_status = new_status # Should be 'active'
                     # Try to get management URLs (might be in this payload sometimes)
                     management_urls = event_payload.get('management_urls', {})
                     update_url = management_urls.get('update_payment_method')
                     cancel_url = management_urls.get('cancel')
                     if update_url: user.paddle_update_url = update_url
                     if cancel_url: user.paddle_cancel_url = cancel_url
                     needs_commit = True
                     print(f"INFO: User {user.id} subscription status updated to {new_status} via {event_type}.")

            # --- Subscription Status Change Events ---
            elif event_type == 'subscription.updated':
                 if user.paddle_subscription_id == paddle_sub_id:
                     print(f"INFO: Processing {event_type} for user {user.id}, sub {paddle_sub_id}")
                     state_changed = False
                     # Update status only if it changed
                     if new_status and user.subscription_status != new_status:
                         user.subscription_status = new_status
                         state_changed = True
                         print(f"INFO: User {user.id} subscription status updated to {new_status}.")
                     # Update management URLs if provided and different
                     management_urls = event_payload.get('management_urls', {})
                     update_url = management_urls.get('update_payment_method')
                     cancel_url = management_urls.get('cancel')
                     if update_url and user.paddle_update_url != update_url:
                         user.paddle_update_url = update_url
                         state_changed = True
                     if cancel_url and user.paddle_cancel_url != cancel_url:
                         user.paddle_cancel_url = cancel_url
                         state_changed = True
                     if state_changed: needs_commit = True
                 else: print(f"WARN: Mismatched sub ID for {event_type}")

            elif event_type == 'subscription.paused':
                 if user.paddle_subscription_id == paddle_sub_id and user.subscription_status != 'paused':
                      print(f"INFO: Processing {event_type} for user {user.id}, sub {paddle_sub_id}")
                      user.subscription_status = 'paused'
                      needs_commit = True
                 else: print(f"WARN: Mismatched sub ID or already paused for {event_type}")

            elif event_type == 'subscription.resumed': # Check exact event name in Paddle docs
                 if user.paddle_subscription_id == paddle_sub_id and user.subscription_status != 'active':
                      print(f"INFO: Processing {event_type} for user {user.id}, sub {paddle_sub_id}")
                      user.subscription_status = 'active' # Resumed to active
                      needs_commit = True
                 else: print(f"WARN: Mismatched sub ID or already active for {event_type}")

            elif event_type == 'subscription.past_due':
                 if user.paddle_subscription_id == paddle_sub_id and user.subscription_status != 'past_due':
                     print(f"INFO: Processing {event_type} for user {user.id}, sub {paddle_sub_id}")
                     user.subscription_status = 'past_due'
                     needs_commit = True
                 else: print(f"WARN: Mismatched sub ID or already past_due for {event_type}")

            elif event_type == 'subscription.canceled':
                 if user.paddle_subscription_id == paddle_sub_id and user.subscription_status != 'canceled':
                     print(f"INFO: Processing {event_type} for user {user.id}, sub {paddle_sub_id}")
                     user.subscription_status = 'canceled'
                     user.plan = 'free' # Revert plan immediately upon cancellation notification
                     needs_commit = True
                 else: print(f"WARN: Mismatched sub ID or already canceled for {event_type}")

            else:
                print(f"DEBUG: Ignored known/unhandled webhook event type: {event_type}")

            # Commit DB changes if any updates were made
            if needs_commit:
                try:
                    db.session.commit()
                    print(f"INFO: Database commit successful for user {user.id} after event {event_type}")
                except Exception as e:
                    db.session.rollback()
                    print(f"ERROR: DB Error committing changes for user {user.id} after event {event_type}: {e}")
                    abort(500) # Signal internal error to Paddle

        else: # User not found
             print(f"ERROR: Could not find user to process webhook event: {event_type}")
             # Still return 200 OK to prevent Paddle retries for this event
             pass

    # Catch errors during JSON parsing or initial processing
    except Exception as e:
         print(f"ERROR: Failed to parse or process webhook payload: {e}")
         # Return 200 to prevent Paddle retries if payload might be malformed
         return jsonify({'status': 'processing_error'}), 200

    # Acknowledge receipt to Paddle if we didn't abort
    return jsonify({'status': 'received'}), 200

# --- End of paddle_webhook function ---

@app.route('/profile')
@login_required
def profile():
    # The current_user object is automatically available via Flask-Login
    return render_template('profile.html', title='Your Profile', user=current_user)


@app.route('/form/<int:form_id>/download/csv')
@login_required
def download_submissions_csv(form_id):
    form = Form.query.get_or_404(form_id)

    # --- Authorization Check: Owner AND Pro Plan ---
    if form.author != current_user:
        flash("You do not have permission to download submissions for this form.", "danger")
        return redirect(url_for('dashboard'))
    if not (current_user.plan == 'pro' and current_user.subscription_status == 'active'):
        flash("CSV download is a Pro feature. Please upgrade your plan.", "warning")
        # Redirect back to submissions page or pricing page
        return redirect(url_for('view_submissions', form_id=form.id))
    # --- End Authorization Check ---

    # Fetch data needed for CSV
    fields = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()
    submissions_raw = Submission.query.filter_by(form_id=form.id).order_by(Submission.submitted_at.asc()).all() # Oldest first typically better for export

    # Use StringIO to build CSV in memory
    si = io.StringIO()
    cw = csv.writer(si)

    # --- Create CSV Header ---
    header = ['Submission ID', 'Submitted At'] # Standard columns first
    field_labels = {f"field_{field.id}": field.label for field in fields} # Map field_id to label for header lookup
    header.extend([field.label for field in fields])
    cw.writerow(header)

    # --- Write Data Rows ---
    for sub in submissions_raw:
        try:
            data_dict = json.loads(sub.data) # Parse the stored JSON data
        except json.JSONDecodeError:
            data_dict = {"error": "parse_error"} # Handle potential bad data

        row = [
            sub.id,
            sub.submitted_at.strftime('%Y-%m-%d %H:%M:%S') # Format timestamp
        ]
        # Add data for each field column, in the same order as headers
        for field in fields:
            field_key = f"field_{field.id}"
            row.append(data_dict.get(field_key, '')) # Use .get() for safety if data missing
        cw.writerow(row)

    # --- Create Flask Response ---
    output = si.getvalue()
    # Create filename, ensuring it's safe
    safe_title = "".join(c if c.isalnum() else "_" for c in form.title) # Basic sanitization
    filename = f"form_{form.id}_{safe_title}_submissions.csv"

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

# --- End download_submissions_csv function ---

# main.py -> Replace the existing subscription_management route

@app.route('/subscription')
@login_required
def subscription_management():
    # User object is available via current_user

    # Initialize variables for management URLs
    paddle_update_url = None
    paddle_cancel_url = None

    # Only attempt to fetch URLs if user has an active/paused/past_due Paddle subscription ID
    if current_user.paddle_subscription_id and current_user.plan == 'pro':
        print(f"DEBUG: User {current_user.id} has paddle sub ID {current_user.paddle_subscription_id}. Fetching management URLs.")

        # Determine Paddle API Base URL
        is_production = os.environ.get('FLASK_ENV') == 'production'
        api_base_url = "https://api.paddle.com" if is_production else "https://sandbox-api.paddle.com"
        subscription_api_url = f"{api_base_url}/subscriptions/{current_user.paddle_subscription_id}"

        # Define Headers
        headers = { 'Authorization': f'Bearer {PADDLE_API_KEY}' } # Assumes PADDLE_API_KEY is loaded

        try:
            # Make API call to GET subscription details
            response = requests.get(subscription_api_url, headers=headers, timeout=10)
            response.raise_for_status() # Check for HTTP errors

            response_data = response.json()

            # Extract management URLs from the response (using .get for safety)
            management_urls = response_data.get('data', {}).get('management_urls', {})
            paddle_update_url = management_urls.get('update_payment_method')
            paddle_cancel_url = management_urls.get('cancel')
            print(f"DEBUG: Retrieved management URLs: Update={paddle_update_url}, Cancel={paddle_cancel_url}")

        except requests.exceptions.RequestException as e:
             print(f"ERROR: Network error fetching Paddle subscription details: {e}")
             flash("Could not retrieve subscription management links due to a network error.", "warning")
        except Exception as e:
             print(f"ERROR: Failed to fetch/parse Paddle subscription details: {e}")
             # Log potential structured error from Paddle if available in response
             if hasattr(e, 'response') and e.response is not None:
                 try: print(f"DEBUG: Paddle Error Response: {e.response.text}")
                 except: pass # Ignore if can't get text
             flash("Could not retrieve subscription management links.", "warning")

    # Render template, passing the user object AND the potentially fetched URLs
    return render_template(
        'subscription.html',
        title='Manage Subscription',
        user=current_user,
        update_url=paddle_update_url, # Pass fetched URL (or None)
        cancel_url=paddle_cancel_url   # Pass fetched URL (or None)
    )

@app.route('/terms')
def terms_of_service():
    return render_template('terms.html', title='Terms of Service')

@app.route('/privacy')
def privacy_policy():
    # Renders the privacy.html template
    return render_template('privacy.html', title='Privacy Policy')

if __name__ == '__main__':
    # Ensure database tables are created before running the app for the first time
    # with app.app_context():
        # db.drop_all() # Use this carefully only if you need to reset the DB structure
        # db.create_all()
       # print("Database tables checked/created.")
    app.run(host='0.0.0.0', port=81) # Standard Replit config
