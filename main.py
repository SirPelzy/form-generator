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
from flask import request, abort, jsonify # Import request, abort, jsonify
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

# Create Form Route #
@app.route('/create_form', methods=['GET', 'POST'])
@login_required
def create_form():
    if request.method == 'POST':
        # *** START: Form Limit Check ***
        if current_user.plan == 'free': # Check the user's plan attribute
            current_form_count = Form.query.filter_by(user_id=current_user.id).count()
            if current_form_count >= MAX_FORMS_FREE_TIER:
                flash(f"You have reached the limit of {MAX_FORMS_FREE_TIER} forms for the free tier. Delete an existing form or upgrade for more.", "warning")
                return redirect(url_for('dashboard')) # Or pricing page
        # *** END: Form Limit Check ***
        
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
@limiter.limit("60 per hour", methods=['POST']) # Keep rate limit
def public_form(form_key):
    # Find the form by its unique key, return 404 if not found
    # Eager load the author to avoid extra query later when checking plan
    form = Form.query.options(db.joinedload(Form.author)).filter_by(unique_key=form_key).first_or_404()
    # Fetch fields once for both GET and POST logic if needed for rendering
    fields = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()

    # --- Handle form SUBMISSION (POST request) ---
    if request.method == 'POST':
        # --- CSRF Check ---
        try:
            validate_csrf(request.form.get('csrf_token'))
        except ValidationError:
            flash('Invalid submission token.', 'warning')
            # Pass necessary variables back for re-rendering
            return render_template('public_form.html', form=form, fields=fields, errors={}, submitted_data=request.form)

        # --- Initialize variables ---
        submitted_data = request.form
        errors = {} # Define errors dict before checks
        limit_reached = False
        form_owner = form.author # Get owner (already loaded)

        # --- START: Updated Submission Limit Check ---
        # Check limits ONLY if the form owner exists and is on the free plan
        if form_owner and form_owner.plan == 'free': # <--- Check actual plan
            today = date.today()
            start_of_month = datetime(today.year, today.month, 1)

            # Count submissions this month for ALL forms owned by this user
            submission_count = db.session.query(Submission.id).join(Form).filter(
                Form.user_id == form_owner.id,
                Submission.submitted_at >= start_of_month
            ).count()

            if submission_count >= MAX_SUBMISSIONS_FREE_TIER:
                limit_reached = True
                print(f"User {form_owner.id} (Free Tier) hit submission limit ({submission_count}/{MAX_SUBMISSIONS_FREE_TIER}) for form {form.id}")
                errors['_limit_error'] = f"This form cannot accept submissions right now (monthly limit reached)."
                flash('Monthly submission limit reached for this form.', 'warning')
                # Fall through to the error check below to re-render form
        # --- END: Updated Submission Limit Check ---

        # --- Server-Side Validation Loop (Run if limit not reached) ---
        if not limit_reached:
            for field in fields:
                field_name = f"field_{field.id}"
                value = submitted_data.get(field_name)
                if field.required:
                    is_missing = False
                    if field.field_type == 'checkbox':
                        if field_name not in submitted_data: is_missing = True
                    elif not value: is_missing = True
                    if is_missing:
                        errors[field_name] = "This field is required."

        # --- Check if any errors occurred (limit OR validation) ---
        if errors:
            if not limit_reached: # Only flash validation error if no limit error occurred
                flash('Please correct the errors below.', 'warning')
            # Re-render the template with errors and submitted data
            return render_template('public_form.html', form=form, fields=fields, errors=errors, submitted_data=submitted_data)

        # --- If NO errors (limit or validation), proceed to save ---
        submission_data_dict = {}
        try:
            for field in fields:
                field_name = f"field_{field.id}"
                if field.field_type == 'checkbox': value = 'true' if field_name in submitted_data else 'false'
                else: value = submitted_data.get(field_name)
                submission_data_dict[field_name] = value

            data_json = json.dumps(submission_data_dict)
            new_submission = Submission(form_id=form.id, data=data_json)
            db.session.add(new_submission)
            db.session.commit()
            flash('Thank you! Your submission has been recorded.', 'success')
            return redirect(url_for('public_form', form_key=form_key)) # PRG pattern

        except Exception as e:
            # Handle potential database errors during save
            db.session.rollback()
            flash(f'An error occurred while saving submission: {e}', 'danger')
            print(f"Error saving submission form {form.id}: {e}")
            errors["_save_error"] = "Could not save submission due to a server error."
            return render_template('public_form.html', form=form, fields=fields, errors=errors, submitted_data=submitted_data)

    if 'fields' not in locals(): # Ensure fields is defined if POST wasn't hit
         fields_for_display = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()
    else:
         fields_for_display = fields # Use fields from POST logic if defined
    # ---> ADD THIS DEBUG PRINT <---
    if form.author:
        print(f"DEBUG: Rendering public form {form.id}. Author ID: {form.author.id}, Author Plan: '{form.author.plan}', Author Status: '{form.author.subscription_status}'")
    else:
        # This would indicate a problem loading the relationship
        print(f"DEBUG: Rendering public form {form.id}. Author relationship not loaded or null.")
    # ---> END DEBUG PRINT <---
    # --- Display the form (GET request) ---
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
@csrf.exempt # Exclude webhook route from session-based CSRF check
def paddle_webhook():
    # 1. Verify Signature (CRITICAL FOR SECURITY)
    webhook_secret = os.environ.get('PADDLE_WEBHOOK_SECRET')
    if not webhook_secret:
        print("ERROR: PADDLE_WEBHOOK_SECRET environment variable not set.")
        abort(500) # Internal Server Error if secret missing

    signature_header = request.headers.get('Paddle-Signature')
    if not signature_header:
        print("WARN: Missing Paddle-Signature header from incoming webhook.")
        abort(400) # Bad Request

    try: # Main try block for signature verification logic
        # Step 2: Extract timestamp and signature hash from header
        timestamp_str = None
        signature_hash = None
        for part in signature_header.split(';'):
            if '=' in part: # Ensure proper format before splitting
                key, value = part.split('=', 1)
                if key == 'ts':
                    timestamp_str = value
                elif key == 'h1':
                    signature_hash = value
            else:
                print(f"WARN: Malformed part in Paddle-Signature header: {part}")

        if not timestamp_str or not signature_hash:
            raise ValueError("Paddle-Signature header missing 'ts' or 'h1'")

        timestamp = int(timestamp_str)

        # Step 2b: Check timestamp tolerance
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300: # 5 minutes tolerance
            print(f"WARN: Paddle webhook timestamp difference too large: {abs(current_time - timestamp)}s.")
            abort(400) # Bad Request - Timestamp outside tolerance

        # Step 3: Build signed payload
        request_body_bytes = request.get_data()
        signed_payload = f"{timestamp}:{request_body_bytes.decode('utf-8')}" # Use COLON

        # Step 4: Hash signed payload
        expected_signature = hmac.new(
            webhook_secret.encode('utf-8'),
            signed_payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        # Step 5: Compare signatures securely
        if not hmac.compare_digest(expected_signature, signature_hash):
             print("WARN: Invalid Paddle webhook signature.")
             abort(400) # Bad Request - Signature mismatch

        print("DEBUG: Paddle webhook signature verified successfully.")

    except Exception as e:
        # Catch errors during signature verification
        print(f"ERROR: Webhook signature verification failed: {e}")
        abort(400) # Bad Request on verification error
    # --- END: Signature Verification ---

    # If signature verification passed, process the event
    try: # Start try block for event processing (Level 1 indent)
        # Parse JSON only AFTER verifying signature using the raw body
        event_data = request.json
        if not event_data: # Handle empty JSON body
             print("ERROR: Empty JSON payload received in webhook.")
             abort(400)

        event_type = event_data.get('event_type')
        event_payload = event_data.get('data', {})
        print(f"DEBUG: Received Paddle webhook event: {event_type}")

        # --- START: Handle Specific Events --- (Level 2 indent)
        user_id = event_payload.get('custom_data', {}).get('user_id')
        user = None

        if user_id: # (Level 3 indent)
            try: # (Level 4 indent)
                user = User.query.get(int(user_id))
                if not user: # (Level 5 indent)
                     print(f"ERROR: Webhook received for non-existent user ID: {user_id}")
            except ValueError: # (Level 4 indent)
                 print(f"ERROR: Invalid user_id format in custom_data: {user_id}")
        else: # (Level 3 indent)
             # Fallback: Try finding user via Paddle Customer ID
             paddle_customer_id = event_payload.get('customer_id')
             if paddle_customer_id: # (Level 4 indent)
                  user = User.query.filter_by(paddle_customer_code=paddle_customer_id).first()
                  if not user: # (Level 5 indent)
                       print(f"ERROR: Webhook received for unknown Paddle Customer ID: {paddle_customer_id}")
             else: # (Level 4 indent)
                  print("ERROR: Webhook payload missing custom_data.user_id and customer_id. Cannot link to user.")

        # Proceed only if we found a user
        if user:
            print(f"DEBUG: Webhook linked to User ID: {user.id}, Email: {user.email}")
            needs_commit = False # Flag to track if DB change needed

            # --- Subscription Activated/Created ---
            # Check Paddle docs for the exact event type signifying a new active subscription
            if event_type in ['subscription.activated', 'subscription.created']:
                print(f"INFO: Processing {event_type} for user {user.id}")
                subscription_id = event_payload.get('id')
                status = event_payload.get('status') # Should be 'active'

                # Update user record in your database
                user.plan = 'pro' # Assuming only one paid plan for now
                if status: user.subscription_status = status
                if subscription_id: user.paddle_subscription_id = subscription_id
                needs_commit = True
                print(f"INFO: User {user.id} plan set to Pro (Paddle Sub ID: {subscription_id})")

            # --- Subscription Cancelled ---
            elif event_type == 'subscription.canceled':
                print(f"INFO: Processing {event_type} for user {user.id}")
                paddle_sub_id = event_payload.get('id')
                # Check if the cancellation event is for the user's current subscription
                if user.paddle_subscription_id == paddle_sub_id:
                    new_status = event_payload.get('status') # Should be 'canceled'
                    # Check for scheduled change (Paddle might cancel at period end)
                    # scheduled_change = event_payload.get('scheduled_change') # TODO: Handle this later if needed
                    if new_status: user.subscription_status = new_status
                    # Decide on plan change: revert immediately or wait? Revert status now.
                    # user.plan = 'free' # Optional: Revert plan immediately
                    needs_commit = True
                    print(f"INFO: User {user.id} subscription status updated to {new_status}.")
                else:
                     print(f"WARN: Received cancellation for sub ID {paddle_sub_id} but user {user.id} has sub ID {user.paddle_subscription_id}")

            # --- Subscription Updated (e.g., payment method update, pause/resume) ---
            elif event_type == 'subscription.updated':
                print(f"INFO: Processing {event_type} for user {user.id}")
                paddle_sub_id = event_payload.get('id')
                # Check if the update is for the user's current subscription
                if user.paddle_subscription_id == paddle_sub_id:
                    new_status = event_payload.get('status')
                    if new_status: user.subscription_status = new_status
                    # Update management URLs as they might change
                    needs_commit = True
                    print(f"INFO: User {user.id} subscription status updated to {new_status} (via updated event).")
                else:
                     print(f"WARN: Received update for sub ID {paddle_sub_id} but user {user.id} has sub ID {user.paddle_subscription_id}")

            # --- Other events ---
            else:
                print(f"DEBUG: Ignored webhook event type: {event_type}")

            # --- Commit DB Changes if needed ---
            if needs_commit:
                try:
                    db.session.commit()
                    print(f"INFO: Database committed successfully for user {user.id} after event {event_type}")
                except Exception as e:
                    db.session.rollback()
                    print(f"ERROR: DB Error committing changes for user {user.id} after {event_type}: {e}")
                    abort(500) # Internal error processing update

        else:
            # Could not find user associated with webhook
            print(f"ERROR: Could not find user for webhook event: {event_type}")
            # Still return 200 OK to Paddle even if user not found, to prevent retries.
            pass # Important to pass here, don't abort
    # --- End Event Handling Logic ---

    # ---> CORRECTED INDENTATION: This except matches the 'try' around event processing <---
    except Exception as e: # (Level 1 indent)
         # ---> Indent this block (Level 2)
         print(f"ERROR: Failed to parse or process webhook JSON payload: {e}")
         # Return 200 to prevent Paddle retries if payload was malformed/unexpected,
         # but log error for investigation.
         return jsonify({'status': 'processing_error'}), 200
    # --- END Event Processing Try/Except ---

    # 3. Acknowledge Receipt to Paddle if processed successfully or ignored gracefully
    return jsonify({'status': 'received'}), 200 # (Level 1 indent)

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
