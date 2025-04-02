# main.py
import os
from flask import Flask, render_template, redirect, url_for, flash, request, current_app
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

@app.route('/create_form', methods=['GET', 'POST'])
@login_required
def create_form():
    if request.method == 'POST':
        # *** START: Form Limit Check ***
        # Assuming only free tier exists for now
        current_form_count = Form.query.filter_by(user_id=current_user.id).count()
        if current_form_count >= MAX_FORMS_FREE_TIER:
            flash(f"You have reached the limit of {MAX_FORMS_FREE_TIER} forms for the free tier. Delete an existing form or upgrade for more.", "warning")
            return redirect(url_for('dashboard')) # Redirect back to dashboard
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
def public_form(form_key):
    # Find the form by its unique key, return 404 if not found
    form = Form.query.filter_by(unique_key=form_key).first_or_404()

    # --- Handle form SUBMISSION (POST request) ---
    if request.method == 'POST':
        # --- START: Submission Limit Check --- (Indented Level 1)
        form_owner = form.author # Get the owner of the form being submitted to
        # For now, assume all users are on the free tier
        is_free_tier = True # TODO: Replace with check on user's actual plan later
        if is_free_tier: # (Indented Level 2)
            # ---> This block indented (Level 3)
            today = date.today()
            start_of_month = datetime(today.year, today.month, 1)

            # Count submissions this month for ALL forms owned by this user
            submission_count = db.session.query(Submission.id).join(Form).filter(
                Form.user_id == form_owner.id,
                Submission.submitted_at >= start_of_month
            ).count() # More efficient count

            if submission_count >= MAX_SUBMISSIONS_FREE_TIER: # (Indented Level 3)
                # ---> This block indented (Level 4)
                # Limit reached - show error and re-render form
                # NOTE: This prevents the submission from being saved
                print(f"User {form_owner.id} hit submission limit ({submission_count}/{MAX_SUBMISSIONS_FREE_TIER}) for form {form.id}")
                # Use a specific error key for the template if needed
                errors = {'_limit_error': f"This form cannot accept submissions right now (monthly limit reached)."}
                # Re-render form, passing back submitted data and error
                # Need fields for re-rendering template correctly
                fields = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()
                return render_template('public_form.html', form=form, fields=fields, errors=errors, submitted_data=request.form)
        # --- END: Submission Limit Check ---

        # Fetch the fields associated with this form again for validation (Indented Level 2)
        fields = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()
        submitted_data = request.form # Get submitted data
        errors = {} # Dictionary to store validation errors

        # --- Server-Side Validation Loop --- (Indented Level 2)
        for field in fields: # (Indented Level 3)
            field_name = f"field_{field.id}"
            value = submitted_data.get(field_name)

            if field.required: # (Indented Level 4)
                is_missing = False
                if field.field_type == 'checkbox': # (Indented Level 5)
                    # Required checkbox must be present in the form data
                    if field_name not in submitted_data: # (Indented Level 6)
                        is_missing = True
                elif not value: # (Indented Level 5) Check if value is None or empty string for others
                    is_missing = True

                if is_missing: # (Indented Level 5)
                    errors[field_name] = "This field is required." # (Indented Level 6)
            # --- Add other validations later if needed (e.g., email format) ---

        # --- Check if any errors occurred --- (Indented Level 2)
        if errors:
             # ---> This block indented (Level 3)
            flash('Please correct the errors below.', 'warning')
            # Re-render the form template, passing errors and submitted data back
            return render_template('public_form.html',
                                   form=form,
                                   fields=fields,
                                   errors=errors, # Pass errors dict
                                   submitted_data=submitted_data) # Pass submitted data

        # --- If validation passed, proceed to save submission --- (Indented Level 2)
        submission_data_dict = {}
        try: # (Indented Level 3)
             # ---> This block indented (Level 4)
            for field in fields: # (Indented Level 5)
                field_name = f"field_{field.id}"
                if field.field_type == 'checkbox': # (Indented Level 6)
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

        except Exception as e: # (Indented Level 3)
             # ---> This block indented (Level 4)
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
        # --- End of try/except for saving ---
    # --- End of 'if request.method == POST' block ---

    # --- Display the form (GET request) --- (Indented Level 1)
    # Fetch fields for display if it's a GET request
    fields_for_display = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()
    return render_template('public_form.html',
                           form=form,
                           fields=fields_for_display,
                           errors={}, # Pass empty dict for errors
                           submitted_data={}) # Pass empty dict for submitted_data

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

    if not client_token or not pro_price_id:
        print("ERROR: PADDLE_CLIENT_SIDE_TOKEN or PADDLE_PRO_PRICE_ID missing from env vars!")
        # Handle missing config - maybe disable upgrade button in template?
        # For now, template JS will handle button state if IDs missing

    return render_template(
        'pricing.html',
        title='Pricing',
        client_token=client_token,
        pro_price_id=pro_price_id,
        user_email=user_email
    )

# main.py -> Replace the entire old paddle_webhook function with this one
@app.route('/webhooks/paddle', methods=['POST'])
@csrf.exempt # Uncomment this if CSRF protection interferes later
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

    try: # Main try block for verification
        # Step 2: Extract timestamp and signature hash from header
        timestamp_str = None
        signature_hash = None
        for part in signature_header.split(';'):
            # Ensure splitting results in two parts before unpacking
            if '=' in part:
                key, value = part.split('=', 1)
                if key == 'ts':
                    timestamp_str = value
                elif key == 'h1':
                    signature_hash = value
            else:
                # Handle cases where a part might not have '=' (though unlikely for Paddle)
                print(f"WARN: Malformed part in Paddle-Signature header: {part}")


        if not timestamp_str or not signature_hash:
            raise ValueError("Paddle-Signature header missing 'ts' or 'h1'")

        timestamp = int(timestamp_str) # Convert timestamp string to integer

        # Step 2b (Optional but Recommended): Check timestamp tolerance (e.g., within 5 minutes)
        current_time = int(time.time()) # Get current Unix timestamp
        if abs(current_time - timestamp) > 300: # 300 seconds = 5 minutes
            print(f"WARN: Paddle webhook timestamp difference too large: {abs(current_time - timestamp)}s.")
            abort(400) # Bad Request - Timestamp outside tolerance

        # Step 3: Build signed payload (Timestamp + Colon + Raw Body)
        request_body_bytes = request.get_data() # Get raw request body bytes BEFORE parsing JSON
        signed_payload = f"{timestamp}:{request_body_bytes.decode('utf-8')}" # Use COLON separator

        # Step 4: Hash signed payload using HMAC-SHA256
        expected_signature = hmac.new(
            webhook_secret.encode('utf-8'),
            signed_payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        # Step 5: Compare signatures securely
        if not hmac.compare_digest(expected_signature, signature_hash):
             print("WARN: Invalid Paddle webhook signature.")
             abort(400) # Bad Request - Signature mismatch

        # If we reach here, the signature is valid
        print("DEBUG: Paddle webhook signature verified successfully.")

    except Exception as e:
        # Catch potential errors during parsing or verification
        print(f"ERROR: Webhook signature verification failed: {e}")
        abort(400) # Bad Request on any verification error
    # --- END: Signature Verification ---

    # If verification passed, continue to process event...
    # Parse JSON only AFTER verifying signature using the raw body
    try:
        event_data = request.json
        if not event_data: # Handle empty JSON body
             print("ERROR: Empty JSON payload received in webhook.")
             abort(400)
        event_type = event_data.get('event_type')
        event_payload = event_data.get('data', {}) # The actual event details

        print(f"DEBUG: Received Paddle webhook event: {event_type}")

        # --- TODO: Add logic here later to handle specific event_types ---
        # Example:
        # if event_type == 'subscription.created' or event_type == 'subscription.activated':
        #     # Find user via custom_data or customer_id in event_payload
        #     # Update user plan/status in DB
        #     # db.session.commit()
        #     pass
        # elif event_type == 'subscription.canceled':
        #     # Find user
        #     # Update user status in DB
        #     # db.session.commit()
        #     pass
        # --- End TODO ---

    except Exception as e:
         print(f"ERROR: Failed to parse or process webhook JSON payload: {e}")
         # Still return 200 to Paddle if signature was okay but processing failed,
         # otherwise Paddle might retry indefinitely. Log the error for investigation.
         return jsonify({'status': 'processing_error'}), 200


    # 3. Acknowledge Receipt to Paddle if processed successfully
    return jsonify({'status': 'received'}), 200

# --- End of paddle_webhook function ---

@app.route('/terms')
def terms_of_service():
    return render_template('terms.html', title='Terms of Service')

if __name__ == '__main__':
    # Ensure database tables are created before running the app for the first time
    # with app.app_context():
        # db.drop_all() # Use this carefully only if you need to reset the DB structure
        # db.create_all()
       # print("Database tables checked/created.")
    app.run(host='0.0.0.0', port=81) # Standard Replit config
