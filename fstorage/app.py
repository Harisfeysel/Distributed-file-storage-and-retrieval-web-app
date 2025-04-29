import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, OperationFailure
from dotenv import load_dotenv
import datetime
from bson.objectid import ObjectId
import logging
import hashlib
import secrets
import mimetypes
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/file_storage')
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)  # Session will last for 7 days

# Initialize MongoDB with error handling
try:
    client = MongoClient(app.config['MONGO_URI'], serverSelectionTimeoutMS=5000)
    # Force a connection to verify it works
    client.admin.command('ping')
    db = client.file_storage
    users_collection = db.users
    files_collection = db.files
    folders_collection = db.folders
    
    logger.info("MongoDB connection successful")
    logger.info(f"Database collections: users, files, folders initialized")
    
    # Check if collections exist and are accessible
    try:
        users_count = users_collection.count_documents({})
        files_count = files_collection.count_documents({})
        folders_count = folders_collection.count_documents({})
        logger.info(f"Collection counts - Users: {users_count}, Files: {files_count}, Folders: {folders_count}")
    except Exception as e:
        logger.error(f"Error checking collection counts: {e}")
except (ConnectionFailure, ServerSelectionTimeoutError) as e:
    logger.error(f"MongoDB connection error: {e}")
    # We'll handle this in the routes to show a user-friendly message
    client = None
    db = None
    users_collection = None
    files_collection = None
    folders_collection = None

# Initialize Login Manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']

@login_manager.user_loader
def load_user(user_id):
    try:
        if users_collection is None:
            return None
        user_data = users_collection.find_one({'_id': ObjectId(user_id)})
        return User(user_data) if user_data else None
    except Exception as e:
        logger.error(f"Error loading user: {e}")
        return None

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if database connection is available
    if users_collection is None:
        flash('Database connection error. Please try again later or contact support.', 'danger')
        return render_template('login.html')
        
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            user_data = users_collection.find_one({'email': email})
            if user_data and check_password_hash(user_data['password'], password):
                user = User(user_data)
                login_user(user, remember=True)
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                if not user_data:
                    flash('No account found with this email address', 'danger')
                else:
                    flash('Invalid password', 'danger')
        except OperationFailure as e:
            logger.error(f"Database operation error: {e}")
            flash('Database error occurred. Please try again later.', 'danger')
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred during login. Please try again.', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Check if database connection is available
    if users_collection is None:
        flash('Database connection error. Please try again later or contact support.', 'danger')
        return render_template('register.html')
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        terms = request.form.get('terms') == 'on'  # Check if terms checkbox is checked
        
        # Basic validation
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('register.html')
            
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return render_template('register.html')
            
        if not terms:
            flash('You must agree to the terms of service', 'danger')
            return render_template('register.html')
        
        try:
            # Check if email already exists
            if users_collection.find_one({'email': email}):
                flash('Email already exists!', 'danger')
                return render_template('register.html')
            
            # Check if username already exists
            if users_collection.find_one({'username': username}):
                flash('Username already taken!', 'danger')
                return render_template('register.html')
            
            # Create the user
            hashed_password = generate_password_hash(password)
            user_id = users_collection.insert_one({
                'username': username,
                'email': email,
                'password': hashed_password,
                'created_at': datetime.datetime.now()
            }).inserted_id
            
            # Log the user in
            user = User(users_collection.find_one({'_id': user_id}))
            login_user(user)
            
            # Create user upload directory
            user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
            os.makedirs(user_upload_dir, exist_ok=True)
            
            flash('Registration successful! Welcome to File Storage App.', 'success')
            return redirect(url_for('dashboard'))
        except OperationFailure as e:
            logger.error(f"Database operation error during registration: {e}")
            flash('Database error occurred. Please try again later.', 'danger')
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.', 'danger')
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Check if database connection is available
    if files_collection is None:
        flash('Database connection error. Please try again later or contact support.', 'danger')
        return redirect(url_for('home'))
        
    try:
        # Fetch user email for Gravatar
        user_data = users_collection.find_one({'_id': ObjectId(current_user.id)})
        user_email = user_data.get('email', '') if user_data else ''
        
        # Generate Gravatar URL
        email_hash = hashlib.md5(user_email.lower().encode('utf-8')).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?s=80&d=identicon&r=g" # s=80 for slightly smaller size in dropdown

        # Get all user's files
        all_user_files = list(files_collection.find({'user_id': current_user.id}))
        
        # Calculate file statistics
        total_files_count = len(all_user_files)
        total_size = sum(file.get('size', 0) for file in all_user_files)
        
        # Find latest upload date
        latest_upload_date = None
        if all_user_files:
            latest_upload_date = max(file.get('uploaded_at', datetime.datetime.min) for file in all_user_files)
        
        # Current folder info for breadcrumb
        current_folder = {
            'id': 'root',
            'name': 'Home',
            'path': '',
            'parent_id': None
        }
        
        # Just one breadcrumb for Home
        breadcrumbs = [{
            'id': 'root',
            'name': 'Home',
            'is_current': True
        }]
        
        logger.info(f"Dashboard data - Total files: {total_files_count}")
        
        return render_template(
            'dashboard.html', 
            files=all_user_files,
            folders=[],  # No folders
            current_folder=current_folder,
            breadcrumbs=breadcrumbs,
            gravatar_url=gravatar_url,
            total_files_count=total_files_count,
            total_size=total_size,
            latest_upload_date=latest_upload_date
        )
    except Exception as e:
        logger.error(f"Error loading dashboard: {e}")
        flash('Error loading dashboard', 'danger')
        return redirect(url_for('home'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    # Check if database connection is available
    if files_collection is None:
        # Return JSON error for Dropzone
        return jsonify({'success': False, 'error': 'Database connection error. Please try again later or contact support.'}), 503 # Service Unavailable

    if 'file' not in request.files:
        # Return JSON error
        return jsonify({'success': False, 'error': 'No file part in the request.'}), 400

    file = request.files['file']
    if file.filename == '':
        # Return JSON error
        return jsonify({'success': False, 'error': 'No file selected for upload.'}), 400
    
    if file:
        try:
            # Secure the filename to prevent directory traversal attacks
            filename = secure_filename(file.filename)
            
            # Ensure user_id is a string and create user directory
            user_id_str = str(current_user.id)
            user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], user_id_str)
            
            # Ensure the upload directory exists
            os.makedirs(user_upload_folder, exist_ok=True)
            
            # Check for duplicate filename and add counter if needed
            base_name, extension = os.path.splitext(filename)
            counter = 1
            final_filename = filename
            while os.path.exists(os.path.join(user_upload_folder, final_filename)):
                final_filename = f"{base_name}_{counter}{extension}"
                counter += 1
            
            # Save the file
            file_path = os.path.join(user_upload_folder, final_filename)
            file.save(file_path)
            
            # Get file size and MIME type
            file_size = os.path.getsize(file_path)
            mime_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
            
            # Normalize path for storage in DB (always use forward slashes)
            db_file_path = os.path.join(user_id_str, final_filename).replace('\\', '/')
            
            # Store file info in database
            file_data = {
                'user_id': user_id_str,
                'filename': final_filename,
                'filepath': db_file_path,
                'folder_id': 'root',  # All files at root level
                'size': file_size,
                'content_type': mime_type,
                'uploaded_at': datetime.datetime.now()
            }
            
            file_id = files_collection.insert_one(file_data).inserted_id
            
            logger.info(f"File uploaded: {final_filename} ({file_size} bytes)")
            
            # Return success response
            return jsonify({
                'success': True,
                'file_id': str(file_id),
                'filename': final_filename,
                'size': file_size,
                'content_type': mime_type
            })
        except Exception as e:
            logger.error(f"Upload error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # Fallback error response
    return jsonify({'success': False, 'error': 'Unknown error occurred'}), 500

@app.route('/download/<file_id>')
@login_required
def download_file(file_id):
    # Check if database connection is available
    if files_collection is None:
        flash('Database connection error. Please try again later or contact support.', 'danger')
        return redirect(url_for('dashboard'))
        
    try:
        is_preview = request.args.get('preview') == 'true'
        
        # Log basic request info
        logger.info(f"Download request: file_id={file_id}, user_id={current_user.id}, preview={is_preview}")
        
        # Find the file record in database
        file_data = files_collection.find_one({
            '_id': ObjectId(file_id),
            'user_id': current_user.id
        })
        
        if not file_data:
            logger.error(f"File not found in database: file_id={file_id}, user_id={current_user.id}")
            flash('File not found', 'danger')
            return redirect(url_for('dashboard'))
        
        # --- Path Handling --- 
        stored_path = file_data['filepath']
        
        # Print complete file data for debugging
        logger.info(f"File data retrieved: {file_data}")
        
        # Normalize path based on OS
        if os.name == 'nt':  # Windows
            stored_path_os = stored_path.replace('/', '\\')
        else:  # Unix/Linux/Mac
            stored_path_os = stored_path.replace('\\', '/')
        
        base_filename = os.path.basename(stored_path_os)
        user_id_str = str(current_user.id)
        
        # Multiple possible paths to check with detailed logging
        possible_paths = [
            stored_path_os,  # The stored path in DB with OS-specific separators
            os.path.join(app.config['UPLOAD_FOLDER'], user_id_str, base_filename),  # User-specific folder path
            os.path.join(app.config['UPLOAD_FOLDER'], base_filename),  # Legacy direct path
            os.path.abspath(stored_path_os)  # Try absolute path as last resort
        ]
        
        # Log all paths being checked
        for i, path in enumerate(possible_paths):
            logger.info(f"Checking path {i+1}: {path} - Exists: {os.path.exists(path)}")
        
        # Find the first existing path
        serving_path = None
        for path in possible_paths:
            if os.path.exists(path):
                serving_path = path
                logger.info(f"File found at: {path}")
                break
                
        if not serving_path:
            logger.error(f"File not found in any possible location. Stored path: {stored_path}")
            
            # Check the upload folder to make sure it exists
            upload_folder = app.config['UPLOAD_FOLDER']
            user_folder = os.path.join(upload_folder, user_id_str)
            
            logger.info(f"Upload folder exists: {os.path.exists(upload_folder)}")
            logger.info(f"User folder exists: {os.path.exists(user_folder)}")
            
            flash('File not found on server.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Update file record with correct path if it's different from what was stored
        if os.name == 'nt':  # Windows
            db_path = serving_path.replace('\\', '/')  # Always store with forward slashes in DB
        else:
            db_path = serving_path  # Keep as is for Unix systems
            
        if db_path != stored_path:
            logger.info(f"Updating file path in database from {stored_path} to {db_path}")
            files_collection.update_one(
                {'_id': ObjectId(file_id)},
                {'$set': {'filepath': db_path}}
            )
        # --- End Path Handling ---

        # Use the determined serving_path
        dir_path = os.path.dirname(serving_path)
        file_name = os.path.basename(serving_path)
        
        # Log the final details before attempting to send
        logger.info(f"Serving file: {file_name} from directory: {dir_path}")
        logger.info(f"Final path check: {os.path.join(dir_path, file_name)} exists: {os.path.exists(os.path.join(dir_path, file_name))}")

        # For media files being previewed, we want inline display
        as_attachment = not is_preview
        
        # Set correct content type for images and media files
        mimetype = file_data.get('content_type')
        if not mimetype:
            # Try to guess mimetype if not stored
            mimetype = mimetypes.guess_type(file_name)[0]
        
        # Special handling for different file types
        if is_preview and mimetype and mimetype.startswith('video/'):
            # For video preview, use HTTP 206 partial content for streaming
            # This is handled automatically by send_from_directory
            logger.info(f"Setting up video streaming with mimetype: {mimetype}")
        
        try:
            response = send_from_directory(
                dir_path,
                file_name,
                as_attachment=as_attachment,
                mimetype=mimetype
            )
            
            # Set Content-Disposition for previews or downloads
            if is_preview:
                response.headers['Content-Disposition'] = f'inline; filename="{file_name}"'
            else:
                response.headers['Content-Disposition'] = f'attachment; filename="{file_name}"'
                
            return response
        except Exception as e:
            logger.error(f"Error sending file: {e}")
            flash(f'Error downloading file: {str(e)}', 'danger')
            return redirect(url_for('dashboard'))
        
    except OperationFailure as e:
        logger.error(f"Database operation error during download: {e}")
        flash('Database error occurred. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        flash(f'Error downloading file: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/delete_file/<file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    # Check if database connection is available
    if files_collection is None:
        return jsonify({'success': False, 'error': 'Database connection error'}), 500
        
    try:
        file_data = files_collection.find_one({
            '_id': ObjectId(file_id),
            'user_id': current_user.id
        })
        
        if not file_data:
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        # --- Path Handling for Deletion ---
        stored_path = file_data['filepath']
        # Convert forward slashes to OS-specific path separators for filesystem operations
        stored_path_os = stored_path.replace('/', os.path.sep)
        
        base_filename = os.path.basename(stored_path_os)
        
        # Multiple possible paths to check
        possible_paths = [
            stored_path_os,  # The stored path in DB with OS-specific separators
            os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id), base_filename),  # User-specific folder path
            os.path.join(app.config['UPLOAD_FOLDER'], base_filename)  # Legacy direct path
        ]
        
        # Find the first existing path
        path_to_delete = None
        for path in possible_paths:
            if os.path.exists(path):
                path_to_delete = path
                break
        
        if not path_to_delete:
            logger.warning(f"Physical file not found for deletion. Deleting DB record only.")
        # --- End Path Handling ---

        # Remove file from filesystem if found
        if path_to_delete:
            try:
                os.remove(path_to_delete)
                logger.info(f"Deleted physical file: {path_to_delete}")
            except OSError as e:
                 logger.error(f"Error deleting physical file {path_to_delete}: {e}")
                 # Proceed to delete DB record anyway, but maybe return a partial success or warning?
                 # For now, just log the error and continue.

        # Remove file from database
        files_collection.delete_one({'_id': ObjectId(file_id)})
        logger.info(f"Deleted database record for file_id: {file_id}")

        return jsonify({'success': True, 'message': 'File deleted successfully'})
    except OperationFailure as e:
        error_msg = f"Database operation error during delete: {e}"
        logger.error(error_msg)
        return jsonify({'success': False, 'error': 'Database error occurred'}), 500
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/profile')
@login_required
def profile():
    try:
        # Fetch full user data
        user_data = users_collection.find_one({'_id': ObjectId(current_user.id)})
        if not user_data:
            flash('User data not found.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Calculate total storage used
        total_size_bytes = 0
        if files_collection is not None:
            user_files = files_collection.find({'user_id': current_user.id})
            for file in user_files:
                total_size_bytes += file.get('size', 0)
                
        total_size_mb = round(total_size_bytes / (1024 * 1024), 2)
        storage_limit_mb = 1024 # Example 1GB limit
        storage_percentage = 0
        if storage_limit_mb > 0:
            storage_percentage = min(round((total_size_mb / storage_limit_mb) * 100), 100)

        # Generate Gravatar URL
        email_hash = hashlib.md5(user_data['email'].lower().encode('utf-8')).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?s=100&d=identicon&r=g"
        # s=100 -> size 100px
        # d=identicon -> default image type
        # r=g -> rating
        
        # Generate CSRF token for the password change form
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token

        return render_template(
            'profile.html', 
            user_data=user_data, 
            total_size_mb=total_size_mb, 
            storage_percentage=storage_percentage, 
            storage_limit_mb=storage_limit_mb,
            gravatar_url=gravatar_url,
            csrf_token=csrf_token
        )
        
    except OperationFailure as e:
        logger.error(f"Database error fetching profile data: {e}")
        flash('Database error occurred while loading profile.', 'danger')
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"Error loading profile page: {e}")
        flash('An error occurred while loading the profile page.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    try:
        # Verify CSRF token
        form_csrf_token = request.form.get('csrf_token')
        stored_csrf_token = session.get('csrf_token')
        
        logger.info(f"CSRF check - Form token: {form_csrf_token != None}, Stored token: {stored_csrf_token != None}")
        
        if not form_csrf_token or not stored_csrf_token or form_csrf_token != stored_csrf_token:
            logger.warning(f"CSRF token validation failed for user {current_user.id}")
            return jsonify({'success': False, 'error': 'Security validation failed.'}), 403
            
        # Log request form data for debugging - excluding the actual passwords for security
        logger.info(f"Password change attempt for user {current_user.id}")
        logger.info(f"Form fields present: {list(request.form.keys())}")
        
        # Check if required fields exist in request
        if 'currentPassword' not in request.form or 'newPassword' not in request.form or 'confirmPassword' not in request.form:
            missing_fields = set(['currentPassword', 'newPassword', 'confirmPassword']) - set(request.form.keys())
            logger.error(f"Missing required form fields: {missing_fields}")
            return jsonify({'success': False, 'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        current_password = request.form['currentPassword']
        new_password = request.form['newPassword']
        confirm_password = request.form['confirmPassword']

        # Basic validation
        if not current_password:
            logger.warning(f"Empty current password in change password attempt for user {current_user.id}")
            return jsonify({'success': False, 'error': 'Current password is required.'}), 400
            
        if not new_password:
            logger.warning(f"Empty new password in change password attempt for user {current_user.id}")
            return jsonify({'success': False, 'error': 'New password is required.'}), 400
            
        if not confirm_password:
            logger.warning(f"Empty confirm password in change password attempt for user {current_user.id}")
            return jsonify({'success': False, 'error': 'Please confirm your new password.'}), 400
        
        if new_password != confirm_password:
            logger.warning(f"New passwords do not match in change password attempt for user {current_user.id}")
            return jsonify({'success': False, 'error': 'New passwords do not match.'}), 400
        
        if len(new_password) < 8:
            logger.warning(f"New password too short in change password attempt for user {current_user.id}")
            return jsonify({'success': False, 'error': 'New password must be at least 8 characters long.'}), 400

        # Fetch user data
        user_data = users_collection.find_one({'_id': ObjectId(current_user.id)})
        if not user_data:
            logger.error(f"User not found during password change: {current_user.id}")
            return jsonify({'success': False, 'error': 'User not found.'}), 404

        # Verify current password
        logger.info(f"Verifying password for user {current_user.id}")
        if not 'password' in user_data:
            logger.error(f"User has no password hash in database: {current_user.id}")
            return jsonify({'success': False, 'error': 'Account configuration error. Please contact support.'}), 500
        
        try:
            password_match = check_password_hash(user_data['password'], current_password)
            logger.info(f"Password check result: {password_match}")
            
            if not password_match:
                logger.warning(f"Incorrect current password supplied for user {current_user.id}")
                return jsonify({'success': False, 'error': 'Incorrect current password. Please try again.'}), 403
        except Exception as e:
            logger.error(f"Password hash verification error: {e}")
            return jsonify({'success': False, 'error': 'Error verifying password. Please try again.'}), 500
        
        # Hash new password
        try:
            new_hashed_password = generate_password_hash(new_password)
        except Exception as e:
            logger.error(f"Error generating password hash: {e}")
            return jsonify({'success': False, 'error': 'Error processing new password.'}), 500
        
        # Update password in database
        try:
            result = users_collection.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$set': {'password': new_hashed_password}}
            )
            
            if result.modified_count == 1:
                logger.info(f"Password updated successfully for user {current_user.id}")
                return jsonify({'success': True, 'message': 'Password updated successfully!'})
            else:
                # Even if modified_count is 0, it might be because the new hash is identical to the old one
                # Let's check if the document was matched at least
                if result.matched_count == 1:
                    logger.warning(f"Password update reported 0 modified for user {current_user.id}, but document was matched")
                    return jsonify({'success': True, 'message': 'Password updated successfully!'})
                else:
                    logger.error(f"Password update failed for user {current_user.id} - document not found during update")
                    return jsonify({'success': False, 'error': 'Failed to update password in database.'}), 500
        except OperationFailure as e:
            logger.error(f"Database operation error updating password for user {current_user.id}: {e}")
            return jsonify({'success': False, 'error': 'Database error occurred while updating password.'}), 500

    except OperationFailure as e:
        logger.error(f"Database error changing password for user {current_user.id}: {e}")
        return jsonify({'success': False, 'error': 'Database error occurred.'}), 500
    except Exception as e:
        logger.error(f"Error changing password for user {current_user.id}: {e}, {type(e)}")
        return jsonify({'success': False, 'error': 'An unexpected error occurred.'}), 500

# Add route for handling hyphenated URL
@app.route('/change-password', methods=['POST'])
@login_required
def change_password_hyphen():
    """Route to handle requests with hyphen instead of underscore"""
    return change_password()

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    # Check if database connection is available
    if folders_collection is None:
        logger.error("folders_collection is None in create_folder route")
        return jsonify({'success': False, 'error': 'Database connection error'}), 500
        
    try:
        logger.info(f"Create folder request received - Form data: {request.form}")
        
        folder_name = request.form.get('folder_name')
        parent_id = request.form.get('parent_id', 'root')
        
        logger.info(f"Creating folder: {folder_name} with parent_id: {parent_id}")
        
        # Validate folder name
        if not folder_name or len(folder_name.strip()) == 0:
            logger.warning("Folder name is empty")
            return jsonify({'success': False, 'error': 'Folder name cannot be empty'}), 400
        
        # Create safe folder name
        safe_folder_name = secure_filename(folder_name.strip())
        logger.info(f"Safe folder name: {safe_folder_name}")
        
        # Get user ID
        user_id_str = str(current_user.id)
        
        # Check if folder with same name already exists in the same parent
        existing_folder = folders_collection.find_one({
            'user_id': user_id_str,
            'parent_id': parent_id,
            'name': {'$regex': f'^{safe_folder_name}$', '$options': 'i'}  # Case insensitive match
        })
        
        if existing_folder:
            logger.warning(f"Folder with name {safe_folder_name} already exists")
            return jsonify({'success': False, 'error': 'A folder with this name already exists'}), 400
        
        # Generate folder path
        if parent_id == 'root':
            folder_path = safe_folder_name
        else:
            # Get parent folder info
            parent_folder = folders_collection.find_one({
                '_id': ObjectId(parent_id),
                'user_id': user_id_str
            })
            
            if not parent_folder:
                logger.error(f"Parent folder not found: {parent_id}")
                return jsonify({'success': False, 'error': 'Parent folder not found or access denied'}), 404
                
            folder_path = os.path.join(parent_folder['path'], safe_folder_name)
        
        # Normalize path for DB storage (always use forward slashes)
        normalized_path = folder_path.replace('\\', '/')
        logger.info(f"Folder path: {folder_path}, normalized: {normalized_path}")
        
        # Create physical folder
        physical_path = os.path.join(app.config['UPLOAD_FOLDER'], user_id_str, folder_path)
        logger.info(f"Physical path: {physical_path}")
        
        try:
            os.makedirs(physical_path, exist_ok=True)
            logger.info(f"Created folder for user {user_id_str} at: {physical_path}")
        except Exception as e:
            logger.error(f"Error creating physical folder: {e}")
            return jsonify({'success': False, 'error': f'Error creating folder: {str(e)}'}), 500
        
        # Store in database
        folder_data = {
            'user_id': user_id_str,
            'name': safe_folder_name,
            'path': normalized_path,
            'parent_id': parent_id,
            'created_at': datetime.datetime.now()
        }
        logger.info(f"Inserting folder data: {folder_data}")
        
        folder_id = folders_collection.insert_one(folder_data).inserted_id
        logger.info(f"Folder created with ID: {folder_id}")
        
        return jsonify({
            'success': True,
            'folder_id': str(folder_id),
            'name': safe_folder_name
        })
    except OperationFailure as e:
        logger.error(f"Database operation error creating folder: {e}")
        return jsonify({'success': False, 'error': 'Database error occurred'}), 500
    except Exception as e:
        logger.error(f"Error creating folder: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/rename_folder/<folder_id>', methods=['PUT'])
@login_required
def rename_folder(folder_id):
    # Check if database connection is available
    if folders_collection is None:
        return jsonify({'success': False, 'error': 'Database connection error'}), 500
        
    try:
        # Get user ID
        user_id_str = str(current_user.id)
        
        # Check if folder exists and belongs to user
        folder = folders_collection.find_one({
            '_id': ObjectId(folder_id),
            'user_id': user_id_str
        })
        
        if not folder:
            return jsonify({'success': False, 'error': 'Folder not found or access denied'}), 404
            
        # Get new name
        data = request.get_json()
        new_name = data.get('new_name', '').strip()
        
        # Validate new name
        if not new_name:
            return jsonify({'success': False, 'error': 'New folder name cannot be empty'}), 400
            
        safe_new_name = secure_filename(new_name)
        
        # Check if folder with same name already exists in the same parent
        existing_folder = folders_collection.find_one({
            '_id': {'$ne': ObjectId(folder_id)},  # Not the current folder
            'user_id': user_id_str,
            'parent_id': folder['parent_id'],
            'name': {'$regex': f'^{safe_new_name}$', '$options': 'i'}  # Case insensitive match
        })
        
        if existing_folder:
            return jsonify({'success': False, 'error': 'A folder with this name already exists'}), 400
        
        # Generate new path
        old_path = folder['path']
        old_name = folder['name']
        
        # Calculate new path (replacing just the folder name at the end)
        if folder['parent_id'] == 'root':
            new_path = safe_new_name
        else:
            parent_path = os.path.dirname(old_path)
            new_path = os.path.join(parent_path, safe_new_name) if parent_path else safe_new_name
        
        # Normalize paths for DB storage
        new_path = new_path.replace('\\', '/')
        
        # Rename physical folder
        old_physical_path = os.path.join(app.config['UPLOAD_FOLDER'], user_id_str, old_path)
        new_physical_path = os.path.join(app.config['UPLOAD_FOLDER'], user_id_str, new_path)
        
        try:
            if os.path.exists(old_physical_path):
                os.rename(old_physical_path, new_physical_path)
                logger.info(f"Renamed folder from {old_physical_path} to {new_physical_path}")
        except Exception as e:
            logger.error(f"Error renaming physical folder: {e}")
            return jsonify({'success': False, 'error': f'Error renaming folder: {str(e)}'}), 500
        
        # Update folder in database
        folders_collection.update_one(
            {'_id': ObjectId(folder_id)},
            {'$set': {'name': safe_new_name, 'path': new_path}}
        )
        
        # Update all child folders paths
        child_folders = folders_collection.find({
            'user_id': user_id_str,
            'path': {'$regex': f'^{old_path}/'}  # Starts with old path
        })
        
        for child in child_folders:
            child_path = child['path']
            updated_path = child_path.replace(old_path, new_path, 1)
            folders_collection.update_one(
                {'_id': child['_id']},
                {'$set': {'path': updated_path}}
            )
        
        # Update file paths for files in this folder and subfolders
        files_to_update = files_collection.find({
            'user_id': user_id_str,
            'filepath': {'$regex': f'^{app.config["UPLOAD_FOLDER"]}/{user_id_str}/{old_path}'}
        })
        
        for file in files_to_update:
            old_file_path = file['filepath']
            new_file_path = old_file_path.replace(
                f'{app.config["UPLOAD_FOLDER"]}/{user_id_str}/{old_path}',
                f'{app.config["UPLOAD_FOLDER"]}/{user_id_str}/{new_path}',
                1
            )
            
            files_collection.update_one(
                {'_id': file['_id']},
                {'$set': {'filepath': new_file_path}}
            )
        
        return jsonify({
            'success': True,
            'name': safe_new_name
        })
    except OperationFailure as e:
        logger.error(f"Database operation error renaming folder: {e}")
        return jsonify({'success': False, 'error': 'Database error occurred'}), 500
    except Exception as e:
        logger.error(f"Error renaming folder: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/delete_folder/<folder_id>', methods=['DELETE'])
@login_required
def delete_folder(folder_id):
    """
    Delete a folder, its subfolders, and all files within.
    """
    # Check if database connection is available
    if folders_collection is None or files_collection is None:
        return jsonify({'success': False, 'error': 'Database connection error'}), 500
        
    try:
        # Get user ID
        user_id_str = str(current_user.id)
        
        # Check if folder exists and belongs to user
        folder = folders_collection.find_one({
            '_id': ObjectId(folder_id),
            'user_id': user_id_str
        })
        
        if not folder:
            logger.error(f"Folder not found or access denied: {folder_id}")
            return jsonify({'success': False, 'error': 'Folder not found or access denied'}), 404
            
        # Get folder path and name
        folder_path = folder['path']
        folder_name = folder.get('name', 'unknown')
        
        logger.info(f"Starting deletion of folder: {folder_name} (ID: {folder_id}, Path: {folder_path})")
        
        # Function to collect all folder IDs to delete (including nested folders)
        def get_all_folder_ids(parent_id, user_id):
            result = [parent_id]  # Include the parent folder itself
            
            # Find all direct children
            children = folders_collection.find({
                'parent_id': parent_id,
                'user_id': user_id
            })
            
            # For each child, recursively get its children
            for child in children:
                child_id = str(child['_id'])
                result.extend(get_all_folder_ids(child_id, user_id))
                
            return result
            
        # Get all folder IDs to delete (including nested folders)
        all_folder_ids = get_all_folder_ids(folder_id, user_id_str)
        logger.info(f"Found {len(all_folder_ids)} folders to delete (including nested folders)")
        
        # Convert string IDs to ObjectId for MongoDB queries
        folder_object_ids = [ObjectId(fid) for fid in all_folder_ids]
        
        # Delete all files in these folders
        files_deleted = files_collection.delete_many({
            'user_id': user_id_str,
            'folder_id': {'$in': all_folder_ids}
        })
        logger.info(f"Deleted {files_deleted.deleted_count} files from folders")
        
        # Delete all folder records from the database
        folders_deleted = folders_collection.delete_many({
            '_id': {'$in': folder_object_ids},
            'user_id': user_id_str
        })
        logger.info(f"Deleted {folders_deleted.deleted_count} folder records from database")
        
        # Delete the physical folder and its contents
        physical_path = os.path.join(app.config['UPLOAD_FOLDER'], user_id_str, folder_path)
        try:
            if os.path.exists(physical_path):
                logger.info(f"Deleting physical folder at {physical_path}")
                shutil.rmtree(physical_path, ignore_errors=True)
                logger.info(f"Successfully deleted physical folder: {physical_path}")
            else:
                logger.warning(f"Physical folder not found at {physical_path}")
        except Exception as e:
            logger.error(f"Error deleting physical folder {physical_path}: {e}")
            # Continue since we've already deleted from database
        
        # Force MongoDB to synchronize by running a count operation
        root_folders_count = folders_collection.count_documents({
            'user_id': user_id_str,
            'parent_id': 'root'
        })
        logger.info(f"Verified remaining root folders count: {root_folders_count}")
        
        return jsonify({
            'success': True, 
            'message': 'Folder and contents deleted successfully',
            'deleted_folders': folders_deleted.deleted_count,
            'deleted_files': files_deleted.deleted_count
        })
    except Exception as e:
        logger.error(f"Error deleting folder {folder_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/move_item', methods=['POST'])
@login_required
def move_item():
    # Check if database connection is available
    if folders_collection is None or files_collection is None:
        return jsonify({'success': False, 'error': 'Database connection error'}), 500
        
    try:
        data = request.get_json()
        item_id = data.get('item_id')
        item_type = data.get('item_type')  # 'file' or 'folder'
        target_folder_id = data.get('target_folder_id', 'root')
        
        # Validate input
        if not item_id or not item_type:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
            
        if item_type not in ['file', 'folder']:
            return jsonify({'success': False, 'error': 'Invalid item type'}), 400
        
        # Get user ID
        user_id_str = str(current_user.id)
        
        # Verify target folder exists (or is root)
        if target_folder_id != 'root':
            target_folder = folders_collection.find_one({
                '_id': ObjectId(target_folder_id),
                'user_id': user_id_str
            })
            
            if not target_folder:
                return jsonify({'success': False, 'error': 'Target folder not found or access denied'}), 404
                
            target_path = target_folder['path']
        else:
            target_path = ''
            
        # Handle based on item type
        if item_type == 'file':
            # Get file info
            file = files_collection.find_one({
                '_id': ObjectId(item_id),
                'user_id': user_id_str
            })
            
            if not file:
                return jsonify({'success': False, 'error': 'File not found or access denied'}), 404
            
            # Get current folder ID
            current_folder_id = file.get('folder_id', 'root')
            
            # Don't move if target is the same as current
            if current_folder_id == target_folder_id:
                return jsonify({'success': True, 'message': 'File already in target folder'}), 200
            
            # Move physical file
            old_filepath = file['filepath']
            filename = file['filename']
            
            # Build new filepath
            if target_folder_id == 'root':
                new_relative_path = filename
            else:
                new_relative_path = os.path.join(target_path, filename)
                
            # Normalize for storage
            new_relative_path = new_relative_path.replace('\\', '/')
            
            new_filepath = os.path.join(
                app.config['UPLOAD_FOLDER'], 
                user_id_str,
                new_relative_path
            )
            
            # Handle potential name collisions
            base_name, extension = os.path.splitext(new_filepath)
            counter = 1
            while os.path.exists(new_filepath):
                new_filepath = f"{base_name}_{counter}{extension}"
                counter += 1
                
            # Get final filename
            new_filename = os.path.basename(new_filepath)
            
            # Move the physical file
            try:
                # Ensure target directory exists
                os.makedirs(os.path.dirname(new_filepath), exist_ok=True)
                
                # Move file
                old_filepath_os = old_filepath.replace('/', os.path.sep)
                if os.path.exists(old_filepath_os):
                    os.rename(old_filepath_os, new_filepath)
                    logger.info(f"Moved file from {old_filepath_os} to {new_filepath}")
                else:
                    logger.warning(f"Source file {old_filepath_os} not found for moving")
                    return jsonify({'success': False, 'error': 'Source file not found on server'}), 404
            except Exception as e:
                logger.error(f"Error moving physical file: {e}")
                return jsonify({'success': False, 'error': f'Error moving file: {str(e)}'}), 500
            
            # Update database
            normalized_filepath = new_filepath.replace('\\', '/')
            files_collection.update_one(
                {'_id': ObjectId(item_id)},
                {'$set': {
                    'folder_id': target_folder_id,
                    'filepath': normalized_filepath,
                    'filename': new_filename
                }}
            )
            
            return jsonify({
                'success': True,
                'message': 'File moved successfully',
                'new_filename': new_filename
            })
            
        elif item_type == 'folder':
            # Get folder info
            folder = folders_collection.find_one({
                '_id': ObjectId(item_id),
                'user_id': user_id_str
            })
            
            if not folder:
                return jsonify({'success': False, 'error': 'Folder not found or access denied'}), 404
            
            # Get current parent ID
            current_parent_id = folder['parent_id']
            
            # Don't move if target is the same as current
            if current_parent_id == target_folder_id:
                return jsonify({'success': True, 'message': 'Folder already in target location'}), 200
                
            # Check for circular dependency (can't move folder into its own subfolder)
            if target_folder_id != 'root':
                parent_check_id = target_folder_id
                while parent_check_id != 'root':
                    parent_check = folders_collection.find_one({
                        '_id': ObjectId(parent_check_id),
                        'user_id': user_id_str
                    })
                    
                    if not parent_check:
                        break
                    
                    if str(parent_check['_id']) == item_id:
                        return jsonify({'success': False, 'error': 'Cannot move a folder into its own subfolder'}), 400
                        
                    parent_check_id = parent_check['parent_id']
            
            # Move folder
            old_path = folder['path']
            folder_name = folder['name']
            
            # Build new path
            if target_folder_id == 'root':
                new_path = folder_name
            else:
                new_path = os.path.join(target_path, folder_name)
                
            # Normalize for storage
            new_path = new_path.replace('\\', '/')
            
            # Check for name collision in target folder
            existing_folder = folders_collection.find_one({
                '_id': {'$ne': ObjectId(item_id)},
                'user_id': user_id_str,
                'parent_id': target_folder_id,
                'name': {'$regex': f'^{folder_name}$', '$options': 'i'}
            })
            
            if existing_folder:
                # Add numbering to folder name
                counter = 1
                base_name = folder_name
                new_folder_name = f"{base_name}_{counter}"
                
                while folders_collection.find_one({
                    'user_id': user_id_str,
                    'parent_id': target_folder_id,
                    'name': {'$regex': f'^{new_folder_name}$', '$options': 'i'}
                }):
                    counter += 1
                    new_folder_name = f"{base_name}_{counter}"
                    
                folder_name = new_folder_name
                
                # Update new_path with the new folder name
                if target_folder_id == 'root':
                    new_path = folder_name
                else:
                    new_path = os.path.join(os.path.dirname(new_path), folder_name).replace('\\', '/')
            
            # Move physical folder
            old_physical_path = os.path.join(app.config['UPLOAD_FOLDER'], user_id_str, old_path)
            new_physical_path = os.path.join(app.config['UPLOAD_FOLDER'], user_id_str, new_path)
            
            try:
                # Ensure parent directory exists
                os.makedirs(os.path.dirname(new_physical_path), exist_ok=True)
                
                # Move directory
                if os.path.exists(old_physical_path):
                    os.rename(old_physical_path, new_physical_path)
                    logger.info(f"Moved folder from {old_physical_path} to {new_physical_path}")
                else:
                    # Create new directory if old doesn't exist
                    os.makedirs(new_physical_path, exist_ok=True)
                    logger.warning(f"Source folder {old_physical_path} not found, created new folder at {new_physical_path}")
            except Exception as e:
                logger.error(f"Error moving physical folder: {e}")
                return jsonify({'success': False, 'error': f'Error moving folder: {str(e)}'}), 500
            
            # Update folder in database
            folders_collection.update_one(
                {'_id': ObjectId(item_id)},
                {'$set': {
                    'parent_id': target_folder_id,
                    'path': new_path,
                    'name': folder_name
                }}
            )
            
            # Update all child folders paths
            child_folders = folders_collection.find({
                'user_id': user_id_str,
                'path': {'$regex': f'^{old_path}/'}  # Starts with old path
            })
            
            for child in child_folders:
                child_path = child['path']
                updated_path = child_path.replace(old_path, new_path, 1)
                folders_collection.update_one(
                    {'_id': child['_id']},
                    {'$set': {'path': updated_path}}
                )
            
            # Update file paths for files in this folder and subfolders
            files_to_update = files_collection.find({
                'user_id': user_id_str,
                'filepath': {'$regex': f'^{app.config["UPLOAD_FOLDER"]}/{user_id_str}/{old_path}'}
            })
            
            for file in files_to_update:
                old_file_path = file['filepath']
                new_file_path = old_file_path.replace(
                    f'{app.config["UPLOAD_FOLDER"]}/{user_id_str}/{old_path}',
                    f'{app.config["UPLOAD_FOLDER"]}/{user_id_str}/{new_path}',
                    1
                )
                
                files_collection.update_one(
                    {'_id': file['_id']},
                    {'$set': {'filepath': new_file_path}}
                )
            
            return jsonify({
                'success': True,
                'message': 'Folder moved successfully',
                'new_name': folder_name
            })
    except OperationFailure as e:
        logger.error(f"Database operation error moving item: {e}")
        return jsonify({'success': False, 'error': 'Database error occurred'}), 500
    except Exception as e:
        logger.error(f"Error moving item: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_folders', methods=['GET'])
@login_required
def get_folders():
    # Check if database connection is available
    if folders_collection is None:
        logger.error("folders_collection is None in get_folders route")
        return jsonify({'success': False, 'error': 'Database connection error'}), 500
        
    try:
        user_id_str = str(current_user.id)
        current_folder_id = request.args.get('exclude_folder_id')
        logger.info(f"Get folders request - User: {user_id_str}, Exclude folder: {current_folder_id}")
        
        # Get all user folders
        all_folders = list(folders_collection.find({'user_id': user_id_str}))
        logger.info(f"Found {len(all_folders)} folders for user {user_id_str}")
        
        # Convert ObjectIDs to strings for JSON serialization
        for folder in all_folders:
            folder['id'] = str(folder['_id'])
            del folder['_id']
        
        # Build folder hierarchy
        root_folders = []
        folder_map = {}
        
        # First, create a map of all folders
        for folder in all_folders:
            folder_id = folder['id']
            
            # Skip the folder we want to exclude (and its children)
            if current_folder_id and folder_id == current_folder_id:
                continue
                
            folder['children'] = []
            folder_map[folder_id] = folder
        
        # Then, build the hierarchy
        for folder in all_folders:
            folder_id = folder['id']
            
            # Skip the folder we want to exclude (and its children)
            if current_folder_id and folder_id == current_folder_id:
                continue
                
            if folder['parent_id'] == 'root':
                root_folders.append(folder)
            elif folder['parent_id'] in folder_map:
                folder_map[folder['parent_id']]['children'].append(folder)
        
        logger.info(f"Returning {len(root_folders)} root folders")
        return jsonify({
            'success': True,
            'folders': root_folders
        })
    except OperationFailure as e:
        logger.error(f"Database operation error getting folders: {e}")
        return jsonify({'success': False, 'error': 'Database error occurred'}), 500
    except Exception as e:
        logger.error(f"Error getting folders: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/diagnose/folders', methods=['GET'])
@login_required
def diagnose_folders():
    """Diagnostic route to check folder data and repair inconsistencies"""
    if folders_collection is None:
        return "Database connection error", 500
        
    try:
        user_id_str = str(current_user.id)
        
        # Get all folders for this user
        all_folders = list(folders_collection.find({'user_id': user_id_str}))
        
        # Create a results summary
        results = {
            'total_folders': len(all_folders),
            'root_folders': 0,
            'folders_repaired': 0,
            'invalid_folders': [],
            'details': []
        }
        
        # Check each folder
        for folder in all_folders:
            folder_id = str(folder['_id'])
            folder_name = folder.get('name', 'unnamed')
            folder_path = folder.get('path', '')
            parent_id = folder.get('parent_id', 'unknown')
            
            folder_info = {
                'id': folder_id,
                'name': folder_name,
                'path': folder_path,
                'parent_id': parent_id,
                'issues': []
            }
            
            # Count root folders
            if parent_id == 'root':
                results['root_folders'] += 1
            
            # Check if parent exists (skip root)
            if parent_id != 'root':
                parent_exists = folders_collection.count_documents({
                    '_id': ObjectId(parent_id),
                    'user_id': user_id_str
                })
                
                if not parent_exists:
                    folder_info['issues'].append(f"Parent folder {parent_id} does not exist")
                    results['invalid_folders'].append(folder_id)
                    
                    # Fix: Move to root
                    folders_collection.update_one(
                        {'_id': folder['_id']},
                        {'$set': {'parent_id': 'root'}}
                    )
                    folder_info['issues'].append("FIXED: Moved to root folder")
                    results['folders_repaired'] += 1
            
            # Check physical folder
            physical_path = os.path.join(app.config['UPLOAD_FOLDER'], user_id_str, folder_path)
            folder_info['physical_path'] = physical_path
            folder_info['physical_exists'] = os.path.exists(physical_path)
            
            if folder_info['issues'] or not folder_info['physical_exists']:
                results['details'].append(folder_info)
        
        # Return diagnostic info
        return render_template(
            'diagnose_folders.html',
            results=results,
            folders=all_folders
        )
    except Exception as e:
        logger.error(f"Error in diagnose_folders: {e}")
        return f"Error: {str(e)}", 500

@app.route('/diagnose/force_cleanup', methods=['POST'])
@login_required
def force_folder_cleanup():
    """Force cleanup of problematic folders"""
    if folders_collection is None:
        return jsonify({'success': False, 'error': 'Database connection error'}), 500
        
    try:
        user_id_str = str(current_user.id)
        
        # 1. Find all folders where the parent doesn't exist (except root)
        invalid_folders = []
        valid_folder_ids = {'root'} # root is always valid
        
        # Find all folder IDs
        all_folders = list(folders_collection.find({'user_id': user_id_str}))
        for folder in all_folders:
            valid_folder_ids.add(str(folder['_id']))
        
        # Check for invalid parent references
        for folder in all_folders:
            folder_id = str(folder['_id'])
            parent_id = folder.get('parent_id')
            
            if parent_id != 'root' and parent_id not in valid_folder_ids:
                invalid_folders.append(folder_id)
                logger.warning(f"Found invalid folder: {folder_id}, parent {parent_id} doesn't exist")
        
        # 2. Direct bulk delete of invalid folders from database
        if invalid_folders:
            invalid_folder_ids = [ObjectId(fid) for fid in invalid_folders]
            invalid_delete_result = folders_collection.delete_many({
                '_id': {'$in': invalid_folder_ids},
                'user_id': user_id_str
            })
            logger.info(f"Deleted {invalid_delete_result.deleted_count} invalid folders")
            
            # Also delete any files in these folders
            invalid_files_result = files_collection.delete_many({
                'folder_id': {'$in': invalid_folders},
                'user_id': user_id_str
            })
            logger.info(f"Deleted {invalid_files_result.deleted_count} files from invalid folders")
        
        # 3. Force index rebuild in MongoDB (simulate)
        root_folders_count = folders_collection.count_documents({
            'user_id': user_id_str,
            'parent_id': 'root'
        })
        logger.info(f"Index rebuild complete. Root folders count: {root_folders_count}")
        
        # 4. Clean up physical folder structure
        upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], user_id_str)
        if os.path.exists(upload_dir):
            # Find all valid folder paths 
            valid_paths = set()
            for folder in folders_collection.find({'user_id': user_id_str}):
                if 'path' in folder:
                    valid_paths.add(folder['path'])
            
            # Clean up any physical folders that don't have DB entries
            physical_cleanup_count = 0
            try:
                for root, dirs, files in os.walk(upload_dir, topdown=False):
                    # Skip the user root directory
                    if root == upload_dir:
                        continue
                    
                    # Get relative path from upload dir
                    rel_path = os.path.relpath(root, upload_dir)
                    normalized_path = rel_path.replace('\\', '/')
                    
                    # If this normalized path is not in valid_paths, remove it
                    if normalized_path not in valid_paths:
                        try:
                            logger.info(f"Removing invalid physical folder: {root}")
                            shutil.rmtree(root, ignore_errors=True)
                            physical_cleanup_count += 1
                        except Exception as e:
                            logger.error(f"Error removing physical folder {root}: {e}")
            except Exception as e:
                logger.error(f"Error during physical folder cleanup: {e}")
        
        return jsonify({
            'success': True, 
            'invalid_folders_removed': len(invalid_folders),
            'physical_folders_cleaned': physical_cleanup_count,
            'message': 'Folder system cleanup completed successfully'
        })
    except Exception as e:
        logger.error(f"Error in force_folder_cleanup: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    # Verify MongoDB connection before starting the app
    if client is None:
        logger.warning("Starting app without database connection - some features will be unavailable")
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)