from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_FILE_SIZE
)

# User database (in production, use a real database)
users = {
    'student@example.com': {
        'role': 'student',
        'reg': '123',
        'password': generate_password_hash('student123')
    },
    'staff@example.com': {
        'role': 'staff',
        'reg': '456',
        'password': generate_password_hash('staff456')
    }
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    if 'email' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    if 'email' in session:
        return redirect(url_for('dashboard'))
    
    email = request.form.get('email', '').lower()
    reg = request.form.get('regNumber', '')
    role = request.form.get('role', '')
    password = request.form.get('password', '')
    
    user = users.get(email)
    
    if user and user['reg'] == reg and user['role'] == role and check_password_hash(user['password'], password):
        session['email'] = email
        session['role'] = role
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
    
    flash('Invalid credentials', 'error')
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('home'))
    
    files = []
    if session['role'] == 'staff':
        try:
            files = os.listdir(app.config['UPLOAD_FOLDER'])
        except FileNotFoundError:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    return render_template('dashboard.html', 
                         role=session['role'],
                         files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'email' not in session or session['role'] != 'staff':
        flash('Staff access required', 'error')
        return redirect(url_for('dashboard'))
    
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash(f'File {filename} uploaded successfully!', 'success')
    else:
        flash('Invalid file type', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)