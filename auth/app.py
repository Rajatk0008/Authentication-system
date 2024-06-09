from flask import Flask, request, render_template, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import pandas as pd
import os
from pathlib import Path
from functools import wraps
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
import phonenumbers

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key = 'supersecretkey'
db = SQLAlchemy(app)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

TWILIO_ACCOUNT_SID = 'ACf95057f46b34e253f07f3dfd79ca2e80'
TWILIO_AUTH_TOKEN = '56200104abfee776701a20fc5fe07542'
TWILIO_PHONE_NUMBER = '+17622487876'

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    phone_number = db.Column(db.String(15))
    is_admin = db.Column(db.Boolean, default=False)

    def __init__(self, email, password, name, phone_number, is_admin=False):
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.name = name
        self.phone_number = phone_number
        self.is_admin = is_admin

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            return redirect('/login')
        user = User.query.filter_by(email=session['email']).first()
        if not user or not user.is_admin:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/upload_page')
@admin_required
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phone_number = request.form['phone_number']
        is_admin = request.form.get('is_admin') == 'on'

        if not name or not email or not password or not phone_number:
            return 'Please fill out all fields'

        new_user = User(name=name, email=email, password=password, phone_number=phone_number, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['name'] = user.name
            session['email'] = user.email
            return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid user')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        if user:
            return render_template('dashboard.html', user=user, is_admin=user.is_admin)
    
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')

@app.route('/export_users')
@admin_required
def export_users():
    file_path = export_users_to_excel()
    return send_file(file_path, as_attachment=True, download_name='users.xlsx')

def export_users_to_excel():
    home = str(Path.home())
    downloads_dir = os.path.join(home, 'Downloads')
    os.makedirs(downloads_dir, exist_ok=True)

    users = User.query.all()
    user_data = [{
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "phone_number": user.phone_number
    } for user in users]

    df = pd.DataFrame(user_data)
    file_path = os.path.join(downloads_dir, 'users.xlsx')
    df.to_excel(file_path, index=False)
    return file_path

@app.route('/upload', methods=['POST'])
@admin_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file:
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)
        return redirect(url_for('send_sms', filename=file.filename))
    return render_template('index.html')

@app.route('/send_sms/<filename>', methods=['GET', 'POST'])
@admin_required
def send_sms(filename):
    if request.method == 'POST':
        message_body = request.form['message']
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        df = pd.read_excel(file_path)
        
        possible_columns = ['Phone Number', 'phone number', 'Phone number', 'phone Number']
        phone_column = None
        for col in possible_columns:
            if col in df.columns:
                phone_column = col
                break
        
        if phone_column is None:
            flash('No column named "Phone Number" found in the uploaded file.')
            return redirect(url_for('index'))
        
        numbers = df[phone_column].astype(str).dropna().tolist()

        default_region = 'IN'

        for number in numbers:
            try:
                sanitized_number = ''.join(filter(str.isdigit, number))
                parsed_number = phonenumbers.parse(sanitized_number, default_region)
                formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
                client.messages.create(
                    body=message_body,
                    from_=TWILIO_PHONE_NUMBER,
                    to=formatted_number
                )
            except phonenumbers.phonenumberutil.NumberParseException as e:
                flash(f'Failed to parse number {number}: {e}')
                continue
            except TwilioRestException as e:
                flash(f'Failed to send message to {number}: {e}')
                continue
        
        flash('Messages sent successfully!')
        return render_template('success.html')

    return render_template('send_sms.html', filename=filename)

if __name__ == '__main__':
    app.run(debug=True)
