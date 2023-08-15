import sqlite3
from flask import Flask, render_template, request, Response, jsonify, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import functools
app = Flask(__name__)

# Connect to the SQLite database
app.config['SECRET_KEY'] = 'your_secret_key_here'

def login_required(view_func):
    @functools.wraps(view_func)
    def wrapped_view(**kwargs):
        if 'user' not in session:
            return redirect(url_for('index'))
        return view_func(**kwargs)
    return wrapped_view

def get_db_connection():
    connection = sqlite3.connect('recaptchaTask.db')
    connection.row_factory = sqlite3.Row
    return connection

# Check if user credentials are valid
def is_valid_user(email, password):
    connection = get_db_connection()
    user = connection.execute('SELECT * FROM admins WHERE email = ?', (email,)).fetchone()
    connection.close()
    if user and check_password_hash(user['password'], password):
        return True
    return False

def verify_recaptcha(recaptcha_response):
    secret_key = "6LcYY4AnAAAAABCE-ok3rxURdZf35B8FHYMhTGTw"
    response = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data={"secret": secret_key, "response": recaptcha_response}
    )
    result = response.json()
    print(result)  # Add this line to print the response
    return result.get("success", False)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    recaptcha_response = request.form['g-recaptcha-response']

    # Verify reCAPTCHA
    if verify_recaptcha(recaptcha_response):
        if is_valid_user(email, password):
            session['user'] = email  # Store user's email in session
            return redirect(url_for('home'))
        else:
            return "Invalid credentials"
    else:
        return "reCAPTCHA verification failed"

@app.route('/home')
@login_required
def home():

    return render_template('index.html')
@app.route('/logout')
@login_required
def logout():
    session.pop('user', None)  # Remove 'user' from session
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()