from flask import Flask, request, redirect, url_for, flash, render_template_string
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SECURITY_PASSWORD_SALT'] = 'email-verification-salt'

serializer = URLSafeTimedSerializer(app.secret_key)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return '''
        <h2>Welcome to the User Auth System</h2>
        <a href="/register">Register</a> | <a href="/login">Login</a>
    '''

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password)
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, is_verified) VALUES (?, ?, ?, ?)',
                (username, email, hashed_password, 0)
            )
            conn.commit()
            
            token = serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
            verification_link = url_for('verify_email', token=token, _external=True)
            
            print("\n" + "="*70)
            print(f"📧 [SIMULATED EMAIL TO: {email}]")
            print(f"Click or copy this link to verify your account:\n{verification_link}")
            print("="*70 + "\n")
            
            flash('Registration successful! Check your terminal for the simulated verification link.', 'success')
            return redirect(url_for('login'))
            
        except sqlite3.IntegrityError:
            flash('This email address is already registered!', 'danger')
        finally:
            conn.close()
            
    return '''
        <h2>Register</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            <ul>
              {% for category, message in messages %}
                <li style="color: red;">{{ message }}</li>
              {% endfor %}
            </ul>
          {% endif %}
        {% endwith %}
        <form method="POST">
            Username: <input type="text" name="username" required><br><br>
            Email: <input type="email" name="email" required><br><br>
            Password: <input type="password" name="password" required><br><br>
            <input type="submit" value="Register">
        </form>
        <br><a href="/">Back to Home</a>
    '''

# Email Verification Route
@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except Exception as e:
        flash('The verification link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    
    if user:
        if user['is_verified'] == 1:
            flash('Account is already verified! Please log in.', 'info')
        else:
            conn.execute('UPDATE users SET is_verified = 1 WHERE email = ?', (email,))
            conn.commit()
            flash('Email verified successfully! You can now log in.', 'success')
    else:
        flash('User not found.', 'danger')
        
    conn.close()
    return redirect(url_for('login'))

# Login Route with Attempt Tracking & Verification Guard
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        cursor = conn.cursor()
        
        if user:
            # Check 1: Is user verified?
            if user['is_verified'] == 0:
                cursor.execute('INSERT INTO login_logs (user_id, status) VALUES (?, ?)', (user['id'], 'FAILED_UNVERIFIED'))
                conn.commit()
                conn.close()
                flash('Please verify your email address before logging in.', 'danger')
                return redirect(url_for('login'))
            
            # Check 2: Password check
            if check_password_hash(user['password_hash'], password):
                cursor.execute('INSERT INTO login_logs (user_id, status) VALUES (?, ?)', (user['id'], 'SUCCESS'))
                conn.commit()
                conn.close()
                flash(f"Welcome back, {user['username']}!", 'success')
                return redirect(url_for('dashboard'))
            else:
                cursor.execute('INSERT INTO login_logs (user_id, status) VALUES (?, ?)', (user['id'], 'FAILED_WRONG_PASSWORD'))
                conn.commit()
                conn.close()
                flash('Invalid email or password.', 'danger')
        else:
            conn.close()
            flash('Invalid email or password.', 'danger')
            
    return '''
        <h2>Login</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            <ul>
              {% for category, message in messages %}
                <li style="color: blue;">{{ message }}</li>
              {% endfor %}
            </ul>
          {% endif %}
        {% endwith %}
        <form method="POST">
            Email: <input type="email" name="email" required><br><br>
            Password: <input type="password" name="password" required><br><br>
            <input type="submit" value="Login">
        </form>
        <br><a href="/">Back to Home</a>
    '''

# Dashboard after successful login
@app.route('/dashboard')
def dashboard():
    return '''
        <h2>🎉 Welcome to your Dashboard!</h2>
        <p>You have successfully logged in.</p>
        <br>
        <a href="/logs">📊 View Login Attempt Logs (Lab Requirement)</a> | 
        <a href="/login">Log Out</a>
    '''

# Route to view login attempt logs (Lab Requirement)
@app.route('/logs')
def view_logs():
    conn = get_db_connection()
    logs = conn.execute('''
        SELECT login_logs.id, users.username, users.email, login_logs.attempt_time, login_logs.status 
        FROM login_logs 
        JOIN users ON login_logs.user_id = users.id
        ORDER BY login_logs.attempt_time DESC
    ''').fetchall()
    conn.close()
    
    log_html = "<h2>📊 Login Attempt Audit Trail</h2><table border='1' cellpadding='8'><tr><th>ID</th><th>Username</th><th>Email</th><th>Time</th><th>Status</th></tr>"
    for log in logs:
        log_html += f"<tr><td>{log['id']}</td><td>{log['username']}</td><td>{log['email']}</td><td>{log['attempt_time']}</td><td>{log['status']}</td></tr>"
    log_html += "</table><br><a href='/dashboard'>Back to Dashboard</a>"
    return log_html

if __name__ == '__main__':
    app.run(debug=True)
