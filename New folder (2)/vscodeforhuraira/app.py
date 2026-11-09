
import os
import sqlite3
from functools import wraps
from html import escape

from flask import (
    Flask, request, redirect, url_for,
    flash, render_template_string, session
)

from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from markupsafe import Markup


# ==========================================
# FLASK CONFIGURATION
# ==========================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY", "development-secret-key-change-this"
)

app.config["SECURITY_PASSWORD_SALT"] = "email-verification-salt"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

serializer = URLSafeTimedSerializer(app.secret_key)

DATABASE = "database.db"


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db_connection()

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)

    conn.commit()
    conn.close()


# Initialize database automatically
init_db()


# ==========================================
# LOGIN REQUIRED DECORATOR
# ==========================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            flash("Please log in to access this page.", "danger")
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


# ==========================================
# BASE HTML TEMPLATE
# ==========================================

BASE_HTML = """
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Auth System Lab</title>

    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-slate-50 text-slate-800 min-h-screen flex flex-col">

    <!-- Navbar -->

    <nav class="bg-gray-900 text-white shadow-md">

        <div class="max-w-7xl mx-auto px-4 py-3 flex justify-between items-center">

            <a href="/" class="text-xl font-bold tracking-wide">
                🔐 Auth System Lab
            </a>

            <div class="space-x-3">

                {% if session.get('user_id') %}

                    <a href="/dashboard"
                       class="px-4 py-2 rounded-lg text-sm hover:bg-gray-800">
                        Dashboard
                    </a>

                    <a href="/logout"
                       class="px-4 py-2 rounded-lg text-sm bg-red-600 hover:bg-red-700">
                        Logout
                    </a>

                {% else %}

                    <a href="/login"
                       class="px-4 py-2 rounded-lg text-sm border border-gray-700 hover:bg-gray-800">
                        Login
                    </a>

                    <a href="/register"
                       class="px-4 py-2 rounded-lg text-sm bg-indigo-600 hover:bg-indigo-700">
                        Register
                    </a>

                {% endif %}

            </div>
        </div>

    </nav>


    <!-- Main Container -->

    <main class="flex-grow max-w-7xl w-full mx-auto px-4 py-8">

        {% with messages = get_flashed_messages(with_categories=true) %}

            {% if messages %}

                <div class="space-y-3 mb-6">

                    {% for category, message in messages %}

                        {% set colors = {
                            'danger': 'bg-red-50 text-red-700 border-red-200',
                            'success': 'bg-emerald-50 text-emerald-700 border-emerald-200',
                            'info': 'bg-blue-50 text-blue-700 border-blue-200'
                        } %}

                        <div class="p-4 rounded-xl text-sm font-medium border
                            {{ colors.get(category, colors['info']) }}">

                            {{ message }}

                        </div>

                    {% endfor %}

                </div>

            {% endif %}

        {% endwith %}


        {{ content | safe }}

    </main>


    <!-- Footer -->

    <footer class="bg-white border-t border-slate-200 text-center py-4 text-sm text-slate-500">

        Software Engineering Lab Project &bull; Flask & Tailwind

    </footer>

</body>
</html>
"""


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def index():

    content = """
    <div class="max-w-2xl mx-auto mt-16 text-center bg-white p-8 rounded-2xl shadow-sm border border-slate-200">

        <h1 class="text-3xl font-extrabold text-slate-900 mb-4">
            User Registration & Login System
        </h1>

        <p class="text-slate-600 mb-8">
            Secure authentication with email token verification,
            password hashing, and login audit logs.
        </p>

        <div class="flex justify-center gap-4">

            <a href="/register"
               class="px-6 py-3 bg-indigo-600 text-white font-semibold rounded-xl hover:bg-indigo-700">
                Get Started
            </a>

            <a href="/login"
               class="px-6 py-3 bg-slate-100 text-slate-700 font-semibold rounded-xl hover:bg-slate-200">
                Log In
            </a>

        </div>

    </div>
    """

    return render_template_string(BASE_HTML, content=Markup(content))


# ==========================================
# USER REGISTRATION
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")

        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")

        else:

            hashed_password = generate_password_hash(password)

            conn = get_db_connection()

            try:

                conn.execute(
                    """
                    INSERT INTO users
                    (username, email, password_hash, is_verified)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, email, hashed_password, 0)
                )

                conn.commit()

                # Generate email verification token

                token = serializer.dumps(
                    email,
                    salt=app.config["SECURITY_PASSWORD_SALT"]
                )

                verification_link = url_for(
                    "verify_email",
                    token=token,
                    _external=True
                )

                # Simulated email

                print("\n" + "=" * 70)
                print(f"EMAIL TO: {email}")
                print("Click the following link to verify your account:")
                print(verification_link)
                print("=" * 70 + "\n")

                flash(
                    "Registration successful! Check your terminal for the verification link.",
                    "success"
                )

                return redirect(url_for("login"))

            except sqlite3.IntegrityError:

                flash(
                    "Username or email is already registered!",
                    "danger"
                )

            finally:
                conn.close()


    content = """
    <div class="max-w-md mx-auto bg-white p-8 rounded-2xl shadow-sm border border-slate-200 mt-6">

        <h2 class="text-2xl font-bold text-slate-900 mb-6 text-center">
            Create an Account
        </h2>

        <form method="POST" class="space-y-4">

            <div>
                <label class="block text-sm font-medium mb-1">
                    Username
                </label>

                <input type="text"
                       name="username"
                       required
                       class="w-full px-4 py-2 border rounded-lg">
            </div>

            <div>
                <label class="block text-sm font-medium mb-1">
                    Email Address
                </label>

                <input type="email"
                       name="email"
                       required
                       class="w-full px-4 py-2 border rounded-lg">
            </div>

            <div>
                <label class="block text-sm font-medium mb-1">
                    Password
                </label>

                <input type="password"
                       name="password"
                       minlength="8"
                       required
                       class="w-full px-4 py-2 border rounded-lg">
            </div>

            <button type="submit"
                    class="w-full py-3 bg-indigo-600 text-white font-semibold rounded-xl hover:bg-indigo-700">
                Register
            </button>

        </form>

    </div>
    """

    return render_template_string(BASE_HTML, content=Markup(content))


# ==========================================
# EMAIL VERIFICATION
# ==========================================

@app.route("/verify/<token>")
def verify_email(token):

    try:

        email = serializer.loads(
            token,
            salt=app.config["SECURITY_PASSWORD_SALT"],
            max_age=3600
        )

    except Exception:

        flash(
            "The verification link is invalid or has expired.",
            "danger"
        )

        return redirect(url_for("login"))


    conn = get_db_connection()

    user = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if user:

        if user["is_verified"] == 1:

            flash(
                "Account is already verified! Please log in.",
                "info"
            )

        else:

            conn.execute(
                "UPDATE users SET is_verified = 1 WHERE email = ?",
                (email,)
            )

            conn.commit()

            flash(
                "Email verified successfully! You can now log in.",
                "success"
            )

    else:

        flash("User not found.", "danger")

    conn.close()

    return redirect(url_for("login"))


# ==========================================
# USER LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db_connection()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if user:

            cursor = conn.cursor()

            if not check_password_hash(user["password_hash"], password):

                cursor.execute(
                    """
                    INSERT INTO login_logs (user_id, status)
                    VALUES (?, ?)
                    """,
                    (user["id"], "FAILED_WRONG_PASSWORD")
                )

                conn.commit()
                conn.close()

                flash("Invalid email or password.", "danger")

            elif user["is_verified"] == 0:

                cursor.execute(
                    """
                    INSERT INTO login_logs (user_id, status)
                    VALUES (?, ?)
                    """,
                    (user["id"], "FAILED_UNVERIFIED")
                )

                conn.commit()
                conn.close()

                flash(
                    "Please verify your email address before logging in.",
                    "danger"
                )

            else:

                cursor.execute(
                    """
                    INSERT INTO login_logs (user_id, status)
                    VALUES (?, ?)
                    """,
                    (user["id"], "SUCCESS")
                )

                conn.commit()

                session.clear()
                session["user_id"] = user["id"]

                username = user["username"]

                conn.close()

                flash(
                    f"Welcome back, {username}!",
                    "success"
                )

                return redirect(url_for("dashboard"))

        else:

            conn.close()

            flash("Invalid email or password.", "danger")


    content = """
    <div class="max-w-md mx-auto bg-white p-8 rounded-2xl shadow-sm border border-slate-200 mt-6">

        <h2 class="text-2xl font-bold text-slate-900 mb-6 text-center">
            User Login
        </h2>

        <form method="POST" class="space-y-4">

            <div>
                <label class="block text-sm font-medium mb-1">
                    Email Address
                </label>

                <input type="email"
                       name="email"
                       required
                       class="w-full px-4 py-2 border rounded-lg">
            </div>

            <div>
                <label class="block text-sm font-medium mb-1">
                    Password
                </label>

                <input type="password"
                       name="password"
                       required
                       class="w-full px-4 py-2 border rounded-lg">
            </div>

            <button type="submit"
                    class="w-full py-3 bg-gray-900 text-white font-semibold rounded-xl hover:bg-gray-800">
                Log In
            </button>

        </form>

    </div>
    """

    return render_template_string(BASE_HTML, content=Markup(content))


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db_connection()

    user = conn.execute(
        "SELECT username FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    conn.close()

    if user is None:
        session.clear()
        flash("Please log in again.", "danger")
        return redirect(url_for("login"))

    safe_username = escape(user["username"])

    content = f"""
    <div class="max-w-xl mx-auto bg-white p-8 rounded-2xl shadow-sm border border-slate-200 mt-10 text-center">

        <h2 class="text-3xl font-bold text-slate-900 mb-2">
            🎉 Dashboard
        </h2>

        <p class="text-slate-600 mb-2">
            Welcome, {safe_username}!
        </p>

        <p class="text-slate-600 mb-6">
            You have successfully authenticated into your secure account.
        </p>

        <div class="flex justify-center gap-4">

            <a href="/logs"
               class="px-5 py-2.5 bg-indigo-600 text-white font-medium rounded-xl hover:bg-indigo-700">
                📊 View Login Logs
            </a>

            <form action="/logout" method="POST">

                <button type="submit"
                        class="px-5 py-2.5 bg-red-600 text-white font-medium rounded-xl hover:bg-red-700">
                    Log Out
                </button>

            </form>

        </div>

    </div>
    """

    return render_template_string(BASE_HTML, content=Markup(content))


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout", methods=["POST"])
@login_required
def logout():

    session.clear()

    flash("You have successfully logged out.", "success")

    return redirect(url_for("login"))


# ==========================================
# LOGIN AUDIT LOGS
# ==========================================

@app.route("/logs")
@login_required
def view_logs():

    conn = get_db_connection()

    logs = conn.execute(
        """
        SELECT
            login_logs.id,
            users.username,
            users.email,
            login_logs.attempt_time,
            login_logs.status

        FROM login_logs

        JOIN users
        ON login_logs.user_id = users.id

        ORDER BY login_logs.attempt_time DESC
        """
    ).fetchall()

    conn.close()

    rows = ""

    for log in logs:

        if log["status"] == "SUCCESS":

            badge = """
            <span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-emerald-100 text-emerald-800">
                SUCCESS
            </span>
            """

        elif log["status"] == "FAILED_UNVERIFIED":

            badge = """
            <span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-amber-100 text-amber-800">
                UNVERIFIED
            </span>
            """

        else:

            badge = """
            <span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800">
                FAILED
            </span>
            """

        rows += f"""
        <tr class="hover:bg-slate-50 border-b border-slate-100">

            <td class="px-6 py-4 text-sm text-slate-600">
                {log['id']}
            </td>

            <td class="px-6 py-4 text-sm font-medium text-slate-900">
                {escape(log['username'])}
            </td>

            <td class="px-6 py-4 text-sm text-slate-600">
                {escape(log['email'])}
            </td>

            <td class="px-6 py-4 text-sm text-slate-500">
                {escape(log['attempt_time'])}
            </td>

            <td class="px-6 py-4 text-sm">
                {badge}
            </td>

        </tr>
        """

    if not rows:

        rows = """
        <tr>
            <td colspan="5" class="px-6 py-6 text-center text-slate-500">
                No login attempts recorded yet.
            </td>
        </tr>
        """

    content = f"""
    <div class="max-w-5xl mx-auto bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden mt-6">

        <div class="bg-slate-900 text-white px-6 py-4 flex justify-between items-center">

            <h3 class="font-bold text-lg">
                📊 Login Attempt Audit Trail
            </h3>

            <a href="/dashboard"
               class="text-sm px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded-lg">
                Back to Dashboard
            </a>

        </div>

        <div class="overflow-x-auto">

            <table class="min-w-full divide-y divide-slate-200">

                <thead class="bg-slate-50 text-left text-xs font-semibold text-slate-500 uppercase">

                    <tr>
                        <th class="px-6 py-3">ID</th>
                        <th class="px-6 py-3">Username</th>
                        <th class="px-6 py-3">Email</th>
                        <th class="px-6 py-3">Timestamp</th>
                        <th class="px-6 py-3">Status</th>
                    </tr>

                </thead>

                <tbody class="divide-y divide-slate-200 bg-white">

                    {rows}

                </tbody>

            </table>

        </div>

    </div>
    """

    return render_template_string(BASE_HTML, content=Markup(content))


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(debug=True)
