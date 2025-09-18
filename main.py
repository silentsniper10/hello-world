from flask import Flask, render_template, request, redirect, session, g, url_for, abort
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import logging

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change this!

# enable debug logging to terminal
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)


# ----------------------
# DATABASE SETUP
# ----------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "users.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    if "db" in g:
        g.db.close()


def init_db():
    """Create users table if it doesn't exist"""
    db = sqlite3.connect(DATABASE)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    db.commit()
    db.close()


# small logger to help debug 405s
@app.before_request
def log_request_info():
    app.logger.debug(f"Incoming request: {request.method} {request.path}")


# ----------------------
# ROUTES
# ----------------------
@app.route("/")
def home():
    # simple home - create an index.html in templates folder if you haven't already
    return render_template("index.html")


# SIGN UP (canonical route)
@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not (username and email and password):
            error = "Please fill in all fields."
            return render_template("signup.html", error=error)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, generate_password_hash(password)),
            )
            db.commit()

            # Fetch user back from DB
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

            # Auto login new user
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(url_for("home"))
        except sqlite3.IntegrityError:
            # username or email already in use
            error = "Account already exists, please log in."
    return render_template("signup.html", error=error)


# Provide the same page as /signup but also accept POSTs if someone posts to /signup.html
@app.route("/signup.html", methods=["GET", "POST"])
def signup_html():
    if request.method == "POST":
        # delegate to canonical signup() function (this will handle DB insertion and redirects)
        return signup()
    # for GET just render the same template
    return render_template("signup.html", error=None)


# LOGIN (canonical route)
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("home"))
        else:
            error = "Incorrect email address or password."
    return render_template("login.html", error=error)


# Accept POSTs to /login.html as well (delegate to login)
@app.route("/login.html", methods=["GET", "POST"])
def login_html():
    if request.method == "POST":
        return login()
    return render_template("login.html", error=None)


# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# Generic render for other pages like about.html etc. (GET only)
@app.route("/<page>.html", methods=["GET"])
def render_page(page):
    # keep this GET-only generic route for other static pages you might have
    template_name = f"{page}.html"
    try:
        return render_template(template_name)
    except Exception as e:
        app.logger.debug(f"Template not found: {template_name} -> {e}")
        abort(404)


# ----------------------
# RUN APP
# ----------------------
if __name__ == "__main__":
    init_db()  # ensure table exists before running
    app.run(debug=True, host="0.0.0.0", port=5100)
