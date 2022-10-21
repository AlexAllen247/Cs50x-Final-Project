from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from help import error, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Index"""
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return error("Error: must provide a username!", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return error("Error: must provide a password!", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return error("Error: invalid username and/or password!", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        # Get user's data from form
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Checking if there is already such a user
        userexist = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if userexist:
            return error("Error: A user with this username already exists!")

        # Checking for sending an empty field username
        if not username:
            return error("Error: No username entered!")

        # Checking for sending an empty field password
        if not password:
            return error("Error: No password entered!")

        # Checking for the error of re-entering the password
        if password != confirmation:
            return error("Error: passwords do not match!")

        # Password hashing
        hashcode = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hashcode)

        # In case of successful registration, we redirect to the main page
        return redirect("/")
    else:

        # Opening the registration form
        return render_template("register.html")

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Random Quote Generator"""
    return render_template("quote.html")

@app.route("/balls")
@login_required
def balls():
    """Balls"""
    return render_template("balls.html")

@app.route("/quiz")
@login_required
def quiz():
    """Quiz"""
    return render_template("quiz.html")

@app.route("/comments", methods=["GET", "POST"])
@login_required
def comments():
    if request.method == "POST":

        user_id = session["user_id"]

        # Add the user's comments into the database
        comments = request.form.get("comments")
        db.execute("INSERT INTO comments(id, comments) VALUES (?, ?)", user_id, comments)
        return redirect("/comments")

    else:

        # Display the entries in the database on comments.html
        display = db.execute("SELECT * FROM comments")
        return render_template("comments.html", comments=display)
