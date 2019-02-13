from flask import Flask, render_template, redirect, request, session, flash, url_for
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re

app = Flask('__name__')
app.secret_key = "developement_info"
bcrypt = Bcrypt(app)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 
NAME_REGEX = re.compile(r'^[a-zA-Z ]')

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/get_log_in_form")
def get_log_in_form():
    # to check the user is on session or not
    if 'email' in session:
        return redirect("/home")

    return render_template("login.html", email='')

@app.route("/login", methods=['POST'])
def login():
    # to check the user is on session or not
    if 'email' in session:
        return redirect("/home")

    # Check if email and password is given or not
    errorCounter = 0
    email = request.form['email']
    password = request.form['password']
    if len(email) == 0:
        errorCounter += 1
        flash("Email is required", 'email')
    if len(password) == 0:
        errorCounter += 1
        flash("Password is required", 'password')
    if errorCounter > 0:
        return render_template("login.html", email=email)

    # Check if email and password exist in the database
    mysql = connectToMySQL('flask_pets')
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = {
        "email": request.form['email']
    }
    user = mysql.query_db(query, data)
    if user and bcrypt.check_password_hash(user[0]['password'], request.form['password']):
        session['email'] = email
        session['userid'] = user[0]['id']
        return redirect("/home")
    else:
        flash("Incorrect information", 'general')
        return render_template("login.html", email=email)

@app.route("/get_user_registration_form")
def get_user_registration_form():
    # to check the user is on session or not
    if 'email' in session:
        return redirect("/home")

    return render_template("sign_up_form.html", fname='', lname='', email='')

@app.route("/register_user", methods=['POST'])
def register_user():
    # to check the user is on session or not
    if 'email' in session:
        return redirect("/home")

    fname = request.form['first_name']
    lname = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    # validate the information given
    errorCounter = 0

    if len(fname) == 0:
        errorCounter += 1
        flash("First name is required", 'first_name')
    else:
        if not NAME_REGEX.match(fname) or len(fname) < 2:
            errorCounter += 1
            flash("Invalid first name content and must contain only letter", 'first_name')
    if len(lname) == 0:
        errorCounter += 1
        flash("Last name is required", 'last_name')
    else:
        if not NAME_REGEX.match(lname) or len(lname) < 2:
            errorCounter += 1
            flash("Invalid last name content and must contain only letter", 'last_name')
    if len(email) == 0:
        errorCounter += 1
        flash("Email is required", 'email')
    else:
        if not EMAIL_REGEX.match(email):
            errorCounter += 1
            flash("Email is not valid", 'email')
    if len(password) == 0:
        errorCounter += 1
        flash("Password is required", 'password')
    if len(confirm_password) == 0:
        errorCounter += 1
        flash("Confirm passowrd is required", 'confirm_password')
    else:
        if password != confirm_password:
            errorCounter += 1
            flash("Password don't match", 'password')

    if errorCounter > 0:
        return render_template("sign_up_form.html", fname=fname, lname=lname, email=email)
    else:
        # check whether the email already exist or not
        mysql = connectToMySQL('flask_pets')
        query = "SELECT * FROM users WHERE email = %(email)s;"
        data = {
            "email":email
        }
        user = mysql.query_db(query, data)
        if user:
            flash("Email already register", 'email')
            return render_template("sign_up_form.html", fname=fname, lname=lname, email=email)

        # insert the information to database
        hash_password = bcrypt.generate_password_hash(password)
        mysql = connectToMySQL('flask_pets')
        query = "INSERT INTO users(first_name, last_name, email, password, create_at) VALUES(%(fname)s, %(lname)s, %(email)s, %(hash_password)s, NOW())"
        data = {
            "fname": fname,
            "lname": lname,
            "email": email,
            "hash_password": hash_password
        }
        userid = mysql.query_db(query, data)
        
        session['email'] = email
        session['userid'] = userid

        return redirect("/home")

@app.route("/home")
def home():
    # to check the user is on session or not
    if 'email' in session:
        return render_template("home.html")
    else:
        return redirect("/")

@app.route("/logout")
def logout():
    session.pop('email')
    session.pop('userid')
    return redirect("/")

if __name__ == '__main__':
    app.run(debug=True)