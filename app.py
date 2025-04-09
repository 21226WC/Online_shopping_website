from flask import Flask, render_template, request, redirect
import sqlite3
from sqlite3 import Error
app = Flask(__name__)

def connect_database(db_file):
    """
    creates a connection to the database
    :param: db_file
    :return: conn
    """
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error:
        print ("an error has occurred when connecting to database")
@app.route('/')
def render_homepage():
    return render_template('home.html')


@app.route('/menu')
def render_menu():
    return render_template('menu.html')


@app.route('/signup', methods=['GET', 'POST'])
def render_signup():
    if request.method == 'POST':
        username = request.form['uname'].title().strip()
        password = request.form['upassword'].strip()
        confirmpassword = request.form['cpassword'].strip()
        email = request.form['uemail'].lower().strip()

        if password != confirmpassword:
            return redirect("signup?error=Passwords_do_not_match")
        if len(password) < 8:
            return redirect("signup?error=Password_too_short")


    return render_template('signup.html')


@app.route('/signup_sell', methods=['GET', 'POST'])
def render_signup_sell():
    if request.method == 'POST':
        username = request.form['uname'].title().strip()
        password = request.form['upassword'].strip()
        confirmpassword = request.form['cpassword'].strip()
        email = request.form['uemail'].lower().strip()

        if password != confirmpassword:
            return redirect("signup?error=Passwords_do_not_match")
        if len(password) < 8:
            return redirect("signup?error=Password_too_short")


    return render_template('signup_sell.html')


@app.route('/login', methods=['GET', 'POST'])
def render_login():
    return render_template('login.html')








if __name__ == '__main__':
    app.run()