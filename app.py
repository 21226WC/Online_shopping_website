from idlelib import query
from itertools import product

from flask import Flask, render_template, request, redirect
import sqlite3
from sqlite3 import Error
from flask_bcrypt import bcrypt, Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "alsdkhf"


DATABASE = "/Users/aaronzang/FlaskProject4/DATABASE"

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


@app.route('/listings')
def render_listings():
   con = connect_database('DATABASE')
   query = "SELECT * FROM user_listings ORDER BY listing_id"
   temp_query = "SELECT * FROM sqlite_master"
   cur = con.cursor()
   cur.execute(query)
   listings = cur.fetchall()
   print(listings)
   con.close()
   return render_template('listings.html', listings_info=listings)



@app.route('/contact')
def render_contact():
    return render_template('contact.html')



@app.route('/login', methods=['GET', 'POST'])
def render_login():
     if request.method == 'POST':
         email = request.form['user_email'].lower().strip()
         password = request.form['user_password'].strip()

         query = "SELECT * FROM signup_users WHERE email = ?"
         con = connect_database(DATABASE)
         cur = con.cursor()
         cur.execute(query, (email,))
         user_info = cur.fetchall()
         print (user_info)
         cur.close()
         try:
             ID = user_info[0][0]
             name = user_info[0][1]
             email = user_info[0][2]
             password = user_info[0][3]
         except IndexError:
             return redirect('/login?error=email_or_password_incorrect')
         if bcrypt.check_password_hash(user_info['password'], password):

     return render_template('login.html')




@app.route('/login_sell', methods=['GET', 'POST'])
def render_login_sell():
    return render_template('login_sell.html')




@app.route('/signup', methods=['GET', 'POST'])
def render_signup():
    if request.method == 'POST':
        username = request.form['uname'].title().strip()
        password = request.form['upassword'].strip()
        confirmpassword = request.form['cpassword'].strip()
        email = request.form['uemail'].lower().strip()

        if password != confirmpassword:
            return redirect("Passwords_do_not_match")
        if len(password) < 8:
            return redirect("Password_too_short")

        hashed_password = bcrypt.generate_password_hash(password)

        con = connect_database('DATABASE')
        query_insert = "INSERT INTO signup_users (name, email, password) VALUES (?, ?, ?)"
        cur = con.cursor()
        cur.execute(query_insert, (username, email, hashed_password))
        con.commit()
        con.close()
        return render_template('login.html')


    return render_template('signup.html')


@app.route('/signup_sell', methods=['GET', 'POST'])
def render_signup_sell():
    if request.method == 'POST':
        username = request.form['uname'].title().strip()
        password = request.form['upassword'].strip()
        confirm_password = request.form['cpassword'].strip()
        email = request.form['uemail'].lower().strip()

        if password != confirmpassword:
            return redirect("signup?error=Passwords_do_not_match")
        if len(password) < 8:
            return redirect("signup?error=Password_too_short")


    return render_template('signup_sell.html')



if __name__ == '__main__':
    app.run()