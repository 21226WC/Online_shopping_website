from idlelib import query
from itertools import product

from flask import Flask, render_template, request, redirect, session
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


def logged_in():
    if session.get("ID") == None:
        print("Not logged in")
        return False
    else:
        print("Logged in")
        print("true")
        return True




@app.route('/')
def render_homepage():
    return render_template('home.html',log_in=logged_in())
@app.route('/admin')
def render_admin():
    con = connect_database('DATABASE')
    query = "SELECT title, description, price, image_id, name, listing_id FROM user_listings INNER JOIN signup_users ON user_listings.ID=signup_users.ID"
    cur = con.cursor()
    cur.execute(query)
    admin_listings = cur.fetchall()
    con.close()
    return render_template('admin.html',admin_listings=admin_listings, log_in=logged_in())

@app.route('/listings')
def render_listing():
    con = connect_database('DATABASE')
    query = "SELECT title, description, price, image_id, name, listing_id FROM user_listings INNER JOIN signup_users ON user_listings.ID=signup_users.ID"
    cur = con.cursor()
    cur.execute(query)
    listings = cur.fetchall()
    con.close()
    return render_template('listings.html', listings_info=listings, log_in=logged_in())


@app.route('/my_listings')
def render_my_listings():
   con = connect_database('DATABASE')
   query = "SELECT title, description, price, image_id, name, listing_id from user_listings INNER JOIN signup_users ON user_listings.ID=signup_users.ID where user_listings.ID = ?"
   cur = con.cursor()
   cur.execute(query, (session['ID'],))
   my_listings = cur.fetchall()
   con.close()
   return render_template('My_listings.html',my_listings=my_listings, log_in=logged_in())


@app.route('/create_listing', methods=['GET', 'POST'])
def create_listing():
    if request.method == 'POST':
        title = request.form['title'].title().strip()
        description = request.form['description'].strip()
        price = request.form['price'].strip()
        ID = session["ID"]
        con = connect_database('DATABASE')
        query_insert = "INSERT INTO user_listings (title, description, price, ID) VALUES (?, ?, ? ,?)"
        cur = con.cursor()
        cur.execute(query_insert, (title, description, price, ID))
        con.commit()
        con.close()
    return render_template('creating_listing.html', log_in=logged_in())





@app.route('/login', methods=['GET', 'POST'])
def render_listings():
     if request.method == 'POST':
         email = request.form['user_email'].lower().strip()
         password = request.form['user_password'].strip()

         query = "SELECT * FROM signup_users WHERE email = ?"
         con = connect_database(DATABASE)
         cur = con.cursor()
         cur.execute(query, (email,))
         user_info = cur.fetchall()
         cur.close()
         try:
             ID = user_info[0][0]
             name = user_info[0][1]
             email = user_info[0][2]
             login_password = user_info[0][3]
         except IndexError:
             return redirect('/login?error=email_or_password_incorrect')
         if not bcrypt.check_password_hash(login_password, password):
             return redirect('/login?error=email_or_password_incorrect')
         else:
             session ['ID'] = ID
             session ['email'] = email
             session ['name'] = name
             print(session)
             return redirect('/listings')


     return render_template('login.html',log_in=logged_in())






@app.route('/signup', methods=['GET', 'POST'])
def render_signup():
    if request.method == 'POST':
        username = request.form['uname'].title().strip()
        password = request.form['upassword'].strip()
        confirmpassword = request.form['cpassword'].strip()
        email = request.form['uemail'].lower().strip()
        admin_code = request.form['admin_code']


        if password != confirmpassword:
            return redirect('/signup?error=passwords_dont_match')
        if len(password) < 8:
            return redirect('/signup?error=password_too_short')
        if len(username) > 50:
            return redirect('/signup?error=user_name_too_long')
        if len(email) > 50:
            return redirect('/signup?error=email_too_long')
        if len(password) > 30:
            return redirect('/signup?error=password_too_long')

        is_admin=1 if admin_code == '1992' else 0

        hashed_password = bcrypt.generate_password_hash(password)

        if is_admin == 1:
            con = connect_database('DATABASE')
            query_insert = "INSERT INTO signup_users (name, email, password, admin) VALUES (?, ?, ?, ?)"
            cur = con.cursor()
            cur.execute(query_insert, (username, email, hashed_password, is_admin))
            con.commit()
            con.close()

        else:
            con = connect_database('DATABASE')
            query_insert = "INSERT INTO signup_users (name, email, password, admin) VALUES (?, ?, ?)"
            cur = con.cursor()
            cur.execute(query_insert, (username, email, hashed_password))
            con.commit()
            con.close()
        return redirect("/login")
    return render_template('signup.html')



@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect('/?message=successfully logged out')


@app.route('/delete_listing', methods=['POST'])
def delete_listing():
    listing_id = request.form.get('listing_id')

    if not listing_id:
        return redirect('/my_listings')
    else:
        con = connect_database('DATABASE')
        cur = con.cursor()
        cur.execute("DELETE FROM user_listings WHERE listing_id = ?", (listing_id,))
        con.commit()
        con.close()

    return redirect('/my_listings')


if __name__ == '__main__':
    app.run()
