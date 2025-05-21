from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "alsdkhf"  # Used to incrypt the password to be inserted into database

DATABASE = "/Users/aaronzang/FlaskProject4/DATABASE"

# Function to create a connection to the SQLite database
# Returns a connection or an error
def connect_database(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error:
        print("An error has occurred when connecting to database")

# Function to check whether a user is currently logged in
# Returns True if session contains a user ID, False otherwise
def logged_in():
    if session.get("ID") == None:  # If session does not contain 'ID', user is not logged in
        print("Not logged in")
        return False
    else:
        print("Logged in")
        return True

# Function to determine if the logged-in user is an administrator
# Returns True if session indicates admin status (1), False otherwise
def is_admin():
    if session.get("admin") == 1:  # Check if the session value for 'admin' is set to 1
        print("is admin")
        return True
    else:
        print("not admin")
        return False

# Route for the homepage
@app.route('/')
def render_homepage():
    return render_template('home.html', log_in=logged_in())  # Render homepage and pass login status

# Route for the admin dashboard that displays all listings from all users
@app.route('/admin')
def render_admin():
    con = connect_database('DATABASE')
    # Query to join user_listings with signup_users to retrieve listing and user details
    query = """
    SELECT title, description, price, image_id, name, listing_id 
    FROM user_listings 
    INNER JOIN signup_users ON user_listings.ID=signup_users.ID
    """
    cur = con.cursor()
    cur.execute(query)  # Execute the query
    admin_listings = cur.fetchall()  # Retrieve all matching records
    con.close()
    return render_template('admin.html', admin_listings=admin_listings, log_in=logged_in(), admin=is_admin())

# Route to display all listings to any user
@app.route('/listings')
def render_listing():
    con = connect_database('DATABASE')
    # Same query as admin, but shown to regular users
    query = """
    SELECT title, description, price, image_id, name, listing_id 
    FROM user_listings 
    INNER JOIN signup_users ON user_listings.ID=signup_users.ID
    """
    cur = con.cursor()
    cur.execute(query)
    listings = cur.fetchall()
    con.close()
    return render_template('listings.html', listings_info=listings, log_in=logged_in(), admin=is_admin())

# Route to display listings that belong to the currently logged-in user
@app.route('/my_listings')
def render_my_listings():
    con = connect_database('DATABASE')
    # Query to only retrieve listings where user ID matches the logged-in user
    query = """
    SELECT title, description, price, image_id, name, listing_id 
    FROM user_listings 
    INNER JOIN signup_users ON user_listings.ID=signup_users.ID 
    WHERE user_listings.ID = ?
    """
    cur = con.cursor()
    cur.execute(query, (session['ID'],))  # Pass current user's ID into query
    my_listings = cur.fetchall()
    con.close()
    return render_template('my_listings.html', my_listings=my_listings, log_in=logged_in(), admin=is_admin())

# Route to view a specific listing selected by the user
@app.route('/view_listing', methods=['POST'])
def view_listing():
    listing_id = request.form.get('view_listing_id')  # Get the listing ID from the form POST data

    # Query to fetch detailed info about the selected listing, including seller's name
    query = """
    SELECT title, description, price, image_id, name
    FROM user_listings 
    INNER JOIN signup_users ON signup_users.ID = user_listings.ID
    WHERE listing_id = ?
    """
    con = connect_database('DATABASE')
    cur = con.cursor()
    cur.execute(query, (listing_id,))  # Use listing ID in WHERE clause to get one listing to display
    view_listings = cur.fetchone()
    con.close()
    return render_template('view_listing.html', view_listings=view_listings, log_in=logged_in(), admin=is_admin())

# Route to delete a listing created by the user
@app.route('/delete_listing', methods=['POST'])
def delete_listing():
    listing_id = request.form.get('listing_id')  # Get the listing ID

    if not listing_id:  # If no listing ID provided, redirect back
        return redirect('/my_listings')
    else:
        con = connect_database('DATABASE')
        cur = con.cursor()
        # SQL DELETE query to remove the listing with the specified ID
        cur.execute("DELETE FROM user_listings WHERE listing_id = ?", (listing_id,))
        con.commit()
        con.close()
    return redirect('/my_listings')

# Route for admin to delete any listing
@app.route('/delete_listing_admin', methods=['POST'])
def delete_listing_admin():
    listing_id = request.form.get('listing_id')

    if not listing_id:
        return redirect('/admin')
    else:
        con = connect_database('DATABASE')
        cur = con.cursor()
        # Same deletion logic as above but accessible by admin
        cur.execute("DELETE FROM user_listings WHERE listing_id = ?", (listing_id,))
        con.commit()
        con.close()
    return redirect('/admin')

# Route for creating a new listing
@app.route('/create_listing', methods=['GET', 'POST'])
def create_listing():
    if request.method == 'POST':  # If user submitted the form
        title = request.form['title'].title().strip()
        description = request.form['description'].strip()
        price = request.form['price'].strip()
        ID = session["ID"]

        con = connect_database('DATABASE')
        # Insert query to save the new listing in the database
        query_insert = "INSERT INTO user_listings (title, description, price, ID) VALUES (?, ?, ?, ?)"
        cur = con.cursor()
        cur.execute(query_insert, (title, description, price, ID))
        con.commit()
        con.close()
        return redirect('/my_listings')
    return render_template('creating_listing.html', log_in=logged_in(), admin=is_admin())


@app.route('/trade', methods=['GET', 'POST'])
def trade():
    if not logged_in():
        return redirect('/login')

    con = connect_database(DATABASE)
    cur = con.cursor()

    if request.method == 'POST':
        listing_id = request.form.get('listing_id')
        user_id = session['ID']

        if listing_id:
            # Insert trade request with status 'pending'
            query = "INSERT INTO trades (listing_id, user_id, status) VALUES (?, ?, ?)"
            cur.execute(query, (listing_id, user_id, 'pending'))
            con.commit()
            con.close()
            return redirect('/trade')

    # Show all trade requests for this user
    query = """
        SELECT trades.trade_id, user_listings.title, trades.status
        FROM trades
        INNER JOIN user_listings ON trades.listing_id = user_listings.listing_id
        WHERE trades.user_id = ?
    """
    cur.execute(query, (session['ID'],))
    trade_requests = cur.fetchall()
    con.close()

    return render_template('trade.html', trade_requests=trade_requests, log_in=logged_in(), admin=is_admin())

@app.route('/confirm_trade', methods=['GET', 'POST'])
def confirm_trade():





# Route to handle user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['user_email'].lower().strip()
        password = request.form['user_password'].strip()

        # Query to find user by email
        query = "SELECT * FROM signup_users WHERE email = ?"
        con = connect_database(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_info = cur.fetchall()
        cur.close()

        try:
            # Extract user info from query result
            ID = user_info[0][0]
            name = user_info[0][1]
            email = user_info[0][2]
            login_password = user_info[0][3]
            admin = user_info[0][4]
        except IndexError:  # If user not found
            return redirect('/login?error=email_or_password_incorrect')

        # Check password with hashed version
        if not bcrypt.check_password_hash(login_password, password):
            return redirect('/login?error=email_or_password_incorrect')
        else:
            # Store login info in session
            session['ID'] = ID
            session['email'] = email
            session['name'] = name
            session['admin'] = admin
            print(session)
            return redirect('/listings')

    return render_template('login.html', log_in=logged_in(), admin=is_admin())

# Route to handle new user signup
@app.route('/signup', methods=['GET', 'POST'])
def render_signup():
    if request.method == 'POST':
        username = request.form['uname'].title().strip()
        password = request.form['upassword'].strip()
        confirmpassword = request.form['cpassword'].strip()
        email = request.form['uemail'].lower().strip()
        admin_code = request.form['admin_code']

        # Validation checks for user input
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
        if len(admin_code) > 4:
            return redirect('/signup?error=admin_code_error')

        # Determine admin status based on secret code
        is_admin = 1 if admin_code == '1992' else 0

        # Hash password using bcrypt
        hashed_password = bcrypt.generate_password_hash(password)

        con = connect_database('DATABASE')
        cur = con.cursor()

        if is_admin == 1:
            # Insert new admin user
            query_insert = "INSERT INTO signup_users (name, email, password, admin) VALUES (?, ?, ?, ?)"
            cur.execute(query_insert, (username, email, hashed_password, is_admin))
        else:
            # Insert new regular user
            query_insert = "INSERT INTO signup_users (name, email, password) VALUES (?, ?, ?)"
            cur.execute(query_insert, (username, email, hashed_password))

        con.commit()
        con.close()
        return redirect("/login")

    return render_template('signup.html')

# Route to log the user out and clear their session
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()  # Remove all session data
    return redirect('/?message=successfully logged out')

if __name__ == '__main__':
    app.run()
