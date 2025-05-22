from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
#importing things i will need


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "alsdkhf"  # Used to encrypt the password to be inserted into database

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
# Returns True if session contains a user ID
def logged_in():
    if session.get("ID") is None:  # If session does not contain 'ID', user is not logged in
        print("Not logged in")
        return False
    else:
        print("Logged in")
        return True

# Function to determine if the logged-in user is an administrator
# Returns True if session indicates admin status (1)
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
    return render_template('home.html',
                           log_in=logged_in())  # Render homepage and pass login status

# Route for the admin dashboard that displays all listings from all users
# returns rendering the admin html file and listing info to be displayed
@app.route('/admin')
def render_admin():
    con = connect_database(DATABASE)
    # Query to join user_listings with signup_users to retrieve listing and user details
    # this is to let any admin delete all listings where normal users can only delete their own
    query = """
    SELECT title, description, price, image_id, name, listing_id 
    FROM user_listings 
    INNER JOIN signup_users ON user_listings.ID=signup_users.ID
    """
    cur = con.cursor()
    cur.execute(query)
    admin_listings = cur.fetchall()  # Retrieve all rows from table listings
    con.close()
    return render_template('admin.html',
                           admin_listings=admin_listings,
                           log_in=logged_in(),
                           admin=is_admin())

# Route to display all listings to any user
@app.route('/listings')
def render_listing():
    con = connect_database(DATABASE)
    # Same query as admin, but shown to regular users
    # displays all listings for users to see but in the html it doesnt give them the option to delete them
    # only to trade returns the listing html and listing info
    query = """
    SELECT title, description, price, image_id, name, listing_id 
    FROM user_listings 
    INNER JOIN signup_users ON user_listings.ID=signup_users.ID
    """
    cur = con.cursor()
    cur.execute(query)
    listings = cur.fetchall()
    con.close()
    return render_template('listings.html',
                           listings_info=listings,
                           log_in=logged_in(),
                           admin=is_admin())

# Route to display listings that belong to the currently logged-in user
# this has basically the same code as the other rendering listings, but this shows your own listings
# so you can delete them
@app.route('/my_listings')
def render_my_listings():
    con = connect_database(DATABASE)
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
    return render_template('my_listings.html',
                           my_listings=my_listings,
                           log_in=logged_in(),
                           admin=is_admin())

# Route to view a specific listing selected by the user
# renders a page where only the clicked on listing is shown
# gives the info for a button and a drop down to trade where
# you select one of your own listings to trade for someone else's on the html file
# returns the view listing html file and info about the displayed listing aswell
# as your current listing info for the dropdown select
@app.route('/view_listing', methods=['POST'])
def view_listing():
    listing_id = request.form.get('view_listing_id')

    con = connect_database(DATABASE)
    cur = con.cursor()

    # Get the listing being viewed
    query = """
    SELECT title, description, price, image_id, name
    FROM user_listings
    INNER JOIN signup_users ON signup_users.ID = user_listings.ID
    WHERE listing_id = ?
    """
    cur.execute(query, (listing_id,))
    view_listings = cur.fetchone()

    # Get the current user's own listings to offer for drop down
    my_listings = []
    if logged_in():
        cur.execute("SELECT listing_id, title FROM user_listings WHERE ID = ?", (session['ID'],))
        my_listings = cur.fetchall()

    con.close()

    return render_template('view_listing.html',
                           view_listings=view_listings,
                           view_listing_id=listing_id,
                           my_listings=my_listings,
                           log_in=logged_in(),
                           admin=is_admin())

# Route to delete a listing created by the user
# a delete button is on the my listings html page where it calls this action and passes the listing id
# for it to be deleted
@app.route('/delete_listing', methods=['POST'])
def delete_listing():
    listing_id = request.form.get('listing_id')  # Get the listing ID

    if not listing_id:  # If no listing ID provided, redirect back
        return redirect('/my_listings')
    else:
        con = connect_database(DATABASE)
        cur = con.cursor()
        # SQL DELETE query to remove the listing with the specified ID
        cur.execute("DELETE FROM user_listings WHERE listing_id = ?", (listing_id,))
        con.commit()
        con.close()
    return redirect('/my_listings')

# Route for admin to delete any listing
# same code as before but can you be called from the admin page to delete any listing
@app.route('/delete_listing_admin', methods=['POST'])
def delete_listing_admin():
    listing_id = request.form.get('listing_id')

    if not listing_id:
        return redirect('/admin')
    else:
        con = connect_database(DATABASE)
        cur = con.cursor()
        cur.execute("DELETE FROM user_listings WHERE listing_id = ?", (listing_id,))
        con.commit()
        con.close()
    return redirect('/admin')

# Route for creating a new listing
# receives info from the html page and inserts it into user_listings table
@app.route('/create_listing', methods=['GET', 'POST'])
def create_listing():
    if request.method == 'POST':  # If user submitted the form info is passed
        title = request.form['title'].title().strip()
        description = request.form['description'].strip()
        price = request.form['price'].strip()
        id = session["ID"]

        con = connect_database(DATABASE)
        # Insert query to save the new listing in the database
        query_insert = "INSERT INTO user_listings (title, description, price, ID) VALUES (?, ?, ?, ?)"
        cur = con.cursor()
        cur.execute(query_insert, (title, description, price, id))
        con.commit()
        con.close()
        return redirect('/my_listings')
    return render_template('creating_listing.html',
                           log_in=logged_in(),
                           admin=is_admin())

# inserts a trade request into the trades table
@app.route('/trade', methods=['POST','GET'])
def trade():
    if not logged_in(): # makes sure user is logged in
        return redirect('/login')

    target_listing_id = request.form.get('target_listing_id') #gets the listing that the user wants
    offered_listing_id = request.form.get('my_listing_id') # gets the offered listing
    user_id = session['ID'] # gets the current user ID from session

    if target_listing_id and offered_listing_id:
        con = connect_database(DATABASE)
        cur = con.cursor()

        # Get the owner of the target listing
        cur.execute("SELECT ID FROM user_listings WHERE listing_id = ?", (target_listing_id,))
        target_owner = cur.fetchone()
        if not target_owner:
            return redirect('/listings')
        target_owner_id = target_owner[0]

        # insert info into trade table with the correct offered_user_id
        query = "INSERT INTO trades (listing_id, user_id, offered_listing_id, status, offered_user_id) VALUES (?, ?, ?, ?, ?)"
        cur.execute(query, (target_listing_id, user_id, offered_listing_id, 'pending', target_owner_id))
        con.commit()
        con.close()

    return redirect('/listings') # if full info is not provided, redirected back to all listings


@app.route('/approve_trade', methods=['POST'])
def approve_trade():

    target_listing_id = request.form.get('target_listing_id')  # listing being offered
    trade_id = request.form.get('trade_id')  # trade request ID
    listing_id = request.form.get('listing_id')  # your own listing being requested

    con = connect_database(DATABASE)
    cur = con.cursor()

    # Delete your listing and the trade record
    cur.execute("DELETE FROM user_listings WHERE listing_id = ?", (listing_id,))
    cur.execute("DELETE FROM trades WHERE trade_id = ?", (trade_id,))
    con.commit()

    # Fetch the email of the user who made the trade offer
    query = """
    SELECT email FROM signup_users 
    WHERE ID = (SELECT user_id FROM trades WHERE trade_id = ?)
    """
    cur.execute(query, (trade_id,))
    result = cur.fetchone()
    con.close()

    return render_template('approve_trade.html',
                           requester_email=result,
                           log_in=logged_in(),
                           admin=is_admin())


@app.route('/reject_trade', methods=['POST'])
def reject_trade():
    if not logged_in():
        return redirect('/login')

    trade_id = request.form.get('trade_id')  # get trade ID from form

    con = connect_database(DATABASE)
    cur = con.cursor()
    # Just delete the trade request
    cur.execute("DELETE FROM trades WHERE trade_id = ?", (trade_id,))
    con.commit()
    con.close()

    return render_template('reject_trade.html',
                           log_in=logged_in(),
                           admin=is_admin())



# looks if current user has any requests and gets info to be displayed
# it does this by first querying the database
@app.route('/trade_requests', methods=['GET'])
def trade_requests():
    if not logged_in():
        return redirect('/login')

    user_id = session['ID']

    con = connect_database(DATABASE)
    cur = con.cursor()
#Query to fetch all trade requests where the current user owns the requested listing
    query = """
    SELECT trade_id, listing_id, user_id, offered_listing_id, status
    FROM trades
    WHERE offered_user_id = ?
    """
    cur.execute(query, (user_id,))
    trade_requests_data = cur.fetchall()
#makes an empty list so it is easier to move data to the html file
    trade_details = []

    for trade in trade_requests_data:
        # Get the requested listing (owned by this user)
        cur.execute("""
        SELECT title, description, price, name 
        FROM user_listings 
        INNER JOIN signup_users ON signup_users.ID = user_listings.ID
        WHERE listing_id = ?""", (trade[1],))
        requested = cur.fetchone()

        # Get the offered listing (owned by someone else)
        cur.execute("""
        SELECT title, description, price, name 
        FROM user_listings 
        INNER JOIN signup_users ON signup_users.ID = user_listings.ID
        WHERE listing_id = ?""", (trade[3],))
        offered = cur.fetchone()
# places the information into the blank table with trade ID, the status and the two relevant listings
        trade_details.append([trade[0], trade[4], requested, offered])

    con.close()

    return render_template('trade_requests.html',
                           trade_requests=trade_details, # returns the list of info to be displayed on the html
                           log_in=logged_in(),
                           admin=is_admin())




# Route to handle user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['user_email'].lower().strip()
        password = request.form['user_password'].strip()
# takes the info form the form and makes sure that the email is lowercase and both dosent have a space after
        # Query to find user by email
        query = "SELECT * FROM signup_users WHERE email = ?"
        con = connect_database(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_info = cur.fetchall()
        cur.close()

        try:
            # compares the data given by the user to details from signup to verify that its the same account details
            ID = user_info[0][0]
            name = user_info[0][1]
            email = user_info[0][2]
            login_password = user_info[0][3]
            admin = user_info[0][4]
        except IndexError:  # If user not found
            return redirect('/login?error=email_or_password_incorrect')

        # Check the incrypted password to make sure they are the same
        if not bcrypt.check_password_hash(login_password, password):
            return redirect('/login?error=email_or_password_incorrect') #if any info doesnt match up, a error is given
        else:
            # Store login info in session
            session['ID'] = ID
            session['email'] = email
            session['name'] = name
            session['admin'] = admin
            print(session)
            return redirect('/listings') #redirects to listings if user successfully logs in

    return render_template('login.html',
                           log_in=logged_in(),
                           admin=is_admin())

# Route to handle new user signup
@app.route('/signup', methods=['GET', 'POST'])
def render_signup():
    if request.method == 'POST':
        username = request.form['uname'].title().strip()
        password = request.form['upassword'].strip()
        confirmpassword = request.form['cpassword'].strip()
        email = request.form['uemail'].lower().strip()
        admin_code = request.form['admin_code']
        # gets info from the signup form and stores them in a veriable

        # Validation checks for user input
        if password != confirmpassword: #makes sure passwords match to avoid typo in password
            return redirect('/signup?error=passwords_dont_match')
        if len(password) < 8: # makes sure password is at least 8 characters for security
            return redirect('/signup?error=password_too_short')
        if len(username) > 50: # makes sure username isnt too long
            return redirect('/signup?error=user_name_too_long')
        if len(email) > 50: #makes sure email is isnt too long
            return redirect('/signup?error=email_too_long')
        if len(password) > 30: #makes sure password isnt too long
            return redirect('/signup?error=password_too_long')
        if len(admin_code) > 4: #makes sure correct admin code length
            return redirect('/signup?error=admin_code_error')

        # Determine admin status based on secret code
        is_admin = 1 if admin_code == '1992' else 0

        # encrypt password using bcrypt
        hashed_password = bcrypt.generate_password_hash(password)

        con = connect_database(DATABASE)
        cur = con.cursor()

        if is_admin == 1:
            # Insert new admin user into table
            query_insert = "INSERT INTO signup_users (name, email, password, admin) VALUES (?, ?, ?, ?)"
            cur.execute(query_insert, (username, email, hashed_password, is_admin))
        else:
            # Insert new regular user into table
            query_insert = "INSERT INTO signup_users (name, email, password) VALUES (?, ?, ?)"
            cur.execute(query_insert, (username, email, hashed_password))

        con.commit()
        con.close()
        return redirect("/login") #if successfully signed up, will be redirected to login page

    return render_template('signup.html')

# Route to log the user out and clear their session
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()  # Remove all session data
    return redirect('/?message=successfully logged out')

if __name__ == '__main__':
    app.run()
