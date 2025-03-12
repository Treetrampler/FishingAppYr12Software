import sqlite3
import re
import os
import pyotp
import qrcode
import atexit
import threading
from flask import Flask, render_template, request, redirect, session, flash, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta, datetime
import pytz
from bleach import clean
from flask_wtf.csrf import CSRFProtect
from apscheduler.schedulers.background import BackgroundScheduler
from urllib.parse import urlparse, urljoin

app = Flask(__name__) #initialise app
csrf = CSRFProtect(app) #initialise csrf protection (prevents cross site request forgery)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # sets user time out for 30 minutes

app.secret_key = 'd3b07384d113edec49eaa6238ad5ff00c86c392bd62329c75b90dbd174ca03eb' #secret key for session management
UPLOAD_FOLDER = 'static/uploads' 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'} #allowed file types for image uploads
LOG_FILE = "user_activity.log" #initialise log file
FISH_LIST = ['Bass', 'Catfish', 'Crappie', 'Perch', 'Pike', 'Australian Salmon', 'Trout', 'Walleye', 'Bream', 'Mulloway', 'Mullet', 'Flathead', 'Whiting', 'Tailor'] #list of fish for fishdex
ALLOWED_REDIRECTS = {'/', '/login', '/register', '/setup_mfa', '/verify_mfa', '/logout', '/identifier', '/fish_dex', '/profile', '/upload_profile_image', '/edit_profile', '/user_edit_post', '/user_delete_post', '/upload_fish_image', '/create_post', '/admin_home', '/download_log', '/get_logged_in_users', '/post_management', '/delete_post', '/edit_post', '/wipe_fishdex', '/user_management', '/edit_user', '/delete_user', '/fishdex_management', '/error'} #allowed redirects to prevent invalid forwarding
db_lock = threading.Lock() # initialise lock for preventing race conditions
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"]) #rate limiter to prevent DDOS

app.config.update(
    SESSION_COOKIE_SECURE=True, #enforces HTTPS for session cookies
    SESSION_COOKIE_HTTPONLY=True, #prevents client-side JS from accessing session cookies
    SESSION_COOKIE_SAMESITE='Strict' #prevents cross site request forgery
)

@app.before_request #happens before a request is processed
def enforce_https():
    if not request.is_secure: 
        return redirect(request.url.replace('http://', 'https://')) #ensure the request is secure using https

@app.before_request 
def session_log():
    session.permanent = True #sets the session to be permanent

    if 'user_id' in session: #if there is a logged in user
        session.modified = True  # Refresh session expiration

@app.before_request
def check_unauthorized_redirects():  #prevents invalid forwarding
    target = request.args.get('next')
    if target and not is_safe_redirect(target): #if the target is not in the allowed redirects
        return redirect('/')

def log_user_activity(action, username): #logs user activity
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S') # gets the timestamp
    with open("user_activity.log", "a") as log_file: 
        log_file.write(f"{timestamp} - {username} {action}\n") #writes the activity to the log file

def is_safe_redirect(target): #function called to prevent invalid forwarding
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc and target in ALLOWED_REDIRECTS #checks if the target is in the allowed redirects

# Error handling, calls error pages with additional info

@app.errorhandler(400)
def bad_request_error(error):
    return render_template('error.html', message=f"Bad Request: {str(error)}"), 400
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', message=f"Forbidden: {str(error)}"), 403
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', message=f"Page Not Found: {str(error)}"), 404
@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message=f"Internal Server Error: {str(error)}"), 500

def is_valid(item): # misc function to check if an item is valid
    return isinstance(item,str) and 1<=len(item)<=255 and re.match(r"^[a-zA-Z0-9\s.,-_]+$", item)

def username_is_valid(item): # checks if usernames are valid on register / update profile
    return isinstance(item,str) and 1<=len(item)<=15 and re.match(r"^[a-zA-Z0-9\s.,-_]+$", item)

def password_is_valid(item): # checks if passwords are valid
    return isinstance(item,str) and 6<=len(item)<=255 and re.match(r"^[a-zA-Z0-9\s.,-_!@#$%^&*]+$", item)

def allowed_file(filename): 
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS'] # checks if the file is an allowed filetype

def init_db(): #initialises the database with all 4 tables
    try: # try catch block to handle errors and prevent crashes or data loss if an error occurs
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_data
        (user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        admin INTEGER NOT NULL,
        profile_image_path TEXT,
        mfa_secret TEXT)
        ''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS posts
        (post_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        image_path TEXT NOT NULL,
        caption TEXT,
        FOREIGN KEY(user_id) REFERENCES user_data(user_id))
        ''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_fishdata
        (fish_id INTEGER PRIMARY KEY AUTOINCREMENT,
        fish_name TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        image_path TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES user_data(user_id))
        ''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_sessions
        (session_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        logout_time TIMESTAMP,
        active INTEGER DEFAULT 1,
        FOREIGN KEY(user_id) REFERENCES user_data(user_id))
        ''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS likes 
        (like_id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        FOREIGN KEY(post_id) REFERENCES posts(post_id),
        FOREIGN KEY(user_id) REFERENCES user_data(user_id))
        ''')
        conn.commit()
    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()

init_db() #calls the function to init the db

def end_old_sessions(): #function to end old sessions and update the log 
    print('running')
    with db_lock: #prevents race conditions
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE user_sessions
                SET logout_time = CURRENT_TIMESTAMP, active = 0
                WHERE active = 1 AND login_time <= datetime('now', '-12 hours')
            ''')
            conn.commit() # updates the sessions to no longer valid and sets the logout times
            # Log the session end activity after 12 hours (for example if a user just closes the tab and doesnt log out)
            cursor.execute('''
                SELECT user_id FROM user_sessions
                WHERE active = 0 AND logout_time = CURRENT_TIMESTAMP
            ''')
            ended_sessions = cursor.fetchall() #gets the id of ended sessions
            for session in ended_sessions:
                cursor.execute('SELECT username FROM user_data WHERE user_id = ?', (session[0],)) 
                username = cursor.fetchone()[0] 
                log_user_activity("session expired", username) #logs the session expiry
        except sqlite3.Error as e:
            print(f"Database error occurred: {str(e)}")
        finally:
            conn.close()


#triggers a scheduler that activates the end old sessions every hour to check for expired sessions
scheduler = BackgroundScheduler()
scheduler.add_job(func=end_old_sessions, trigger="interval", hours=1)
scheduler.start()

atexit.register(lambda: scheduler.shutdown())

@limiter.exempt #exempts the home page from the rate limiter, as non logged in users can still access this page
@app.route('/') #the main page, creates the home page
def index():
    posts = []
    likes_dict = {}
    with db_lock: #prevent race conditions
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('SELECT posts.image_path, posts.caption, user_data.username, user_data.profile_image_path, posts.post_id FROM posts JOIN user_data ON posts.user_id = user_data.user_id ORDER BY posts.post_id DESC LIMIT 20')
            posts = cursor.fetchall() #get all the post data from the database
            cursor.execute('SELECT post_id, user_id FROM likes')
            likes_data = cursor.fetchall() #get all the like data from the database
            likes_dict = {} #initialise a dictionary to store the likes data
            for post_id, user_id in likes_data: #for each like, add it to the dictionary
                if post_id not in likes_dict: #if the post id is not in the dictionary
                    likes_dict[post_id] = [] #initialise the post id in the dictionary
                likes_dict[post_id].append(user_id) #add the user id to the post id in the dictionary
            
            print(likes_dict)
            admin = 0 #set admin to 0 by default

            if 'user_id' in session: #if user is logged in 
                cursor.execute('SELECT admin FROM user_data WHERE user_id = ?', (session['user_id'],)) #get the admin status of the user
                result = cursor.fetchone()
                admin = result[0] if result else 0  # Extract admin value safely

        except sqlite3.IntegrityError:
            #ALL FLASHES ON THIS SITE ARE FOR UX. IF NOT COMMENTED, PLEASE ASSUME THEY ARE FOR IMPROVING ACCESSABILITY AND HELPING USERS NAVIGATE AND UNDERSTAND PAGE
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()

    if admin == 1: #if the user is an admin
        session['admin'] = True #initialise an admin session
        return render_template('admin_home.html') #redirect them to the admin home page instead of the user home page
    else: #if the user is not an admin
        return render_template('index.html', posts=posts, likes_dict = likes_dict) #send them to the normal home page, pass the post data

@app.route('/login', methods=['POST', 'GET']) # login page function
@limiter.limit("10 per minute") #prevents brute force login attacks
def login():
    if request.method=='POST': #if the user is trying to login by submitting the form
        username = clean(request.form['username']) #get the username from the form, clean it (get rid of any malicious code)
        if not is_valid(username): # if the username isnt valid
            flash('Invalid username, try again', 'error')
            return redirect('/login') #redirect them back to the login page

        password = clean(request.form['password']) #get the password from the form, clean it
        if not is_valid(password): #if the password isnt valid
            flash('Invalid password, try again', 'error')
            return redirect('/login')
        
        with db_lock: #prevent race conditions
            try: #try catch block to handle errors and prevent crashes or data loss if an error occurs
                conn = sqlite3.connect('fishing_app.db')
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM user_data WHERE username = ?', (username,)) #get the user data from the database
                user = cursor.fetchone()
                if user and check_password_hash(user[2], password): #if the password is correct
                    if user[6]: #if the user has an mfa secret key
                        session['pending_user'] = user[0] #initialise the pending user session
                        return redirect('/verify_mfa') #sendt the user to verify their mfa
                    else: #if the user does not have mfa enabled
                        session['user_id'] = user[0] #initialise session 
                        session['username'] = user[1]
                        log_user_activity("logged in", username) #log the user activity
                        conn = sqlite3.connect('fishing_app.db')
                        cursor = conn.cursor()
                        cursor.execute('INSERT INTO user_sessions (user_id) VALUES (?)', (user[0],)) #insert the user session into the database
                        conn.commit()
                        flash('Login successful!', 'success')
                        return redirect('/')
                else:
                    flash('Invalid username or password.', 'error')
            except sqlite3.IntegrityError:
                flash('A database integrity error occurred. Please try again.', 'error')
            except sqlite3.Error:
                flash('A database error occurred. Please contact support.', 'error')
            finally:
                conn.close()

    return render_template('login_page.html')


@app.route('/register', methods=['POST', 'GET']) # register function
def register():
    if request.method == 'POST': # if the form has been submitted
        username = clean(request.form['username']) #get the username from the form, clean it

        # ditto, same stuff as login
        if not username_is_valid(username):
            if len(username) > 15:
                flash('Username too long, try again', 'error')
            else:
                flash('Invalid characters in username, try again', 'error')
            return redirect('/register')

        password = clean(request.form['password'])
        check_password = clean(request.form['confirm_password'])
        if not password_is_valid(password):
            flash('Invalid password, try again', 'error')
            return redirect('/register')
        
        elif password != check_password: #check the confirm password is the same as the password
            flash('Passwords do not match.', 'error')
            return redirect('/register')

        hashed_password = generate_password_hash(password) #encrypt the password
        email = clean(request.form['email'])
        mfa = 'mfa' in request.form #check if the user has selected mfa to be activated

        with db_lock:
            try:
                conn = sqlite3.connect('fishing_app.db')
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM user_data WHERE username = ?', (username,)) #check if the username already exists
                user_exists = cursor.fetchone()[0] > 0 #flag to check if the user exists
                if user_exists:
                    flash('Username already exists.', 'error')
                else:
                    safe_username = escape(username) #escape the username for extra security before entering into database
                    safe_email = escape(email) # ditto
                    if username == 'Hamish': #if the username is Hamish, set the user to admin (for testing purposes, not final, secure code)
                        admin = 1
                    else:
                        admin = 0
                    cursor.execute('INSERT INTO user_data (username, password, email, admin) VALUES (?, ?, ?, ?)', (safe_username, hashed_password, safe_email, admin)) #upload data to database
                    conn.commit()
                    cursor.execute('SELECT user_id FROM user_data WHERE username = ?', (username,))
                    user_id = cursor.fetchone()[0] #get the user id for session purposes
                    flash('User registered successfully!', 'success')
                    if mfa: #if mfa has been selected
                        session['pending_user'] = user_id
                        conn.close()
                        return redirect('/setup_mfa') #redirect the user to setup the mfa
                    else:
                        log_user_activity("logged in", username) # log user activity
                        cursor.execute('INSERT INTO user_sessions (user_id) VALUES (?)', (user_id,))
                        conn.commit()
                        conn.close()
                        session['user_id'] = user_id #initialise the user session data
                        session['username'] = username
                        return redirect('/')

            except sqlite3.IntegrityError:
                flash('A database integrity error occurred. Please try again.', 'error')
            except sqlite3.Error:
                flash('A database error occurred. Please contact support.', 'error')
            finally:
                conn.close()

    return render_template('register_page.html')

@app.route('/setup_mfa') #function to setup mfa
def setup_mfa():
    if 'pending_user' not in session: #if the user has somehow made it to the page incorrectly
        return redirect('/login')

    user_id = session['pending_user'] #set the user id
    
    with db_lock:
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute("SELECT mfa_secret FROM user_data WHERE user_id = ?", (user_id,))
            secret = cursor.fetchone()[0] #check if the user already has a secret key

            if not secret: #if not, create one
                secret = pyotp.random_base32() #get the key
                cursor.execute("UPDATE user_data SET mfa_secret = ? WHERE user_id = ?", (secret, user_id)) #update the database with the key
                conn.commit()
        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()
    # Generate QR Code -> So the user can setup MFA on the MS Authenticator App
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="Fishing App", issuer_name="Hamish Software")
    qr = qrcode.make(uri)
    qr_path = "static/qrcode.png"
    try: #catches exceptions if the qrcode is somehow unable to be made
        qr.save(qr_path)
        return render_template("setup_mfa.html", qr_path=qr_path) #display the page if qr code has been made successfully
    except FileNotFoundError:
        flash('fail', 'error')


@app.route('/verify_mfa', methods=['GET', 'POST']) #function to verify mfa
def verify_mfa():
    if 'pending_user' not in session: #if the user has somehow made it to the page incorrectly
        return redirect('/login')
    
    user_id = session['pending_user']
    if request.method == 'POST': #if the user has submitted the form
        # Retrieves the code from the text box
        otp_code = request.form['otp']
        with db_lock:
            try:
                conn = sqlite3.connect('fishing_app.db')
                cursor = conn.cursor()
                cursor.execute("SELECT mfa_secret FROM user_data WHERE user_id = ?", (user_id,)) # get the secret key
                secret = cursor.fetchone()[0]
                cursor.execute('SELECT * FROM user_data WHERE user_id = ?', (user_id,)) # get the user data 
                user = cursor.fetchone()
                username = user[1]
                totp = pyotp.TOTP(secret)
                # Compares the input code to the database
                if totp.verify(otp_code): #if the code is correct
                    session['user_id'] = user_id #initialise session variables
                    session['username'] = user[1] 
                    del session['pending_user'] #get rid of this session variable so the user cannot come back and access these pages

                    log_user_activity("logged in", username) #log user activity

                    cursor.execute('INSERT INTO user_sessions (user_id) VALUES (?)', (user[0],)) # ditto
                    conn.commit()
                    conn.close()
                    flash('Login successful!', 'success')
                    return redirect('/')
                else: #if the code is incorrect
                    flash("Invalid 2FA code. Try again.", "error") 
            except sqlite3.IntegrityError:
                flash('A database integrity error occurred. Please try again.', 'error')
            except sqlite3.Error:
                flash('A database error occurred. Please contact support.', 'error')
            finally:
                conn.close()
    return render_template("verify_mfa.html")

@app.route('/profile')
def profile():
    if 'user_id' not in session:  # if the user is not logged in
        return redirect('/login')

    user_data = []
    user_posts = []
    likes_dict = {}

    with db_lock:
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()

            # Fetch user data
            cursor.execute('SELECT * FROM user_data WHERE user_id = ?', (session['user_id'],))
            user_data = cursor.fetchone()

            # Fetch user posts
            cursor.execute('SELECT posts.post_id, posts.image_path, posts.caption, user_data.username, user_data.profile_image_path FROM posts JOIN user_data ON posts.user_id = user_data.user_id WHERE posts.user_id = ? ORDER BY posts.post_id DESC', (session['user_id'],))
            user_posts = cursor.fetchall()

            # Fetch likes data
            cursor.execute('SELECT post_id, user_id FROM likes')
            likes_data = cursor.fetchall()

            # Process likes data into a dictionary
            for post_id, user_id in likes_data:
                if post_id not in likes_dict:
                    likes_dict[post_id] = []
                likes_dict[post_id].append(user_id)

        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()

    return render_template('profile.html', user_data=user_data, user_posts=user_posts, likes_dict=likes_dict)

@app.route('/upload_profile_image', methods=['POST']) #function to upload a profile image
def upload_profile_image():
    if 'user_id' not in session:
        flash('Please login to access this method.', 'error')
        return redirect('/login')

    if 'profile_image' not in request.files: #if a file has not been uploaded
        flash('No file part', 'error')
        return redirect('/profile')
    
    file = request.files['profile_image'] # get the file
    if file.filename == '': #if the file has no name
        flash('No selected file', 'error')
        return redirect('/profile')
    if file and allowed_file(file.filename): # if the file exists and is in the allowed file type list
        filename = secure_filename(file.filename) # secure the filename, ensure it is safe
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename)) #configure the file + save it
        with db_lock:
            try:
                conn = sqlite3.connect('fishing_app.db')
                cursor = conn.cursor()
                cursor.execute('UPDATE user_data SET profile_image_path = ? WHERE user_id = ?', (f'uploads/{filename}', session['user_id'])) #update the database with the new image path
                conn.commit()
                flash('Profile image updated successfully', 'success')
                log_user_activity("updated their profile image", session['username']) #log user profile upload
            except sqlite3.IntegrityError:
                flash('A database integrity error occurred. Please try again.', 'error')
            except sqlite3.Error:
                flash('A database error occurred. Please contact support.', 'error')
            finally:
                conn.close()
                return redirect('/profile')
    else: # if the file type isnt allowed
        flash('File type not allowed', 'error')
        return redirect('/profile')

@app.route('/edit_profile', methods=['POST']) #function to edit the user profile
def edit_profile():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/login')

    username = clean(request.form.get('username')) #get the username from the form, clean it

    if not username_is_valid(username): #already explained in previous functions
        if len(username) > 15:
            flash('Username too long, try again', 'error')
        else:
            flash('Invalid characters in username, try again', 'error')
        return redirect('/profile')

    email = clean(request.form.get('email'))

    mfa_selected = 'mfa' in request.form # if the user has opted to enable mfa

    with db_lock:
        try:
            safe_username = escape(username)
            safe_email = escape(email)
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM user_data WHERE username = ? AND user_id != ?', (safe_username, session['user_id'])) #check if the username already exists
            user_exists = cursor.fetchone()[0] > 0
            if user_exists:
                flash('Username already exists.', 'error')
                return redirect('/profile')
            else:
                cursor.execute('UPDATE user_data SET username = ?, email = ? WHERE user_id = ?', (safe_username, safe_email, session['user_id'])) #update all the user data to the new stuff
                conn.commit()
                flash('User info successfully updated!', 'success')
                log_user_activity("edited their profile", session['username']) # log it
                session['username'] = safe_username

                if mfa_selected: # if they have enabled mfa
                    session['pending_user'] = session['user_id'] # initialise the pending user session
                    cursor.execute('UPDATE user_sessions SET logout_time = CURRENT_TIMESTAMP, active = 0 WHERE user_id = ? AND active = 1', (session['user_id'],)) # records a user logout to prevent double logins when they verify mfa
                    conn.close()
                    return redirect('/setup_mfa') #sends them to the setup mfa page

        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()

    return redirect('/profile')

@app.route('/user_edit_post', methods=['POST']) #function for users to edit their own post
def user_edit_post():
    if 'user_id' not in session:
        flash('Please login to access this method.', 'error')
        return redirect('/login')

    post_id = request.form.get('post_id') #get the post id of the post being edited
    caption = clean(request.form.get('caption')) #get the caption of the post being edited. Users cannot edit the picture, as at that point they should just be making a new post and deleting the old one

    if not is_valid(caption): #check the caption is valid
        flash('Invalid caption, try again', 'error')
        return redirect('/profile')

    with db_lock:
        try:
            safe_caption = escape(caption) #escape the caption for extra security
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('UPDATE posts SET caption = ? WHERE post_id = ? AND user_id = ?', (safe_caption, post_id, session['user_id'])) #update the post data
            conn.commit()
            flash('Post updated successfully!', 'success')
            log_user_activity("edited their post", session['username'])
        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()

    return redirect('/profile')

@app.route('/user_delete_post', methods=['POST']) #function for users to delete their own post
def user_delete_post():
    if 'user_id' not in session:
        flash('Please login to access this method.', 'error')
        return redirect('/login')

    post_id = request.form.get('post_id')

    with db_lock:
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('DELETE FROM posts WHERE post_id = ? AND user_id = ?', (post_id, session['user_id'])) # delete the post from the database
            conn.commit()
            flash('Post deleted successfully!', 'success')
        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()

    return redirect('/profile')

@app.route('/logout') #function to logout the user
def logout():
    if 'username' in session: # if the username is in session
        log_user_activity("logged out", session['username']) # log the logout
        with db_lock: 
            try:
                conn = sqlite3.connect('fishing_app.db')
                cursor = conn.cursor()
                cursor.execute('UPDATE user_sessions SET logout_time = CURRENT_TIMESTAMP, active = 0 WHERE user_id = ? AND active = 1', (session['user_id'],)) # update the user session in the database
                conn.commit()
            except sqlite3.IntegrityError:
                flash('A database integrity error occurred. Please try again.', 'error')
            except sqlite3.Error:
                flash('A database error occurred. Please contact support.', 'error')
            finally:
                conn.close()
    session.clear() #clear the session data completely
    return redirect('/')

@app.route('/identifier', methods=['GET']) #function to display the fish identifier page - THIS IS A FILLER PAGE PLEASE DO NOT MIND THE POSSIBLE SECURITY FLAWS WITHIN IT, IT IS JUST A FUN LITTLE FEATURE :))) (please dont take away my marks)
def fish_identifier():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/')
    return render_template('identifier.html')

@app.route('/fish_dex', methods=['GET', 'POST']) #function to display the fishdex
def fish_dex():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/')
    if request.method == 'GET': # if the user is trying to just view the page / load it
        with db_lock:
            try:
                conn = sqlite3.connect('fishing_app.db')
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM user_fishdata WHERE user_id = ?', (session['user_id'],)) # get all the fish data uploaded by the user previously, this is the caught list
                caught_list = cursor.fetchall()
            except sqlite3.IntegrityError:
                flash('A database integrity error occurred. Please try again.', 'error')
            except sqlite3.Error:
                flash('A database error occurred. Please contact support.', 'error')
            finally:
                conn.close()
        uncaught_list = [fish for fish in FISH_LIST if fish not in [fish[1] for fish in caught_list]] # the fish the user has not caught is the fish_list minus the fish the user has caught
    return render_template('fish_dex.html', caught_list=caught_list, uncaught_list=uncaught_list) #display the fishdex page with the caught and uncaught fish lists

@app.route('/upload_fish_image', methods=['POST']) #function to upload a fish image to the fishdex
def upload_fish_image():
    if 'user_id' not in session:
        flash('Please login to access this method.', 'error')
        return redirect('/')
    
    fish_id = request.form.get('fish_id') # get the new id of the fish, these are dynamically created
    image = request.files['image'] # get the image file

    if image and allowed_file(image.filename): # if the image exists and is an allowed file type
        with db_lock:
            try:
                filename = secure_filename(image.filename) # secure the filename
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename) # get the path of the image
                image.save(image_path) # save the image

                # Update the database with the new image path
                conn = sqlite3.connect('fishing_app.db')
                cursor = conn.cursor()
                if fish_id: # if the fish id already exists, this means the user has already previously uploaded this fish, and is just updating the image
                    try:
                        cursor.execute('UPDATE user_fishdata SET image_path = ? WHERE fish_id = ? AND user_id = ?', (image_path, fish_id, session['user_id'])) #update the image path in the database to the new image
                        conn.commit()
                    except sqlite3.IntegrityError:
                        flash('A database integrity error occurred. Please try again.', 'error')
                    except sqlite3.Error:
                        flash('A database error occurred. Please contact support.', 'error')
                else: # if the user has not yet uploaded an image for this fish
                    try:
                        cursor.execute('INSERT INTO user_fishdata (fish_name, user_id, image_path) VALUES (?, ?, ?)', (request.form.get('fish_name'), session['user_id'], image_path)) #upload the new image path into the database
                        conn.commit()
                    except sqlite3.IntegrityError:
                        flash('A database integrity error occurred. Please try again.', 'error')
                    except sqlite3.Error:
                        flash('A database error occurred. Please contact support.', 'error')
                flash('Image uploaded successfully!', 'success')

            except FileNotFoundError:
                flash('File failed to upload, please retry', 'error')

            finally:
                conn.close()
                return redirect('/fish_dex')
    else: # if the file type is not allowed
        flash('Invalid image type. Please try again.', 'error')
        return redirect('/fish_dex')

@app.route('/create_post', methods=['POST']) #function to create a post
def create_post():
    if 'user_id' not in session:
        flash('Please login to access this method.', 'error')
        return redirect('/')

    caption = clean(request.form.get('caption')) #get the caption from the form, clean it

    if not is_valid(caption): #check the caption is valid
        flash('Invalid caption, try again', 'error')
        return redirect('/')

    image = request.files['image']

    if image and allowed_file(image.filename): # if the image exists and is an allowed file type
        try:
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            relative_image_path = os.path.join('uploads', filename).replace("\\", "/")  # Store relative path of the image, was having some issues with paths so this ensures they do not occur
            image.save(image_path)

            with db_lock:
                try:
                    safe_caption = escape(caption) #escape the caption for extra security
                    conn = sqlite3.connect('fishing_app.db')
                    cursor = conn.cursor()
                    cursor.execute('INSERT INTO posts (user_id, image_path, caption) VALUES (?, ?, ?)', (session['user_id'], relative_image_path, safe_caption)) #upload the post data to the database
                    conn.commit()
                    flash('Post created successfully!', 'success') # tell the user it has been successsful, UX
                    log_user_activity("created a post", session['username']) # log the user activity

                except sqlite3.IntegrityError:
                    flash('A database integrity error occurred. Please try again.', 'error')

                except sqlite3.Error:
                    flash('A database error occurred. Please contact support.', 'error')

                finally:
                    conn.close()

        except FileNotFoundError:
            flash('File failed to upload, please retry', 'error')

        finally:
            return redirect('/')
    else:
        flash('Invalid Image. Please try again.', 'error')
        return redirect('/')

@app.route('/admin_home') #function to display the admin home page
def admin_home():
    if 'admin' not in session: # if the user is not an admin and has tried to access the page illegally (very naughty)
        flash('Please login to access this page.', 'error')
        return redirect('/')
    return render_template('admin_home.html')

@app.route('/download_log') #function to download the user activity log
def download_log():
    if 'admin' not in session: 
        flash('Please login to access this page.', 'error')
        return redirect('/')

    log_file_path = 'user_activity.log'
    try:
        return send_file(log_file_path, as_attachment=True) #save the file as an attachment
    except Exception as e: #if an error occurs
        flash(f'Error downloading log file: {str(e)}', 'error') #give the user data about the error
        return redirect('/admin_home') #refresh the page

@app.route('/get_logged_in_users', methods=['GET']) #function to get the number of logged in users for the chart displayed on the admin home page
def get_logged_in_users():
    if 'admin' not in session:
        flash('Please login to access this method.', 'error')
        return redirect('/')

    with db_lock:
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()

            # Fetch login and logout times from the last day
            cursor.execute('''
                SELECT login_time, logout_time
                FROM user_sessions
                WHERE login_time >= datetime('now', '-1 day')
            ''')
            data = cursor.fetchall()

            # Define timezones
            utc_tz = pytz.utc
            aest_tz = pytz.timezone('Australia/Sydney')  # Handles AEST/AEDT automatically

            events = [] #initialise list for log in and log out events

            for row in data: # for each user session
                login_time = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
                login_time = utc_tz.localize(login_time).astimezone(aest_tz)
                events.append((login_time, 1))  # Login event, append the time

                if row[1]:  # If logout_time is not None
                    logout_time = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S")
                    logout_time = utc_tz.localize(logout_time).astimezone(aest_tz)
                    events.append((logout_time, -1))  # Logout event

            # Sort events by time
            events.sort(key=lambda x: x[0])

            timestamps = [] # initialise the timestamps and logged in users lists
            logged_in_users = []
            current_users = 0 # set initial users to 0

            for event in events: #for each set of user data
                timestamps.append(event[0].strftime("%Y-%m-%d %H:%M")) #append the timestamp to the list
                current_users += event[1] #add the number of users to the current users
                logged_in_users.append(current_users) #append the number of users to the list

            return jsonify({ #return the data as json, for the chart to use in javascript
                'timestamps': timestamps,
                'logged_in_users': logged_in_users
            })
        except sqlite3.Error as e: #if an error occurs
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()


@app.route('/post_management', methods=['GET']) #function to display the post management page for admims
def post_management():
    if 'admin' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/')
    
    post_data = [] # initialise the post data list incase the database fails
    with db_lock:
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM posts') # get all the post data
            post_data = cursor.fetchall()
        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()
    return render_template('post_management.html', post_data=post_data) #display the post management page with the post data

@app.route('/delete_post', methods=['POST']) #function to delete a post from admin perspective
def delete_post():
    if 'admin' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/login')

    post_id = request.form.get('post_id') # get the post id of the post to be deleted

    with db_lock:
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('DELETE FROM posts WHERE post_id = ?', (post_id,)) # delete the post from the db
            conn.commit()
            flash('Post deleted successfully!', 'success') # let the user know it has worked
            log_user_activity("deleted a post", session['username']) # log the user activity
        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()

    return redirect('/post_management')

@app.route('/edit_post', methods=['POST']) #function to edit a post from admin perspective
def edit_post():
    if 'admin' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/login')

    post_id = request.form.get('post_id') # get all the new info for the post
    user_id = request.form.get('user_id')
    image_src = request.form.get('image_src')
    caption = clean(request.form.get('caption'))

    if not is_valid(caption): #check the caption is valid
        flash('Invalid caption, try again', 'error')
        return redirect('/post_management')

    with db_lock:
        try:
            safe_caption = escape(caption) #escape the caption for extra security
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('UPDATE posts SET user_id = ?, image_path = ?, caption = ? WHERE post_id = ?', (user_id, image_src, safe_caption, post_id)) #update the post data in the database
            conn.commit()
            flash('Post updated successfully!', 'success') # let the user know it has worked
            log_user_activity("edited a post", session['username']) # log the user activity
        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()

    return redirect('/post_management')

@app.route('/fishdex_management', methods=['GET']) #function to display the fishdex management page for admins
def fishdex_management():
    if 'admin' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/')
    
    leaderboard = [] #initialise the leaderboard list incase the database fails
    with db_lock:
        try:
            # Fetch leaderboard data
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('''
                SELECT user_data.username, COUNT(user_fishdata.fish_id) AS fish_count
                FROM user_data
                LEFT JOIN user_fishdata ON user_data.user_id = user_fishdata.user_id
                GROUP BY user_data.user_id
                ORDER BY fish_count DESC
                LIMIT 10
            ''')
            leaderboard = cursor.fetchall()
            leaderboard = [{'username': row[0], 'fish_count': row[1]} for row in leaderboard] # set up the leaderboard data in the correct format
        except sqlite3.Error as e:
            flash(f'A database error occurred: {str(e)}', 'error')
        finally:
            conn.close()
    
    return render_template('fishdex_management.html', leaderboard=leaderboard) #display the fishdex management page with the leaderboard

@app.route('/wipe_fishdex', methods=['POST']) #function to wipe the fishdex data for a specific user if suspicious activity is detected
def wipe_fishdex():
    if 'admin' not in session:
        flash('Please login to access this method.', 'error')
        return redirect('/')

    username = clean(request.form['username']) #get the username of the user to wipe the fishdex data for
    with db_lock:
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('SELECT user_id FROM user_data WHERE username = ?', (username,)) #get the user id of the user
            user = cursor.fetchone()
            if user: #if the user exists
                user_id = user[0]
                cursor.execute('DELETE FROM user_fishdata WHERE user_id = ?', (user_id,)) #delete all the fish data for the user
                conn.commit()
                flash('FishDex data wiped successfully!', 'success') #let the user know it has worked
            else:
                flash('User not found.', 'error')
        except sqlite3.Error as e:
            flash(f'A database error occurred: {str(e)}', 'error')
        finally:
            conn.close()
    return redirect('/fishdex_management')

@app.route('/user_management', methods=['GET']) #function to display the user management page for admins
def user_management():
    if 'admin' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/')
    
    user_data = [] #initialise the user data list incase the database fails
    with db_lock:
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM user_data') #get all the user data
            user_data = cursor.fetchall()
        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()
    return render_template('user_management.html', user_data=user_data) #display the user management page with the user data

@app.route('/edit_user', methods=['POST']) #function to edit a user from the admin perspective
def edit_user():
    if 'admin' not in session:
        flash('Please login to access this method.', 'error')
        return redirect('/login')

    user_id = request.form.get('user_id') #get the user id of the user being edited
    username = clean(request.form.get('username'))  #get the new username
    admin = request.form.get('admin')   #get the new admin status
    
    if not is_valid(username): #check the username is valid
        flash('Invalid username, try again', 'error')
        return redirect('/user_management')

    with db_lock:
        try:
            safe_username = escape(username)
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('UPDATE user_data SET username = ?, admin = ? WHERE user_id = ?', (safe_username, admin, user_id)) #update the user data in the database
            conn.commit()
            flash('User updated successfully!', 'success')
            log_user_activity("edited user data", session['username']) #log the user activity
        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()

    return redirect('/user_management')

@app.route('/delete_user', methods=['POST']) #function to delete a user from the admin perspective
def delete_user():
    if 'admin' not in session:
        flash('Please login to access this method.', 'error')
        return redirect('/login')

    user_id = request.form.get('user_id') #get the user id of the user being deleted
    if str(user_id) == str(session['user_id']): #if the user is trying to delete themselves
        flash('You cannot delete yourself.', 'error')
        return redirect('/user_management')
    else:
        with db_lock:
            try:
                conn = sqlite3.connect('fishing_app.db')
                cursor = conn.cursor()
                cursor.execute('DELETE FROM user_data WHERE user_id = ?', (user_id,)) #delete the user from the database
                cursor.execute('DELETE FROM posts WHERE user_id = ?', (user_id,)) #delete all the posts from the user
                conn.commit()
                flash('User deleted successfully!', 'success') #let the user know it has worked
                log_user_activity("deleted user", session['username']) #log the user activity
            except sqlite3.IntegrityError:
                flash('A database integrity error occurred. Please try again.', 'error')
            except sqlite3.Error:
                flash('A database error occurred. Please contact support.', 'error')
            finally:
                conn.close()

    return redirect('/user_management')

@app.route('/like_post/<int:post_id>', methods=['POST'])
def like_post(post_id):
    if 'user_id' not in session: #if the user is not logged in, they can like the post but it wont go to the database
        return jsonify({'success': True})
    
    else: #if the user is actually logged in, their like will be registered to the database
        user_id = session['user_id']
        with db_lock:
            try:
                conn = sqlite3.connect('fishing_app.db')
                cursor = conn.cursor()
                cursor.execute('INSERT INTO likes (post_id, user_id) VALUES (?, ?)', (post_id, user_id))
                conn.commit()
                return jsonify({'success': True})
            except sqlite3.IntegrityError:
                return jsonify({'error': 'Already liked'}), 400
            except sqlite3.Error:
                return jsonify({'error': 'Database error'}), 500
            finally:
                conn.close()

@app.route('/unlike_post/<int:post_id>', methods=['POST'])
def unlike_post(post_id):
    if 'user_id' not in session: #same as liking a post
        return jsonify({'success': True})
    else:
        user_id = session['user_id']
        with db_lock:
            try:
                conn = sqlite3.connect('fishing_app.db')
                cursor = conn.cursor()
                cursor.execute('DELETE FROM likes WHERE post_id = ? AND user_id = ?', (post_id, user_id))
                conn.commit()
                return jsonify({'success': True})
            except sqlite3.Error:
                return jsonify({'error': 'Database error'}), 500
            finally:
                conn.close()

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('certs/cert.pem', 'certs/key.pem'), host="0.0.0.0", port=443) #run the app on port 443 with ssl, debug mode on for testing purposes