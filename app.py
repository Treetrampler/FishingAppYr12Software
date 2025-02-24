import sqlite3
import re
import os
import uuid
from flask import Flask, render_template, request, redirect, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta, datetime
import pytz
from bleach import clean
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

app.secret_key = 'd3b07384d113edec49eaa6238ad5ff00c86c392bd62329c75b90dbd174ca03eb'
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
LOG_FILE = "user_activity.log"
FISH_LIST = ['Bass', 'Catfish', 'Crappie', 'Perch', 'Pike', 'Australian Salmon', 'Trout', 'Walleye', 'Bream', 'Mulloway', 'Mullet']

limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])

app.config.update(
    SESSION_COOKIE_SECURE=True, #enforces HTTPS for session cookies
    SESSION_COOKIE_HTTPONLY=True, #prevents client-side JS from accessing session cookies
    SESSION_COOKIE_SAMESITE='Strict' #prevents cross site request forgery
)

@app.before_request
def enforce_https():
    if not request.is_secure:
        return redirect(request.url.replace("http://", "https://"))
    
@app.before_request
def session_log(): 
    if 'user_id' in session:
        session.modified = True  # Refresh session expiration
    else:
        if 'username' in session:
            log_user_activity("session expired", session['username'])
            session.clear()
    
def make_session_permanent():
    session.permanent = True

def log_user_activity(action, username):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open("user_activity.log", "a") as log_file:
        log_file.write(f"{timestamp} - {username} {action}\n")

@app.errorhandler(400)
def bad_request_error():
    return render_template('error.html', message="Bad Request: Please check your input."), 400
@app.errorhandler(403)
def forbidden_error():
    return render_template('error.html', message="Forbidden: You don’t have permission to access this."), 403
@app.errorhandler(404)
def not_found_error():
    return render_template('error.html', message="Page Not Found: The resource you requested does not exist."), 404
@app.errorhandler(500)
def internal_error():
    return render_template('error.html', message="Internal Server Error: Something went wrong on our end."), 500

def is_valid(item):
    return isinstance(item,str) and 1<=len(item)<=255 and re.match(r"^[a-zA-Z0-9\s.,-_]+$", item)

def init_db():
    try:
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_data
        (user_id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT NOT NULL, 
        password TEXT NOT NULL,
        email TEXT,
        admin INTEGER NOT NULL)
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
        conn.commit()
    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()

init_db() #calls the function to init the db

@limiter.exempt
@app.route('/') #the main page, creates the home page
def index():
    try:
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('SELECT posts.image_path, posts.caption, user_data.username FROM posts JOIN user_data ON posts.user_id = user_data.user_id ORDER BY posts.post_id DESC')
        posts = cursor.fetchall()
        admin = 0

        if 'user_id' in session:
            cursor.execute('SELECT admin FROM user_data WHERE user_id = ?', (session['user_id'],))
            result = cursor.fetchone()
            admin = result[0] if result else 0  # Extract admin value safely

    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()

    if admin == 1:
        return render_template('admin_home.html')
    else:
        return render_template('index.html', posts=posts)

@app.route('/login', methods=['POST', 'GET']) #called when someone tries to login after entering username and pw
@limiter.limit("10 per minute")
def login():
    if request.method=='POST':
        username = clean(request.form['username'])
        if not is_valid(username):
            flash('Invalid username, try again', 'error')
            return redirect('/login')
        
        password = clean(request.form['password'])
        if not is_valid(password):
            flash('Invalid password, try again', 'error')
            return redirect('/login')
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM user_data WHERE username = ?', (username,))
            user = cursor.fetchone()
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['csfr_token'] = str(uuid.uuid4())

                log_user_activity("logged in", username)

                cursor.execute('INSERT INTO user_sessions (user_id) VALUES (?)', (user[0],))
                conn.commit()

                if user[4] == 1:
                    return redirect('/admin_home')
                else:
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


@app.route('/register', methods=['POST', 'GET']) #called when someone tries to register after entering username and pw
def register():
    if request.method == 'POST':
        username = clean(request.form['username'])
        if not is_valid(username):
            flash('Invalid username, try again', 'error')
            return redirect('/register')
        
        password = clean(request.form['password'])
        check_password = clean(request.form['confirm_password'])
        if not is_valid(password):
            flash('Invalid password, try again', 'error')
            return redirect('/register')
        elif password != check_password:
            flash('Passwords do not match.', 'error')
            return redirect('/register')
        
        hashed_password = generate_password_hash(password)

        email = clean(request.form['email'])

        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM user_data WHERE username = ?', (username,))
            user_exists = cursor.fetchone()[0] > 0
            if user_exists:
                flash('Username already exists.', 'error')
            else:
                safe_username = escape(username)
                safe_email = escape(email)
                if username == 'Hamish':
                    admin = 1
                else:
                    admin = 0
                cursor.execute('INSERT INTO user_data (username, password, email, admin) VALUES (?, ?, ?, ?)', (safe_username, hashed_password, safe_email, admin))
                conn.commit()
                cursor.execute('SELECT user_id FROM user_data WHERE username = ?', (username,))
                user_id = cursor.fetchone()[0]
                session['user_id'] = user_id
                session['username'] = username
                session['csfr_token'] = str(uuid.uuid4())

                log_user_activity("logged in", username)

                cursor.execute('INSERT INTO user_sessions (user_id) VALUES (?)', (user_id,))
                conn.commit()
                flash('User registered successfully!', 'success')
                if admin == 1:
                    return redirect('/admin_home')
                else:
                    return redirect('/')
        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()

    return render_template('register_page.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_data = []
    user_posts = []
    
    try:
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        
        # Fetch user data
        cursor.execute('SELECT * FROM user_data WHERE user_id = ?', (session['user_id'],))
        user_data = cursor.fetchone()
        
        # Fetch user posts
        cursor.execute('SELECT post_id, image_path, caption FROM posts WHERE user_id = ?', (session['user_id'],))
        user_posts = cursor.fetchall()
        
    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()

    return render_template('profile.html', user_data=user_data, user_posts=user_posts)

@app.route('/edit_profile', methods=['POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/login')
    
    username = clean(request.form.get('username'))
    print('editing profile')
    
    if not is_valid(username):
        flash('Invalid username, try again', 'error')
        return redirect('/profile')
    
    try:
        safe_username = escape(username)
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        print('runnning db')
        print(session['user_id'])
        cursor.execute('UPDATE user_data SET username = ? WHERE user_id = ?', (safe_username, session['user_id']))
        print('succesffuly updated')
        conn.commit()
        flash(f'Username updated to {safe_username}', 'success')
    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()
    
    return redirect('/profile')

@app.route('/user_edit_post', methods=['POST'])
def user_edit_post():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/login')
    
    post_id = request.form.get('post_id')
    caption = clean(request.form.get('caption'))
    
    if not is_valid(caption):
        flash('Invalid caption, try again', 'error')
        return redirect('/profile')
    
    try:
        safe_caption = escape(caption)
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE posts SET caption = ? WHERE post_id = ? AND user_id = ?', (safe_caption, post_id, session['user_id']))
        conn.commit()
        flash('Post updated successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()
    
    return redirect('/profile')

@app.route('/user_delete_post', methods=['POST'])
def user_delete_post():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/login')
    
    post_id = request.form.get('post_id')
    
    try:
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM posts WHERE post_id = ? AND user_id = ?', (post_id, session['user_id']))
        conn.commit()
        flash('Post deleted successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()
    
    return redirect('/profile')

@app.route('/logout')
def logout():
    if 'username' in session:
        log_user_activity("logged out", session['username'])
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('UPDATE user_sessions SET logout_time = CURRENT_TIMESTAMP, active = 0 WHERE user_id = ? AND active = 1', (session['user_id'],))
            conn.commit()
        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()
    session.clear()
    return redirect('/')

@app.route('/identifier', methods=['GET'])
def fish_identifier():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/')
    return render_template('identifier.html')

@app.route('/map', methods=['GET'])
def map():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/')
    return render_template('map.html')

@app.route('/fish_dex', methods=['GET', 'POST'])
def fish_dex():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/')
    if request.method == 'GET':
        try:
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM user_fishdata WHERE user_id = ?', (session['user_id'],))
            caught_list = cursor.fetchall()
        except sqlite3.IntegrityError:
            flash('A database integrity error occurred. Please try again.', 'error')
        except sqlite3.Error:
            flash('A database error occurred. Please contact support.', 'error')
        finally:
            conn.close()
        uncaught_list = [fish for fish in FISH_LIST if fish not in [fish[1] for fish in caught_list]]
    return render_template('fish_dex.html', caught_list=caught_list, uncaught_list=uncaught_list)

@app.route('/upload_fish_image', methods=['POST'])
def upload_fish_image():    
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/')
    fish_id = request.form.get('fish_id')
    image = request.files['image']
    
    if image:
        try:
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)
            
            # Update the database with the new image path
            conn = sqlite3.connect('fishing_app.db')
            cursor = conn.cursor()
            if fish_id:
                try:
                    cursor.execute('UPDATE user_fishdata SET image_path = ? WHERE fish_id = ? AND user_id = ?', 
                                (image_path, fish_id, session['user_id']))
                    conn.commit()
                except sqlite3.IntegrityError:
                    flash('A database integrity error occurred. Please try again.', 'error')
                except sqlite3.Error:
                    flash('A database error occurred. Please contact support.', 'error')
            else:
                try:
                    cursor.execute('INSERT INTO user_fishdata (fish_name, user_id, image_path) VALUES (?, ?, ?)', 
                                (request.form.get('fish_name'), session['user_id'], image_path))
                    conn.commit()
                except sqlite3.IntegrityError:
                    flash('A database integrity error occurred. Please try again.', 'error')
                except sqlite3.Error:
                    flash('A database error occurred. Please contact support.', 'error')
            conn.close()
            flash('Image uploaded successfully!', 'success')

        except FileNotFoundError:
            flash('File failed to upload, please retry', 'error')

        finally:
            return redirect('/fish_dex')
    else:
        flash('Failed to upload image. Please try again.', 'error')
        return redirect('/fish_dex')

@app.route('/create_post', methods=['POST'])
def create_post():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/')
    
    caption = clean(request.form.get('caption'))

    if not is_valid(caption):
        flash('Invalid caption, try again', 'error')
        return redirect('/')
    
    image = request.files['image']

    if image:
        try:
            filename = secure_filename(image.filename)
            print(filename)
            print(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            relative_image_path = os.path.join('uploads', filename).replace("\\", "/")  # Store relative path
            image.save(image_path)
        
            try:
                safe_caption = escape(caption)
                conn = sqlite3.connect('fishing_app.db')
                cursor = conn.cursor()
                cursor.execute('INSERT INTO posts (user_id, image_path, caption) VALUES (?, ?, ?)', 
                            (session['user_id'], relative_image_path, safe_caption))
                conn.commit()
                flash('Post created successfully!', 'success')
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
        flash('Failed to create post. Please try again.', 'error')
        return redirect('/')
    
@app.route('/admin_home')
def admin_home():
    return render_template('admin_home.html')

@app.route('/get_logged_in_users', methods=['GET'])
def get_logged_in_users():
    try:
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        
        # Fetch timestamps from database (assuming they are stored in UTC)
        cursor.execute('SELECT login_time, COUNT(*) FROM user_sessions WHERE active = 1 GROUP BY login_time')
        data = cursor.fetchall()
        
        # Define timezones
        utc_tz = pytz.utc
        aest_tz = pytz.timezone('Australia/Sydney')  # Handles AEST/AEDT automatically
        
        timestamps = []
        logged_in_users = []

        for row in data:
            utc_time = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")  # Adjust format if needed
            utc_time = utc_tz.localize(utc_time)  # Ensure it's treated as UTC
            aest_time = utc_time.astimezone(aest_tz)  # Convert to AEST/AEDT

            timestamps.append(aest_time.strftime("%Y-%m-%d %H:%M"))  # Format properly
            logged_in_users.append(row[1])

        return jsonify({
            'timestamps': timestamps,
            'logged_in_users': logged_in_users
        })
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

    
@app.route('/post_management', methods=['GET'])
def post_management():
    post_data = []
    try:
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM posts')
        post_data = cursor.fetchall()
    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()
    print(post_data)
    return render_template('post_management.html', post_data=post_data)

@app.route('/delete_post', methods=['POST'])
def delete_post():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/login')
    
    post_id = request.form.get('post_id')
    
    try:
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM posts WHERE post_id = ?', (post_id,))
        conn.commit()
        flash('Post deleted successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()
    
    return redirect('/post_management')

@app.route('/edit_post', methods=['POST'])
def edit_post():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/login')
    
    post_id = request.form.get('post_id')
    user_id = request.form.get('user_id')
    image_src = request.form.get('image_src')
    caption = clean(request.form.get('caption'))

    if not is_valid(caption):
        flash('Invalid caption, try again', 'error')
        return redirect('/post_management')
    
    try:
        safe_caption = escape(caption)
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE posts SET user_id = ?, image_path = ?, caption = ? WHERE post_id = ?', (user_id, image_src, safe_caption, post_id))
        conn.commit()
        flash('Post updated successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()
    
    return redirect('/post_management')

@app.route('/user_management', methods=['GET'])
def user_management():
    user_data = []
    try:
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM user_data')
        user_data = cursor.fetchall()
    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()
    return render_template('user_management.html', user_data=user_data)

@app.route('/edit_user', methods=['POST'])
def edit_user():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/login')
    
    user_id = request.form.get('user_id')
    username = clean(request.form.get('username'))
    admin = request.form.get('admin')
    
    if not is_valid(username):
        flash('Invalid username, try again', 'error')
        return redirect('/user_management')
    
    try:
        safe_username = escape(username)
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE user_data SET username = ?, admin = ? WHERE user_id = ?', (safe_username, admin, user_id))
        conn.commit()
        flash('User updated successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()
    
    return redirect('/user_management')

@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect('/login')
    
    user_id = request.form.get('user_id')
    
    try:
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM user_data WHERE user_id = ?', (user_id,))
        conn.commit()
        flash('User deleted successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('A database integrity error occurred. Please try again.', 'error')
    except sqlite3.Error:
        flash('A database error occurred. Please contact support.', 'error')
    finally:
        conn.close()
    
    return redirect('/user_management')

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('certs/cert.pem', 'certs/key.pem'), host="0.0.0.0", port=443)