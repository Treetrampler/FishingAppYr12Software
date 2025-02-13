import sqlite3
import re
import os
from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape

app = Flask(__name__)

@app.before_request
def enforce_https():
    if not request.is_secure:
        return redirect(request.url.replace("http://", "https://"))

app.secret_key = 'd3b07384d113edec49eaa6238ad5ff00c86c392bd62329c75b90dbd174ca03eb'
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def is_valid_username_or_password(item):
    return isinstance(item,str) and 1<=len(item)<=255 and re.match(r"^[a-zA-Z0-9\s.,'-]+$", item)

def init_db():
    conn = sqlite3.connect('fishing_app.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS user_data
    (user_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username TEXT NOT NULL, 
    password TEXT NOT NULL)
    ''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS posts
    (post_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    image_path TEXT NOT NULL,
    caption TEXT,
    FOREIGN KEY(user_id) REFERENCES user_data(user_id))
    ''')
    conn.commit()
    conn.close()

init_db() #calls the function to init the db

@app.route('/') #the main page, creates the home page
def index():
    conn = sqlite3.connect('fishing_app.db')
    cursor = conn.cursor()
    cursor.execute('SELECT posts.image_path, posts.caption, user_data.username FROM posts JOIN user_data ON posts.user_id = user_data.user_id ORDER BY posts.post_id DESC')
    posts = cursor.fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

@app.route('/login', methods=['POST', 'GET']) #called when someone tries to login after entering username and pw
def login():
    if request.method=='POST':
        username = request.form['username_entry']
        if not is_valid_username_or_password(username):
            flash('Invalid username, try again', 'error')
            return redirect('/login')
        password = request.form['password_entry']
        if not is_valid_username_or_password(password):
            flash('Invalid password, try again', 'error')
            return redirect('/login')
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM user_data WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect('/')
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login_page.html')


@app.route('/register', methods=['POST', 'GET']) #called when someone tries to register after entering username and pw
def register():
    if request.method == 'POST':
        username = request.form['username_entry']
        if not is_valid_username_or_password(username):
            flash('Invalid username, try again', 'error')
            return redirect('/login')
        password = request.form['password_entry']
        if not is_valid_username_or_password(password):
            flash('Invalid password, try again', 'error')
            return redirect('/login')
        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM user_data WHERE username = ?', (username,))
        user_exists = cursor.fetchone()[0] > 0
        if user_exists:
            flash('Username already exists.', 'error')
        else:
            cursor.execute('INSERT INTO user_data (username, password) VALUES (?, ?)', (username, hashed_password,))
            conn.commit()
            conn.close()
            return redirect('/login')
    return render_template('register_page.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('profile.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/identifier', methods=['GET'])
def fish_identifier():
    return render_template('identifier.html')

@app.route('/map', methods=['GET'])
def map():
    return render_template('map.html')

@app.route('/fish_dex', methods=['GET'])
def fish_dex():
    return render_template('fish_dex.html')

@app.route('/create_post', methods=['POST'])
def create_post():
    if 'user_id' not in session:
        return redirect('/login')
    
    image = request.files['image']
    caption = request.form.get('caption')
    
    if image:
        filename = secure_filename(image.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        relative_image_path = os.path.join('uploads', filename).replace("\\", "/")  # Store relative path
        image.save(image_path)
        
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO posts (user_id, image_path, caption) VALUES (?, ?, ?)', 
                       (session['user_id'], relative_image_path, caption))
        conn.commit()
        conn.close()
        
        flash('Post created successfully!', 'success')
        return redirect('/')
    else:
        flash('Failed to create post. Please try again.', 'error')
        return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('certs/cert.pem', 'certs/key.pem'), host="0.0.0.0", port=443)