import sqlite3
import re
from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape

app = Flask(__name__)
app.secret_key = 'd3b07384d113edec49eaa6238ad5ff00c86c392bd62329c75b90dbd174ca03eb'

def init_db(): #initialize the database
    conn = sqlite3.connect('fishing_app.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS user_data
    (user_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username TEXT NOT NULL, 
    password TEXT NOT NULL)
    ''')
    conn.commit()
    conn.close()

init_db() #calls the function to init the db

@app.route('/') #the main page, creates the home page
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST', 'GET']) #called when someone tries to login after entering username and pw
def login():
    if request.method=='POST':
        username = request.form['username_entry']
        password = request.form['password_entry']
        conn = sqlite3.connect('fishing_app.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM user_data WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect('/')
    return render_template('login_page.html')


@app.route('/register', methods=['POST', 'GET']) #called when someone tries to register after entering username and pw
def register():
    if request.method == 'POST':
        username = request.form['username_entry']
        password = request.form['password_entry']
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


@app.route('/fish_identifier', methods=['GET'])
def fish_identifier():
    pass

@app.route('/map', methods=['GET'])
def map():
    pass


@app.route('/fish_dex', methods=['GET'])
def fish_dex():
    pass

if __name__ == '__main__':
    app.run(debug=True)