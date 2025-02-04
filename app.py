import sqlite3
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/access_login_page', methods=['GET'])
def access_login_page():
    return render_template('login_page.html')


@app.route('/fish_identifier', methods=['GET'])
def fish_identifier():
    pass

@app.route('/map', methods=['GET'])
def map():
    pass

@app.route('/login', methods=['POST'])
def login():
    pass

@app.route('/fish_dex', methods=['GET'])
def fish_dex():
    pass

if __name__ == '__main__':
    app.run(debug=True)