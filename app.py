import jwt
from flask import Flask, request, jsonify, make_response, render_template, session, flash
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '93a43d2be8eb4e77b7754684bf110ca1'
app.secret_key = app.config['SECRET_KEY']  # Set secret key for session handling


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert!': 'Token is missing'}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'Alert!': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'Alert!': 'Invalid Token'}), 401
        return func(*args, **kwargs)  # Correctly return the wrapped function
    return decorated


@app.route('/public')
def ppublic():
    return 'This is a public page'


@app.route('/auth')
@token_required
def auth():
    return 'You are verified. Welcome to your dashboard!'


@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return 'Logged in currently'


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username and password == '123456':  # Fix incorrect comparison
        session['logged_in'] = True
        token = jwt.encode({
            'user': username,
            'exp': datetime.utcnow() + timedelta(seconds=150)  # Use 'exp' for expiry
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({'token': token})  # No need for `.decode('utf-8')`
    else:
        return make_response('Unable to verify', 403, {
            'WWW-Authenticate': 'Basic realm="Authentication Failed!"'
        })


if __name__ == '__main__':
    app.run(debug=True)
