from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from src.database import User, db
from src.constants.http_status_codes import *
import validators


auth = Blueprint("auth", __name__, url_prefix='/api/v1/auth')

@auth.post('/register')
def register():

    data = request.json

    if 'username' not in data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'You should send the username, email and password'}), HTTP_400_BAD_REQUEST

    username = data['username']
    email = data['email']
    password = data['password']

    if len(password) < 6:
        return jsonify({'error': 'Password is too short'}), HTTP_400_BAD_REQUEST
    
    if len(username) < 3:
        return jsonify({'error': 'Username is too short'}), HTTP_400_BAD_REQUEST

    if not username.isalnum() or " " in username:
        return jsonify({'error': 'Username should be alphanumeric and also should not have spaces'}), HTTP_400_BAD_REQUEST
    
    if not (validators.email(email)):
        return jsonify({'error': 'Email is not valid'}), HTTP_400_BAD_REQUEST
    
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({'error': 'Email is taken'}), HTTP_409_CONFLICT
    
    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'error': 'Username is taken'}), HTTP_409_CONFLICT
    

    pwd_hash = generate_password_hash(password)
    

    user = User(username=username, password=pwd_hash, email=email)
    db.session.add(user)
    db.session.commit()

    return jsonify({
        'message': 'User Created',
        'user':{
            'username': username,
            'email': email,
        }
    }), HTTP_201_CREATED


@auth.get('/me')
def me():
    return {'user': 'me'}