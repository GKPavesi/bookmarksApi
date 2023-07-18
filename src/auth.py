from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from src.database import User, db
from src.constants.http_status_codes import *
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flasgger import swag_from
import validators


auth = Blueprint("auth", __name__, url_prefix='/api/v1/auth')

@auth.post('/register')
@swag_from('./docs/auth/register.yaml')
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


@auth.post('/login')
@swag_from('./docs/auth/login.yaml')
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    if email is None or password is None:
        return jsonify({'error': 'You should send the email and password to login'}), HTTP_400_BAD_REQUEST
    
    user = User.query.filter_by(email=email).first()

    if user:
        is_password_correct = check_password_hash(user.password, password)

        if is_password_correct:
            refresh = create_refresh_token(identity=user.id)
            access = create_access_token(identity=user.id)

            return jsonify({
                'user': {
                    'refresh': refresh,
                    'access': access,
                    'username': user.username,
                    'email': user.email
                }
            }), HTTP_200_OK
        else:
            return jsonify({'error': 'wrong credencials'}), HTTP_401_UNAUTHORIZED
        
    else:
        return jsonify({'error': 'user does not exists'}), HTTP_401_UNAUTHORIZED



@auth.get('/me')
@jwt_required()
def me():
    user_id = get_jwt_identity()

    user = User.query.filter_by(id=user_id).first()

    return jsonify({
        'username': user.username,
        'email': user.email
    }), HTTP_200_OK

@auth.get('/token/refresh')
@jwt_required(refresh=True)
def refresh_users_token():
    identity = get_jwt_identity()
    access = create_access_token(identity=identity)

    return jsonify({
        'access': access
    }), HTTP_200_OK