from flask import current_app

from app.models import User

from itsdangerous import JSONWebSignatureSerializer as Serializer, BadSignature
from passlib.hash import sha512_crypt as crypt

class AuthService(object):
    @classmethod
    def generate_auth_token(cls, user):
        serializer = Serializer(current_app.config['SECRET_KEY'])
        return serializer.dumps({'id': str(user.id)}).decode('ascii')

    @classmethod
    def verify_auth_token(cls, token):
        if not token:
            return None

        serializer = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = serializer.loads(token)
        except BadSignature:
            return None

        user = User.query.get(data['id'])
        return user

    @classmethod
    def check_password(cls, email, password):
        user = User.get_by_email(email)
        if not user:
            return None

        try:
            is_valid = crypt.verify(password, user.password)
            if is_valid:
                return user
            else:
                return None
        except ValueError:
            return None
