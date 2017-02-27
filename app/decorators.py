from flask import g, abort, request

from app.models import User
from app.services.auth import AuthService

from webargs import fields
from webargs.flaskparser import parser as arg_parse
from functools import wraps

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_token_args = {'auth_token': fields.Str(required=True)}
        content = arg_parse.parse(auth_token_args, request)
        auth_token = content.get('auth_token')
        current_user = AuthService.verify_auth_token(auth_token)
        if not current_user:
            abort(403)
        g.current_user = current_user
        return f(*args, **kwargs)
    return decorated_function
