from app import app, db
from app.decorators import auth_required
from app.models import User, Account, Audit
from app.services.auth import AuthService
from api.model_serializers import (
    UserSerializer,
    AccountSerializer,
    AuditSerializer
    )

from flask import request, g
from flask_restplus import Resource, Api
from webargs import fields
from webargs.flaskparser import parser as arg_parse

api = Api(app, version='1.0', default='api')

@api.route('/auth', methods=['POST', 'PUT'])
class Auth(Resource):
    @api.doc(params={
        'email': 'Email',
        'password': 'Password'
    })
    def post(self):
        '''
        Log in user, returns auth_token to use in other requests
        '''
        args = {
            'email': fields.Str(required=True),
            'password': fields.Str(required=True),
        }
        content = arg_parse.parse(args, request)
        user = AuthService.check_password(
            content['email'],
            content['password']
            )
        if user:
            auth_token = AuthService.generate_auth_token(user)
            user_json = UserSerializer.to_json(user)
        else:
            auth_token = None
            user_json = None

        return {
            'auth_token': auth_token,
            'user': user_json
            }

    @api.doc(params={
        'email': 'Email',
        'password': 'Password',
        'first_name': 'First name',
        'last_name': 'Last name'
    })
    def put(self):
        '''
        Create new user, returning an auth_token for them to use
        '''
        args = {
            'first_name': fields.Str(required=True),
            'last_name': fields.Str(required=True),
            'email': fields.Str(required=True),
            'password': fields.Str(required=True),
        }
        content = arg_parse.parse(args, request)

        user = User(**content)
        db.session.add(user)
        db.session.flush()
        auth_token = AuthService.generate_auth_token(user)
        return {
            'auth_token': auth_token,
            'user': UserSerializer.to_json(user)
            }

@api.route('/users', methods=['GET', 'PUT'])
class UserListView(Resource):
    @auth_required
    @api.doc(params={'auth_token': 'auth_token from /auth'})
    def get(self):
        '''
        List all users
        '''
        users = db.session.query(User).all()
        user_response = [UserSerializer.to_json(user) for user in users]
        return {'users': user_response}

    @api.doc(params={
        'email': 'Email',
        'password': 'Password',
        'first_name': 'First name',
        'last_name': 'Last name'
    })
    @auth_required
    @api.doc(params={'auth_token': 'auth_token from /auth'})
    def put(self):
        '''
        Create user
        '''

        args = {
            'first_name': fields.Str(required=True),
            'last_name': fields.Str(required=True),
            'email': fields.Str(required=True),
            'password': fields.Str(required=True),
        }
        content = arg_parse.parse(args, request)

        user = User(**content)
        db.session.add(user)
        db.session.flush()
        auth_token = AuthService.generate_auth_token(user)

        return {
            'user': UserSerializer.to_json(user)
        }

@api.route('/users/<id>', methods=['GET', 'POST', 'DELETE'])
class UserView(Resource):
    @auth_required
    @api.doc(params={'auth_token': 'auth_token from /auth'})
    def get(self, id):
        '''
        View user attributes
        '''
        user = User.query.get_or_404(id)
        return {
            'user': UserSerializer.to_json(user)
        }

    @auth_required
    @api.doc(params={
        'auth_token': 'auth_token from /auth',
        'email': 'Email',
        'first_name': 'First Name',
        'last_name': 'Last Name',
        'password': 'Password'
    })
    def post(self, id):
        '''
        Update user.  All attributes required
        '''
        user = User.query.get_or_404(id)

        args = {
            'first_name': fields.Str(required=True),
            'last_name': fields.Str(required=True),
            'email': fields.Str(required=True),
            'password': fields.Str(required=True),
        }
        content = arg_parse.parse(args, request)
        for attr, value in content.items():
            setattr(user, attr, value)
        db.session.flush()
        return {
            'user': UserSerializer.to_json(user)
        }

    @auth_required
    @api.doc(params={
        'auth_token': 'auth_token from /auth',
    })
    def delete(self, id):
        '''
        Delete user (for this example, any user can delete another user).
        '''

        user = User.query.get_or_404(id)
        db.session.delete(user)

        return {'deleted': True}

@api.route('/accounts', methods=['GET', 'PUT'])
class AccountListView(Resource):
    @auth_required
    @api.doc(params={
        'auth_token': 'auth_token from /auth',
    })
    def get(self):
        '''
        List all accounts
        '''

        accounts = db.session.query(Account).all()
        account_response = [
            AccountSerializer.to_json(account) for account in accounts
            ]
        return {'users': account_response}

    @auth_required
    @api.doc(params={
        'auth_token': 'auth_token from /auth',
        'name': 'Account Name',
    })
    def put(self):
        '''
        Create account
        '''

        args = {
            'name': fields.Str(required=True)
        }
        content = arg_parse.parse(args, request)
        account = Account(**content)
        db.session.add(account)
        db.session.flush()

        return {
            'account': AccountSerializer.to_json(account)
        }

@api.route('/accounts/<id>', methods=['GET', 'POST', 'DELETE'])
class AccountView(Resource):
    @auth_required
    @api.doc(params={
        'auth_token': 'auth_token from /auth',
    })
    def get(self, id):
        '''
        Get a single account
        '''

        account = Account.query.get_or_404(id)
        return {
            'account': AccountSerializer.to_json(account)
        }

    @auth_required
    @api.doc(params={
        'auth_token': 'auth_token from /auth',
        'name': 'Account Name',
    })
    def post(self, id):
        '''
        Edit account
        '''
        account = Account.query.get_or_404(id)

        args = {
            'name': fields.Str(required=True)
        }
        content = arg_parse.parse(args, request)
        account.name = content['name']
        db.session.flush()
        return {
            'account': AccountSerializer.to_json(account)
        }

    @auth_required
    @api.doc(params={
        'auth_token': 'auth_token from /auth',
    })
    def delete(self, id):
        '''
        Delete account
        '''

        account = Account.query.get_or_404(id)
        db.session.delete(account)
        return {'deleted': True}

@api.route('/audits/<model>/<id>', methods=['GET'])
class AuditView(Resource):
    def get(self, model, id):
        '''
        Gets all audits for an object, given the db model and its id
        '''

        audits = db.session.query(Audit).filter(
            Audit.object_type==model,
            Audit.object_id==id
        ).order_by(
            Audit.created.desc()
        ).all()

        audit_response = [AuditSerializer.to_json(audit) for audit in audits]
        return {
            'audits': audit_response
        }

@api.route('/users/<id>/audits/', methods=['GET'])
class AuditsByUserId(Resource):
    def get(self, id):
        audits = db.session.query(Audit).filter(
            Audit.user_id==id
        ).order_by(
            Audit.created.desc()
        ).all()

        audit_response = [AuditSerializer.to_json(audit) for audit in audits]
        return {
            'audits': audit_response
        }

@api.route('/users/audits/', methods=['GET'])
class AuditsByUserEmail(Resource):
    @api.doc(params={'email': 'User email address'})
    def get(self):
        args = {'email': fields.Str(required=True)}
        content = arg_parse.parse(args, request)

        audits = db.session.query(Audit).filter(
            Audit.email==content['email']
        ).order_by(
            Audit.created.desc()
        ).all()

        audit_response = [AuditSerializer.to_json(audit) for audit in audits]
        return {
            'audits': audit_response
        }
