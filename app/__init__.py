from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError

app = Flask(__name__)

class Config(object):
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:postgres@localhost/opsline'
    SECRET_KEY = 'cdkfnvjkfnvfdnlvdfklvmvmp2r29rhf9r9gprmprempovferpom'
    SQLALCHEMY_TRACK_MODIFICATIONS = True

app.config.from_object(Config())

db = SQLAlchemy()
db.init_app(app)
from models import *
from api.views import *
from app.services.audit import audit_edits, audit_new_objs

@app.after_request
def after_request(response):
    try:
        db.session.commit()
    except SQLAlchemyError as err:
        db.session.rollback()
        raise err
    return response
