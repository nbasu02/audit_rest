from app import db
from sqlalchemy import func
from sqlalchemy.dialects.postgresql.base import UUID

from passlib.hash import sha512_crypt as crypt

class Base(db.Model):
    __abstract__ = True

    id = db.Column(UUID, primary_key=True, server_default=func.uuid_generate_v4())
    created = db.Column(db.DateTime(timezone=True), nullable=False,
        server_default=func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=func.now(),
        server_onupdate=func.now())

    @classmethod
    def get_by_id(cls, id):
        return db.session.query(cls).filter(cls.id==id).first()

class User(Base):
    __tablename__ = 'user'
    first_name = db.Column(db.Text)
    last_name = db.Column(db.Text)
    email = db.Column(db.Text, nullable=False)
    _password = db.Column('password', db.Text, nullable=False)

    @property
    def password(self):
        return self._password
    @password.setter
    def password(self, password):
        self._password = str(crypt.encrypt(password))

    @classmethod
    def get_by_email(cls, email):
        return db.session.query(cls).filter(cls.email==email).first()

class Account(Base):
    __tablename__ = 'account'

    name = db.Column(db.Text, nullable=False)

class Audit(Base):
    __tablename__ = 'audit'

    object_type = db.Column(db.Text, nullable=False)
    object_id = db.Column(UUID, nullable=False)
    operation = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False)
    user_id = db.Column(UUID, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship(
        'User',
        backref=db.backref(
            'audits',
            cascade='all, delete-orphan'
            ),
        )
