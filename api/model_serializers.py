from flask import g, request

from app import db
from app.models import User, Account, Audit
from app.services.audit import AuditCreateService

class ModelSerializer(object):
    @classmethod
    def to_json(cls, obj):
        cls._record_audit(obj)
        return cls._to_json(obj)

    @classmethod
    def _to_json(cls):
        raise NotImplementedError

    @classmethod
    def _record_audit(cls, obj):
        if request.method == 'GET':
            audit_service = AuditCreateService()
            audit = audit_service.create_audit(obj, operation='view')
            if audit:
                db.session.add(audit)

class UserSerializer(ModelSerializer):
    @classmethod
    def _to_json(cls, obj):
        return {
            'id': obj.id,
            'email': obj.email,
            'first_name': obj.first_name,
            'last_name': obj.last_name
        }

class AccountSerializer(ModelSerializer):
    @classmethod
    def _to_json(cls, obj):
        return {
            'id': obj.id,
            'name': obj.name,
        }

class AuditSerializer(ModelSerializer):
    @classmethod
    def _to_json(cls, obj):
        return {
            'id': obj.id,
            'object_type': obj.object_type,
            'object_id': obj.object_id,
            'operation': obj.operation,
            'email': obj.email,
            'user_id': obj.user_id
        }

    @classmethod
    def _record_audit(cls, obj):
        '''
        No need to record audits for this table
        '''
        pass
