from app import db
from flask import g, request

from app.models import (
    Base,
    User,
    Account,
    Audit,
    )

from sqlalchemy import event

class AuditCreateService(object):
    def create_audit(self, db_object, operation):
        user = getattr(g, 'current_user', None)
        if not user:
            return None
        if type(db_object) == Audit:
            return None
        audit = Audit(
            user_id=user.id,
            email=user.email,
            object_type=db_object.__class__.__tablename__,
            object_id=db_object.id,
            operation=operation
        )
        return audit

@event.listens_for(db.session.__class__, 'before_flush')
def audit_edits(session, flush_context, instances):
    if not hasattr(g, 'to_audit'):
        g.to_audit = []

    current_user = getattr(g, 'current_user', None)
    if current_user and current_user in session.deleted:
        # No actions recorded for a user deleting themselves
        return

    audit_service = AuditCreateService()
    for obj in session.new:
        g.to_audit.append(obj)

    for obj in session.dirty:
        audit = audit_service.create_audit(obj, operation='edit')
        if audit:
            session.add(audit)

    for obj in session.deleted:
        audit = audit_service.create_audit(obj, operation='delete')
        if audit:
            session.add(audit)

@event.listens_for(db.session.__class__, 'before_commit')
def audit_new_objs(session):
    audit_service = AuditCreateService()
    for obj in getattr(g, 'to_audit', []):
        audit = audit_service.create_audit(obj, operation='create')
        if audit:
            session.add(audit)
