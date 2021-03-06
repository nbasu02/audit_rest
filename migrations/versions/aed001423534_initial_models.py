"""Initial models

Revision ID: aed001423534
Revises:
Create Date: 2017-02-25 11:03:30.690538

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'aed001423534'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

    op.create_table('account',
    sa.Column('id', postgresql.UUID(), server_default=sa.text(u'uuid_generate_v4()'), nullable=False),
    sa.Column('created', sa.DateTime(timezone=True), server_default=sa.text(u'now()'), nullable=False),
    sa.Column('updated', sa.DateTime(timezone=True), server_default=sa.text(u'now()'), nullable=True),
    sa.Column('name', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', postgresql.UUID(), server_default=sa.text(u'uuid_generate_v4()'), nullable=False),
    sa.Column('created', sa.DateTime(timezone=True), server_default=sa.text(u'now()'), nullable=False),
    sa.Column('updated', sa.DateTime(timezone=True), server_default=sa.text(u'now()'), nullable=True),
    sa.Column('first_name', sa.Text(), nullable=True),
    sa.Column('last_name', sa.Text(), nullable=True),
    sa.Column('email', sa.Text(), nullable=False),
    sa.Column('password', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('audit',
    sa.Column('id', postgresql.UUID(), server_default=sa.text(u'uuid_generate_v4()'), nullable=False),
    sa.Column('created', sa.DateTime(timezone=True), server_default=sa.text(u'now()'), nullable=False),
    sa.Column('updated', sa.DateTime(timezone=True), server_default=sa.text(u'now()'), nullable=True),
    sa.Column('object_type', sa.Text(), nullable=False),
    sa.Column('object_id', postgresql.UUID(), nullable=False),
    sa.Column('operation', sa.Text(), nullable=False),
    sa.Column('email', sa.Text(), nullable=False),
    sa.Column('user_id', postgresql.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('audit')
    op.drop_table('user')
    op.drop_table('account')
    # ### end Alembic commands ###
