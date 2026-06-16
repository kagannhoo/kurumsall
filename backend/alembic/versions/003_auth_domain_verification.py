"""Auth, domain verification, encrypted cloud credentials

Revision ID: 003
Revises: 002
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE user_role AS ENUM ('admin', 'viewer');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
        """
    )

    user_role = postgresql.ENUM("admin", "viewer", name="user_role", create_type=False)

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()

    if "users" not in tables:
        op.create_table(
            "users",
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("hashed_password", sa.String(length=255), nullable=False),
            sa.Column("role", user_role, nullable=False, server_default="viewer"),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_users_email", "users", ["email"], unique=True)

    org_cols = {c["name"] for c in inspector.get_columns("organizations")}
    if "cloud_accounts_encrypted" not in org_cols:
        op.add_column("organizations", sa.Column("cloud_accounts_encrypted", sa.Text(), nullable=True))

    if "domain_verifications" not in tables:
        op.create_table(
            "domain_verifications",
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("organization_id", sa.UUID(), nullable=False),
            sa.Column("domain", sa.String(length=255), nullable=False),
            sa.Column("verification_token", sa.String(length=128), nullable=False),
            sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("organization_id", "domain", name="uq_domain_verification"),
        )


def downgrade() -> None:
    op.drop_table("domain_verifications")
    op.drop_column("organizations", "cloud_accounts_encrypted")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
    op.execute("DROP TYPE IF EXISTS user_role")
