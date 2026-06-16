"""initial schema

Revision ID: 001
Revises:
Create Date: 2026-06-16
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")

    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(128), nullable=False),
        sa.Column("root_domains", postgresql.JSONB(), nullable=False),
        sa.Column("cloud_accounts", postgresql.JSONB(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)

    op.execute("""
        CREATE TYPE asset_type AS ENUM (
            'domain', 'subdomain', 'port', 'ssl_cert', 'cloud_resource', 'vulnerability'
        )
    """)
    op.execute("""
        CREATE TYPE change_type AS ENUM ('added', 'removed', 'modified')
    """)
    op.execute("""
        CREATE TYPE risk_level AS ENUM ('low', 'medium', 'high', 'critical')
    """)
    op.execute("""
        CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed')
    """)

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_type", postgresql.ENUM(name="asset_type", create_type=False), nullable=False),
        sa.Column("identifier", sa.String(512), nullable=False),
        sa.Column("display_name", sa.String(512), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.UniqueConstraint("organization_id", "asset_type", "identifier", name="uq_asset_identity"),
    )
    op.create_index("ix_assets_org_type", "assets", ["organization_id", "asset_type"])

    op.create_table(
        "scan_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", postgresql.ENUM(name="scan_status", create_type=False), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("asset_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("scan_metadata", postgresql.JSONB(), nullable=True),
    )
    op.create_index("ix_scan_runs_org_started", "scan_runs", ["organization_id", "started_at"])

    op.create_table(
        "asset_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_type", postgresql.ENUM(name="asset_type", create_type=False), nullable=False),
        sa.Column("identifier", sa.String(512), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("risk_level", postgresql.ENUM(name="risk_level", create_type=False), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.UniqueConstraint("scan_run_id", "asset_id", name="uq_snapshot_per_scan"),
    )
    op.create_index("ix_snapshots_scan_type", "asset_snapshots", ["scan_run_id", "asset_type"])

    op.create_table(
        "change_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("change_type", postgresql.ENUM(name="change_type", create_type=False), nullable=False),
        sa.Column("asset_type", postgresql.ENUM(name="asset_type", create_type=False), nullable=False),
        sa.Column("identifier", sa.String(512), nullable=False),
        sa.Column("previous_value", postgresql.JSONB(), nullable=True),
        sa.Column("current_value", postgresql.JSONB(), nullable=True),
        sa.Column("risk_level", postgresql.ENUM(name="risk_level", create_type=False), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("summary", sa.String(1024), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_changes_scan_type", "change_events", ["scan_run_id", "change_type"])

    op.create_table(
        "risk_assessments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("total_assets", sa.Integer(), nullable=False),
        sa.Column("previous_total_assets", sa.Integer(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("previous_risk_score", sa.Float(), nullable=True),
        sa.Column("risk_delta_percent", sa.Float(), nullable=True),
        sa.Column("breakdown", postgresql.JSONB(), nullable=False),
        sa.Column("assessed_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    op.create_table(
        "ai_insights",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("risk_commentary", sa.Text(), nullable=False),
        sa.Column("recommendations", postgresql.JSONB(), nullable=False),
        sa.Column("model_name", sa.String(128), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("ai_insights")
    op.drop_table("risk_assessments")
    op.drop_table("change_events")
    op.drop_table("asset_snapshots")
    op.drop_table("scan_runs")
    op.drop_table("assets")
    op.drop_table("organizations")
    op.execute("DROP TYPE IF EXISTS scan_status")
    op.execute("DROP TYPE IF EXISTS risk_level")
    op.execute("DROP TYPE IF EXISTS change_type")
    op.execute("DROP TYPE IF EXISTS asset_type")
