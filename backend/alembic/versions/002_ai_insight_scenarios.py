"""AI insight attack scenarios columns

Revision ID: 002
Revises: 001
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "ai_insights",
        sa.Column("attack_scenarios", postgresql.JSONB(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "ai_insights",
        sa.Column("action_items", postgresql.JSONB(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "ai_insights",
        sa.Column("ollama_connected", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )


def downgrade() -> None:
    op.drop_column("ai_insights", "ollama_connected")
    op.drop_column("ai_insights", "action_items")
    op.drop_column("ai_insights", "attack_scenarios")
