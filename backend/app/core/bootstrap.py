import structlog
from sqlalchemy import select

from app.config import get_settings
from app.core.security import hash_password
from app.db.session import AsyncSessionLocal
from app.models.entities import User, UserRole

logger = structlog.get_logger(__name__)
settings = get_settings()


async def ensure_admin_user() -> None:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).limit(1))
        if result.scalar_one_or_none():
            return
        admin = User(
            email=settings.admin_email,
            hashed_password=hash_password(settings.admin_password),
            role=UserRole.ADMIN,
        )
        session.add(admin)
        await session.commit()
        logger.info("admin_user_created", email=settings.admin_email)
