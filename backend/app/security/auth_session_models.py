"""Additive local-auth metadata; no user or installation secret changes."""

import time

from sqlmodel import Field, SQLModel


class LocalTokenRevocation(SQLModel, table=True):
    __tablename__ = "local_token_revocations"
    token_digest: str = Field(primary_key=True)
    tenant_id: str = Field(index=True)
    user_id: str = Field(index=True)
    expires_at: int = Field(index=True)
    revoked_at: float = Field(default_factory=time.time)


class LocalAuthFence(SQLModel, table=True):
    __tablename__ = "local_auth_fence"
    id: str = Field(default="restore", primary_key=True)
    not_before: float
