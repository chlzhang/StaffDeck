"""Durable local token revocation. Store hashes only; never retain bearer tokens."""

from __future__ import annotations

import hashlib
import time

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import SQLModel

from app.security.auth_session_models import LocalAuthFence, LocalTokenRevocation


def validate_local_session(db, token, payload):
    try:
        revoked = db.get(
            LocalTokenRevocation, hashlib.sha256(token.encode()).hexdigest(), populate_existing=True
        )
        fence = db.get(LocalAuthFence, "restore", populate_existing=True)
        if revoked is not None or (fence is not None and payload.get("iat", 0) <= fence.not_before):
            raise HTTPException(401, "Session revoked; please sign in again")
    except SQLAlchemyError as exc:
        raise HTTPException(503, "Session validation unavailable") from exc


def revoke_local_session(db, token, payload):
    # SQLite is the supported deployment database. Concurrent/idempotent logout
    # must not turn a unique-key race into a successful unpersisted revocation.
    db.exec(
        insert(LocalTokenRevocation)
        .values(
            token_digest=hashlib.sha256(token.encode()).hexdigest(),
            tenant_id=payload["tenant_id"],
            user_id=payload["user_id"],
            expires_at=payload["exp"],
            revoked_at=time.time(),
        )
        .on_conflict_do_nothing(index_elements=["token_digest"])
    )
    db.commit()


def invalidate_restored_sessions(db):
    """Offline restore interlock; all previously issued local tokens must re-login."""
    cutoff = time.time()
    db.exec(
        insert(LocalAuthFence)
        .values(id="restore", not_before=cutoff)
        .on_conflict_do_update(
            index_elements=["id"], set_={"not_before": func.max(LocalAuthFence.not_before, cutoff)}
        )
    )
    db.commit()


def main():
    import argparse
    from pathlib import Path

    from sqlmodel import Session, create_engine

    # Register all existing tables without changing user/secret data.
    import app.db.models  # noqa: F401

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--invalidate-after-restore", action="store_true", required=True)
    args = parser.parse_args()
    engine = create_engine("sqlite:///" + str(args.database.resolve(strict=True)))
    try:
        SQLModel.metadata.create_all(engine)
        with Session(engine) as db:
            invalidate_restored_sessions(db)
        print("Previously issued local sessions invalidated; sign in again.")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
