"""Native local-auth lifecycle with durable SQLite, no identity/token mocks."""

import time

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from app.api import auth as api_auth
from app.db import get_session
from app.db.models import Tenant, User
from app.security.auth import create_access_token, hash_password


@pytest.fixture
def sessions(tmp_path):
    url = "sqlite:///" + str(tmp_path / "sessions.db")
    engine = create_engine(url, connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as db:
        for tenant, uid in [("t", "a"), ("t", "b"), ("other", "c")]:
            if db.get(Tenant, tenant) is None:
                db.add(Tenant(id=tenant, name="Synthetic"))
            db.add(
                User(
                    id=uid,
                    tenant_id=tenant,
                    username=uid,
                    role="admin",
                    password_hash=hash_password("Synthetic-password-2026!"),
                )
            )
        db.commit()

    def client(bind):
        app = FastAPI()
        app.include_router(api_auth.router)

        def database():
            with Session(bind) as db:
                yield db

        app.dependency_overrides[get_session] = database
        return TestClient(app)

    with client(engine) as api:

        def login(uid="a", tenant="t"):
            r = api.post(
                "/api/auth/login",
                json={"tenant_id": tenant, "username": uid, "password": "Synthetic-password-2026!"},
            )
            assert r.status_code == 200
            return r.json()

        yield api, login, engine, url, client
    engine.dispose()


def bearer(token):
    return {"authorization": "Bearer " + token}


def test_logout_replay_is_denied_without_revoking_other_sessions_or_users(sessions):
    api, login, _, _, _ = sessions
    a1 = login()
    a2 = login()
    b = login("b")
    c = login("c", "other")
    assert a1["token"] != a2["token"]
    assert api.post("/api/auth/logout", headers=bearer(a1["token"])).status_code == 200
    assert api.get("/api/auth/me", headers=bearer(a1["token"])).status_code == 401
    for row in [a2, b, c]:
        assert api.get("/api/auth/me", headers=bearer(row["token"])).status_code == 200
    assert api.post("/api/auth/logout", headers=bearer(a1["token"])).status_code == 200
    assert api.get("/api/auth/me", headers=bearer(login()["token"])).status_code == 200


def test_logout_survives_new_engine_and_app(sessions):
    api, login, engine, url, client = sessions
    token = login()["token"]
    assert api.post("/api/auth/logout", headers=bearer(token)).status_code == 200
    engine.dispose()
    restarted = create_engine(url, connect_args={"check_same_thread": False})
    with client(restarted) as second:
        assert second.get("/api/auth/me", headers=bearer(token)).status_code == 401
    restarted.dispose()


def test_revoked_token_denied_by_public_bootstrap_and_cached_compat(sessions, monkeypatch):
    import app.db
    from app.api_enterprise import compat
    from app.public_api.auth import _bootstrap_principal

    api, login, engine, _, _ = sessions
    monkeypatch.setattr(app.db, "engine", engine)
    token = login()["token"]
    with Session(engine) as db:
        assert _bootstrap_principal(token, db).actor_user.id == "a"
    assert compat._resolve_actor(token).user_id == "a"
    assert api.post("/api/auth/logout", headers=bearer(token)).status_code == 200
    with Session(engine) as db:
        with pytest.raises(HTTPException) as denied:
            _bootstrap_principal(token, db)
        assert denied.value.status_code == 401
    assert compat._resolve_actor(token) is None


def test_local_refresh_explicitly_requires_relogin_and_never_issues_token(sessions):
    api, login, _, _, _ = sessions
    signed = login()
    assert signed["refresh_mode"] == "none"
    r = api.post("/api/auth/refresh", headers=bearer(signed["token"]))
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "LOCAL_REFRESH_UNAVAILABLE"
    assert "token" not in r.json()


def test_restore_fence_invalidates_old_tokens_and_preserves_new_logins(sessions):
    from app.security.auth_sessions import invalidate_restored_sessions

    api, login, engine, _, _ = sessions
    old = login()["token"]
    with Session(engine) as db:
        invalidate_restored_sessions(db)
    assert api.get("/api/auth/me", headers=bearer(old)).status_code == 401
    assert api.get("/api/auth/me", headers=bearer(login()["token"])).status_code == 200
    with Session(engine) as db:
        legacy = create_access_token(db.get(User, "a"))
    # Signing a fresh token after the fence is still valid; no TTL shortening.
    assert api.get("/api/auth/me", headers=bearer(legacy)).status_code == 200


def test_cross_origin_logout_does_not_revoke_token(sessions):
    api, login, _, _, _ = sessions
    token = login()["token"]
    assert (
        api.post(
            "/api/auth/logout", headers={**bearer(token), "origin": "https://other.example.test"}
        ).status_code
        == 403
    )
    assert api.get("/api/auth/me", headers=bearer(token)).status_code == 200


def test_revocation_storage_contains_hashes_not_bearer_values(sessions):
    from sqlalchemy import text

    api, login, engine, _, _ = sessions
    token = login()["token"]
    assert api.post("/api/auth/logout", headers=bearer(token)).status_code == 200
    with Session(engine) as db:
        rows = db.exec(text("SELECT * FROM local_token_revocations")).all()
        assert len(rows) == 1 and token not in str(rows) and len(rows[0][0]) == 64


def test_restore_cli_is_runnable_on_a_database_copy(sessions):
    import os
    import subprocess
    import sys

    api, login, _, url, _ = sessions
    old = login()["token"]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.security.auth_sessions",
            "--database",
            url.removeprefix("sqlite:///"),
            "--invalidate-after-restore",
        ],
        env={**os.environ, "PYTHONPATH": "backend:backend/src"},
        check=False,
        capture_output=True,
        text=True,
        timeout=8,
    )
    assert result.returncode == 0, result.stderr
    assert api.get("/api/auth/me", headers=bearer(old)).status_code == 401
    assert api.get("/api/auth/me", headers=bearer(login()["token"])).status_code == 200


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"exp": "bad"},
        {"exp": True},
        {"exp": time.time() + 60},
        {"tenant_id": "t", "user_id": "a", "exp": 0},
    ],
)
def test_signed_malformed_or_expired_tokens_are_401(sessions, payload):
    import json

    from app.security.auth import _b64, _sign

    api, _, _, _, _ = sessions
    body = _b64(json.dumps(payload).encode())
    token = body + "." + _sign(body)
    assert api.get("/api/auth/me", headers=bearer(token)).status_code == 401


def test_expired_native_session_can_logout_without_becoming_stuck(sessions, monkeypatch):
    from app.security import auth
    api, login, _, _, _ = sessions
    token = login()['token']
    now = time.time()
    monkeypatch.setattr(auth.time, 'time', lambda: now + auth.TOKEN_TTL_SECONDS + 1)
    assert api.get('/api/auth/me', headers=bearer(token)).status_code == 401
    assert api.post('/api/auth/logout', headers=bearer(token)).status_code == 200
    assert api.get('/api/auth/me', headers=bearer(token)).status_code == 401
