"""A stable UI request reserves one existing task; synthetic dispatch only."""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from fastapi import HTTPException
from sqlmodel import Session, SQLModel, create_engine, select

from app.db.models import ExternalBusinessTask, utc_now
from staffdeck_harness.contracts.invocation import ModuleResult


@pytest.fixture
def tool_db(tmp_path):
    engine = create_engine(
        "sqlite:///" + str(tmp_path / "tools.db"),
        connect_args={"check_same_thread": False, "timeout": 5},
    )
    SQLModel.metadata.create_all(engine)
    yield engine
    engine.dispose()


def invoke(db, callback, **changes):
    from app.tools.tool_test_requests import run_tool_test_once

    return run_tool_test_once(
        db,
        tenant_id="t",
        user_id="u",
        tool_id="tool",
        agent_id="agent",
        client_request_id="stable-request-1",
        arguments={"value": 1},
        dispatch=callback,
        **changes,
    )


def test_same_request_reuses_receipt_and_completed_result(tool_db):
    calls = []
    with Session(tool_db) as db:
        first = invoke(
            db, lambda: calls.append("effect") or ModuleResult.ok({"answer": "synthetic"})
        )
        again = invoke(db, lambda: calls.append("DUPLICATE") or ModuleResult.ok())
        assert first.data["task_id"] == again.data["task_id"]
        task = db.get(ExternalBusinessTask, first.data["task_id"])
        assert task.status == "completed" and task.result_json == {"answer": "synthetic"}
        assert calls == ["effect"] and len(db.exec(select(ExternalBusinessTask)).all()) == 1


@pytest.mark.parametrize(
    "changed", [{"arguments": {"value": 2}}, {"tool_id": "different"}, {"agent_id": "other"}]
)
def test_same_client_key_with_changed_binding_conflicts(tool_db, changed):
    from app.tools.tool_test_requests import run_tool_test_once

    values = {
        "tenant_id": "t",
        "user_id": "u",
        "tool_id": "tool",
        "agent_id": "agent",
        "client_request_id": "same-key",
        "arguments": {"value": 1},
    }
    calls = []
    with Session(tool_db) as db:
        run_tool_test_once(db, **values, dispatch=lambda: calls.append(1) or ModuleResult.ok())
        with pytest.raises(HTTPException) as conflict:
            run_tool_test_once(
                db, **{**values, **changed}, dispatch=lambda: calls.append(2) or ModuleResult.ok()
            )
        assert conflict.value.status_code == 409 and calls == [1]


def test_concurrent_duplicates_claim_one_dispatch(tool_db):
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def run():
        with Session(tool_db) as db:

            def effect():
                calls.append(1)
                entered.set()
                assert release.wait(3)
                return ModuleResult.ok({"done": True})

            return invoke(db, effect)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run)
        assert entered.wait(2)
        second = pool.submit(run)
        duplicate = second.result(timeout=3)
        release.set()
        original = first.result(timeout=3)
    assert original.data["task_id"] == duplicate.data["task_id"] and calls == [1]


def test_unknown_failure_never_replays_after_restart_or_lease_expiry(tool_db):
    from app.tools.external_tasks import poll_due_external_tasks

    calls = []
    with Session(tool_db) as db:

        def uncertain():
            calls.append("effect")
            raise TimeoutError("synthetic response lost")

        first = invoke(db, uncertain)
        task = db.get(ExternalBusinessTask, first.data["task_id"])
        assert task.status == "outcome_unknown"
        task.lease_expires_at = utc_now() - timedelta(seconds=1)
        db.add(task)
        db.commit()
    with Session(tool_db) as db:
        poll_due_external_tasks(db)
        again = invoke(db, lambda: calls.append("DUPLICATE") or ModuleResult.ok())
        assert again.data["task_id"] == first.data["task_id"] and calls == ["effect"]
        assert db.get(ExternalBusinessTask, first.data["task_id"]).status == "outcome_unknown"


@pytest.mark.parametrize("status", ["cancelled", "expired", "outcome_unknown", "tracking_blocked"])
def test_terminal_and_unknown_states_never_reset_reservation(tool_db, status):
    calls = []
    with Session(tool_db) as db:
        first = invoke(db, lambda: ModuleResult.ok())
        task = db.get(ExternalBusinessTask, first.data["task_id"])
        task.status = status
        db.add(task)
        db.commit()
        again = invoke(db, lambda: calls.append(1) or ModuleResult.ok())
        assert again.data["status"] == status and calls == []


def test_claim_is_scoped_to_user_and_tenant(tool_db):
    from app.tools.tool_test_requests import run_tool_test_once

    ids = []
    calls = []
    with Session(tool_db) as db:
        for tenant, user in [("t", "u"), ("t", "u2"), ("other", "u")]:
            result = run_tool_test_once(
                db,
                tenant_id=tenant,
                user_id=user,
                tool_id="tool",
                agent_id=None,
                client_request_id="same-key",
                arguments={},
                dispatch=lambda: calls.append(1) or ModuleResult.ok(),
            )
            ids.append(result.data["task_id"])
    assert len(set(ids)) == 3 and calls == [1, 1, 1]


def test_native_login_tool_api_uses_one_transport_and_unknown_never_replays(tool_db, monkeypatch):
    from types import SimpleNamespace

    import httpx
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.agents.branching import ensure_open_gallery_binding
    from app.api import auth, external_business_tasks, tools
    from app.db import get_session
    from app.db.models import AgentProfile, Tenant, Tool, User
    from app.security.auth import hash_password
    from app.tools import tool_executor

    with Session(tool_db) as db:
        db.add(Tenant(id="t", name="Synthetic"))
        for uid in ("u", "other"):
            db.add(
                User(
                    id=uid,
                    tenant_id="t",
                    username=uid,
                    role="admin",
                    password_hash=hash_password("Synthetic-password-2026!"),
                )
            )
        db.add(AgentProfile(id="overall", tenant_id="t", name="Synthetic", is_overall=True))
        db.add(
            Tool(
                id="tool",
                tenant_id="t",
                name="synthetic.write",
                method="POST",
                url="https://synthetic-tool.example.test/effect",
            )
        )
        db.flush()
        ensure_open_gallery_binding(db, "t", "tool", "tool")
        db.commit()
    calls = []

    def effect(request):
        import json

        payload = json.loads(request.content)
        calls.append(payload)
        if payload.get("uncertain"):
            raise httpx.ReadTimeout("Synthetic side effect completed; response lost")
        return httpx.Response(200, json={"synthetic_effect_count": len(calls)})

    client = httpx.Client
    monkeypatch.setattr(
        tool_executor,
        "httpx",
        SimpleNamespace(
            Client=lambda **kw: client(**kw, transport=httpx.MockTransport(effect)),
            TimeoutException=httpx.TimeoutException,
            HTTPStatusError=httpx.HTTPStatusError,
        ),
    )
    app = FastAPI()
    app.include_router(auth.router)
    app.include_router(tools.router)
    app.include_router(external_business_tasks.enterprise_router)

    def database():
        with Session(tool_db) as db:
            yield db

    app.dependency_overrides[get_session] = database
    with TestClient(app) as api:
        headers = {}
        for uid in ("u", "other"):
            logged = api.post(
                "/api/auth/login",
                json={"tenant_id": "t", "username": uid, "password": "Synthetic-password-2026!"},
            )
            assert logged.status_code == 200
            headers[uid] = {"authorization": "Bearer " + logged.json()["token"]}
        path = "/api/enterprise/tools/tool/test"
        body = {"tenant_id": "t", "client_request_id": "known-key", "arguments": {"value": 1}}
        first = api.post(path, headers=headers["u"], json=body)
        assert first.status_code == 200, first.text
        again = api.post(path, headers=headers["u"], json=body)
        assert again.status_code == 200, again.text
        assert (
            first.json()["data"]["task_id"] == again.json()["data"]["task_id"] and len(calls) == 1
        )
        assert (
            api.post(
                path, headers=headers["u"], json={**body, "arguments": {"value": 2}}
            ).status_code
            == 409
        )
        body = {**body, "client_request_id": "unknown-key", "arguments": {"uncertain": True}}
        uncertain = api.post(path, headers=headers["u"], json=body)
        assert uncertain.status_code == 200, uncertain.text
        assert uncertain.json()["data"]["status"] == "outcome_unknown"
        assert (
            api.post(path, headers=headers["u"], json=body).json()["data"]["task_id"]
            == uncertain.json()["data"]["task_id"]
        )
        query = "/api/enterprise/tools/tool/test-requests/unknown-key?tenant_id=t"
        assert api.get(query, headers=headers["u"]).json()["status"] == "outcome_unknown"
        assert api.get(query, headers=headers["other"]).status_code == 404
        assert api.get(query).status_code == 401
        assert len(calls) == 2


def test_detached_enqueue_transfers_the_reserved_row_once(tool_db):
    from app.db.models import Tool
    from app.tools.tool_executor import ToolExecutor
    from app.tools.tool_test_requests import run_tool_test_once

    with Session(tool_db) as db:
        tool = Tool(
            id="tool",
            tenant_id="t",
            name="synthetic.detached",
            method="POST",
            url="https://synthetic-tool.example.test/task",
            config_json={"execution": {"execution_mode": "detached"}},
        )
        db.add(tool)
        db.commit()
        calls = []

        def dispatch():
            calls.append(1)
            claim = db.info["tool_test_claim"][0]
            result = ToolExecutor(db).enqueue_http(
                tool,
                {"value": 1},
                user_id="u",
                agent_id="resolved-agent",
                session_id="s",
                invocation_id=claim,
                task_frame_id=claim,
                resume_step_id=None,
                timeout_seconds_override=None,
            )
            return ModuleResult.ok(result.model_dump(mode="json"))

        params = {
            "tenant_id": "t",
            "user_id": "u",
            "tool_id": "tool",
            "agent_id": None,
            "client_request_id": "same-detached",
            "arguments": {"value": 1},
            "dispatch": dispatch,
        }
        first = run_tool_test_once(db, **params)
        second = run_tool_test_once(db, **params)
        assert first.data["task_id"] == second.data["task_id"] and calls == [1]
        rows = db.exec(select(ExternalBusinessTask)).all()
        assert len(rows) == 1 and rows[0].status == "queued"
        assert rows[0].agent_id == "resolved-agent" and rows[0].lease_owner is None


def test_restore_freezes_pending_tool_tests_instead_of_replaying_backup_state(tool_db):
    from app.tools.tool_test_requests import freeze_restored_tool_tests

    with Session(tool_db) as db:
        first = invoke(db, lambda: ModuleResult.ok({"done": True}))
        row = db.get(ExternalBusinessTask, first.data["task_id"])
        row.status = "queued"
        db.add(row)
        db.commit()
        assert freeze_restored_tool_tests(db) == 1
        assert freeze_restored_tool_tests(db) == 0
        called = []
        again = invoke(db, lambda: called.append(1) or ModuleResult.ok())
        assert again.data["status"] == "outcome_unknown" and called == []


def test_tool_restore_cli_runs_against_an_isolated_database_copy(tool_db):
    import os
    import subprocess
    import sys

    with Session(tool_db) as db:
        first = invoke(db, lambda: ModuleResult.ok())
        row = db.get(ExternalBusinessTask, first.data["task_id"])
        row.status = "submitting"
        db.add(row)
        db.commit()
    command = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.tools.tool_test_requests",
            "--database",
            tool_db.url.database,
            "--freeze-after-restore",
        ],
        env={**os.environ, "PYTHONPATH": "backend:backend/src"},
        capture_output=True,
        text=True,
        check=False,
        timeout=8,
    )
    assert command.returncode == 0, command.stderr
    with Session(tool_db) as db:
        assert db.get(ExternalBusinessTask, first.data["task_id"]).status == "outcome_unknown"
