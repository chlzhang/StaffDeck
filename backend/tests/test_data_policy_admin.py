"""Administrator-only policy mutations; user uploads cannot mint approvals."""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import select
from test_data_policy import policy_case as policy_case  # noqa: PLC0414

from app.db import get_session
from app.db.models import DataResourcePolicy, ProviderDataPolicy
from app.security.auth import get_current_user


def api(case):
    from app.api.data_policies import router

    store, _admin, member, _, _ = case
    actor = {"user": member}
    app = FastAPI()
    app.include_router(router)

    def session():
        yield store.db

    app.dependency_overrides[get_session] = session
    app.dependency_overrides[get_current_user] = lambda: actor["user"]
    return TestClient(app), actor


def test_member_cannot_approve_provider(policy_case):
    client, _ = api(policy_case)
    response = client.post(
        "/api/enterprise/data-policies/providers",
        json={
            "tenant_id": "t",
            "model_config_id": "model",
            "purposes": ["answer"],
            "classifications": ["public"],
            "terms_reference": "synthetic-only",
        },
    )
    assert response.status_code == 403
    assert policy_case[0].db.exec(select(ProviderDataPolicy)).all() == []


def test_input_rejects_forged_policy_and_is_unclassified(policy_case):
    client, _ = api(policy_case)
    response = client.post(
        "/api/enterprise/data-policies/inputs",
        json={
            "tenant_id": "t",
            "text": "synthetic question",
            "classification": "public",
            "approved_by": "admin",
        },
    )
    assert response.status_code == 422
    response = client.post(
        "/api/enterprise/data-policies/inputs",
        json={
            "tenant_id": "t",
            "text": "synthetic question",
        },
    )
    assert response.status_code == 200
    assert policy_case[0].db.get(DataResourcePolicy, response.json()["envelope_id"]) is None


def test_admin_can_approve_and_revoke_exact_document_envelope(policy_case):
    client, actor = api(policy_case)
    response = client.post(
        "/api/enterprise/data-policies/documents/doc/register", params={"tenant_id": "t"}
    )
    assert response.status_code == 200
    assert "RAW_PRIVATE_MARKER" not in response.text
    ref = response.json()
    body = {
        "tenant_id": "t",
        "classification": "public",
        "answer_mode": "answer_with_quote",
        "grants": {},
        "revision": ref["revision"],
    }
    path = "/api/enterprise/data-policies/sources/" + ref["envelope_id"]
    assert client.put(path, json=body).status_code == 403
    actor["user"] = policy_case[1]
    assert client.put(path, json=body).status_code == 200
    assert client.post(path + "/revoke", json={"tenant_id": "t"}).status_code == 200
    assert not policy_case[0].db.get(DataResourcePolicy, ref["envelope_id"]).active


def test_provider_approval_requires_terms_reference(policy_case):
    client, actor = api(policy_case)
    actor["user"] = policy_case[1]
    response = client.post(
        "/api/enterprise/data-policies/providers",
        json={
            "tenant_id": "t",
            "model_config_id": "model",
            "purposes": ["answer"],
        },
    )
    assert response.status_code == 422
