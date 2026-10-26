import json

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import select
from test_data_policy import policy_case as policy_case  # noqa: PLC0414
from test_model_data_egress import PROTOCOLS, reply, setup_session

from app.db import get_session


@pytest.fixture
def login_case(policy_case, monkeypatch):
    from app.api import auth, data_policies, knowledge_answers, knowledge_governance
    from app.llm.client import LLMClient
    from app.security.auth import hash_password

    store, admin, member, _, _ = policy_case
    _, refs = setup_session(policy_case)
    for user in (admin, member):
        user.password_hash = hash_password("Synthetic-only-password-2026!")
        store.db.add(user)
    store.db.commit()
    sent = []
    selected = {"view_id": ""}

    def factory(model, **kwargs):
        return LLMClient(
            model,
            **kwargs,
            transport=httpx.MockTransport(
                lambda request: (
                    sent.append(request)
                    or httpx.Response(
                        200,
                        json=reply(PROTOCOLS[0], json.dumps({"view_ids": [selected["view_id"]]})),
                    )
                )
            ),
        )

    monkeypatch.setattr(data_policies, "model_client", factory)
    app = FastAPI()
    for router in (
        auth.router,
        data_policies.router,
        knowledge_answers.router,
        knowledge_governance.router,
    ):
        app.include_router(router)
    app.dependency_overrides[get_session] = lambda: store.db
    with TestClient(app) as api:
        tokens = {}
        for user in (admin, member):
            result = api.post(
                "/api/auth/login",
                json={
                    "tenant_id": "t",
                    "username": user.username,
                    "password": "Synthetic-only-password-2026!",
                },
            )
            assert result.status_code == 200
            tokens[user.id] = {"authorization": "Bearer " + result.json()["token"]}
        yield api, tokens, sent, selected, refs, policy_case


def test_actual_login_roles_and_existing_session_contract(login_case):
    api, tokens, sent, _, _, _ = login_case
    assert api.get("/api/auth/me").status_code == 401
    assert api.get("/api/auth/me", headers=tokens["admin"]).json()["role"] == "admin"
    assert api.get("/api/auth/me", headers=tokens["member"]).json()["role"] == "member"
    assert (
        api.post(
            "/api/auth/login", json={"tenant_id": "t", "username": "admin", "password": "wrong"}
        ).status_code
        == 401
    )
    assert (
        api.post(
            "/api/enterprise/data-policies/providers",
            headers=tokens["member"],
            json={
                "tenant_id": "t",
                "model_config_id": "model",
                "purposes": ["answer"],
                "terms_reference": "synthetic",
            },
        ).status_code
        == 403
    )
    assert api.post("/api/auth/refresh").status_code == 401
    assert api.post("/api/auth/logout", headers=tokens["member"]).status_code == 200
    # Local logout now durably revokes this token; no change to provider-owned auth.
    assert api.get("/api/auth/me", headers=tokens["member"]).status_code == 401
    assert sent == []


def test_member_controlled_answer_sends_approved_view_not_raw_document(login_case):
    api, tokens, sent, selected, refs, case = login_case
    from app.db.models import ProviderDataPolicy

    store, admin, _member, _, _ = case
    provider = store.db.exec(select(ProviderDataPolicy)).one()
    root = refs[-1]
    store.approve_source(
        admin,
        root,
        classification="public",
        answer_mode="controlled_answer",
        grants={provider.id: {"purposes": ["answer"], "representations": ["answer_view"]}},
    )
    view = store.derive("t", admin.id, "answer_view", "APPROVED_PUBLIC_ANSWER", [root])
    store.approve_source(
        admin,
        view,
        classification="public",
        answer_mode="controlled_answer",
        grants={provider.id: {"purposes": ["answer"], "representations": ["answer_view"]}},
    )
    selected["view_id"] = view.envelope_id
    response = api.post(
        "/api/enterprise/knowledge/answer-requests",
        headers=tokens["member"],
        json={
            "tenant_id": "t",
            "provider_policy_id": provider.id,
            "question": "SYNTHETIC_CONTROLLED_QUESTION",
            "document_ids": ["doc"],
            "answer_mode": "controlled_answer",
            "view_ids": [view.envelope_id],
        },
    )
    assert response.status_code == 200, response.text
    prepared = response.json()
    path = "/api/enterprise/knowledge/answer-requests/" + prepared["id"]
    approved = api.post(
        path + "/approve",
        headers=tokens["admin"],
        json={
            "tenant_id": "t",
            "review_digest": prepared["review_digest"],
            "classification": "public",
            "confirm": True,
        },
    )
    assert approved.status_code == 200, approved.text
    assert sent == []
    response = api.post(path + "/answer", headers=tokens["member"], json={"tenant_id": "t"})
    assert response.status_code == 200, response.text
    assert response.json()["answer"] == "APPROVED_PUBLIC_ANSWER"
    assert len(sent) == 1

    assert b"RAW_PRIVATE_MARKER" not in sent[0].content
    assert b"SYNTHETIC_CONTROLLED_QUESTION" in sent[0].content
    store.revoke_source(admin, view)
    assert (
        api.post(path + "/answer", headers=tokens["member"], json={"tenant_id": "t"}).status_code
        == 409
    )
    assert len(sent) == 1


def test_controlled_request_keeps_question_representation_raw(login_case):
    from app.db.models import ProviderDataPolicy
    from app.security.data_policy import PolicyContext
    from app.security.model_egress import ModelPolicySession

    _, _, _, _, refs, case = login_case
    store, admin, member, _, _ = case
    provider = store.db.exec(select(ProviderDataPolicy)).one()
    question = store.register_text("t", member.id, "input", "APPROVED_RAW_QUESTION")
    view = store.derive("t", admin.id, "answer_view", "APPROVED_VIEW", [refs[-1]])
    for ref, mode, reps in [
        (question, "answer_with_quote", ["raw"]),
        (view, "controlled_answer", ["answer_view"]),
    ]:
        store.approve_source(
            admin,
            ref,
            classification="public",
            answer_mode=mode,
            grants={provider.id: {"purposes": ["answer"], "representations": reps}},
        )
    intent = ModelPolicySession(
        store,
        PolicyContext("t", member.id, provider.id, "answer"),
        [refs[0], question, view],
        answer_mode="controlled_answer",
    )
    assert intent.intent.answer_mode == "controlled_answer"
