import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import select
from test_data_policy import policy_case as policy_case  # noqa: PLC0414
from test_model_data_egress import PROTOCOLS, reply, setup_session

from app.db import get_session
from app.db.models import DataResourcePolicy, User
from app.security.auth import get_current_user


@pytest.fixture(params=PROTOCOLS)
def product_case(policy_case, monkeypatch, request):
    from app.api import data_policies, knowledge_answers
    from app.llm.client import LLMClient

    protocol = request.param
    session, _ = setup_session(policy_case, protocol)
    store = policy_case[0]
    actor = {"user": policy_case[2]}
    sent = []

    def factory(model, **kwargs):
        return LLMClient(
            model,
            **kwargs,
            transport=httpx.MockTransport(
                lambda r: (
                    sent.append(r) or httpx.Response(200, json=reply(protocol, "PRODUCT_ANSWER"))
                )
            ),
        )

    monkeypatch.setattr(data_policies, "model_client", factory)
    app = FastAPI()
    app.include_router(knowledge_answers.router)
    app.dependency_overrides[get_session] = lambda: store.db
    app.dependency_overrides[get_current_user] = lambda: actor["user"]
    with TestClient(app) as api:
        yield api, actor, sent, session, policy_case


def prepare(case):
    api, _, _, session, _ = case
    response = api.post(
        "/api/enterprise/knowledge/answer-requests",
        json={
            "tenant_id": "t",
            "provider_policy_id": session.context.provider_policy_id,
            "question": "SYNTHETIC_PRODUCT_QUESTION",
            "document_ids": ["doc"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_product_prepare_review_and_answer_are_separate_actions(product_case):
    api, actor, sent, session, case = product_case
    before = len(case[0].db.exec(select(DataResourcePolicy)).all())
    request = prepare(product_case)
    assert request["status"] == "blocked"
    assert request["code"] == "DATA_UNCLASSIFIED"
    assert len(case[0].db.exec(select(DataResourcePolicy)).all()) == before
    assert sent == []
    path = "/api/enterprise/knowledge/answer-requests/" + request["id"]
    body = {
        "tenant_id": "t",
        "review_digest": request["review_digest"],
        "classification": "public",
        "confirm": True,
    }
    assert api.post(path + "/approve", json=body).status_code == 403
    actor["user"] = case[1]
    assert api.post(path + "/approve", json={**body, "confirm": False}).status_code == 422
    assert api.post(path + "/approve", json={**body, "review_digest": "forged"}).status_code == 409
    approved = api.post(path + "/approve", json=body)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "ready"
    assert sent == []
    # Reviewer is not automatically allowed to send another user's request.
    assert api.post(path + "/answer", json={"tenant_id": "t"}).status_code == 403
    actor["user"] = case[2]
    answer = api.post(path + "/answer", json={"tenant_id": "t"})
    assert answer.status_code == 200, answer.text
    assert answer.json()["answer"] == "PRODUCT_ANSWER"
    assert len(sent) == 1
    assert b"SYNTHETIC_PRODUCT_QUESTION" in sent[0].content
    case[0].revoke_source(case[1], session.intent.envelope_refs[-1])
    assert api.post(path + "/answer", json={"tenant_id": "t"}).status_code == 409
    assert len(sent) == 1


def test_review_never_downgrades_existing_restricted_source(product_case):
    api, actor, sent, session, case = product_case
    store = case[0]
    ref = session.intent.envelope_refs[-1]
    store.approve_source(case[1], ref, classification="confidential", answer_mode="none", grants={})
    request = prepare(product_case)
    actor["user"] = case[1]
    result = api.post(
        "/api/enterprise/knowledge/answer-requests/" + request["id"] + "/approve",
        json={
            "tenant_id": "t",
            "review_digest": request["review_digest"],
            "classification": "public",
            "confirm": True,
        },
    )
    assert result.status_code == 409
    assert store.db.get(DataResourcePolicy, ref.envelope_id).classification == "confidential"
    assert store.db.get(DataResourcePolicy, request["question_ref"]["envelope_id"]) is None
    assert sent == []


def test_request_and_preview_are_not_shared_with_other_members(product_case):
    api, actor, sent, _, case = product_case
    request = prepare(product_case)
    stranger = User(
        id="stranger", tenant_id="t", username="stranger", role="member", password_hash="x"
    )
    case[0].db.add(stranger)
    case[0].db.commit()
    actor["user"] = stranger
    assert (
        api.get(
            "/api/enterprise/knowledge/answer-requests/" + request["id"], params={"tenant_id": "t"}
        ).status_code
        == 404
    )
    assert (
        api.get("/api/enterprise/knowledge/answer-requests", params={"tenant_id": "t"}).json() == []
    )
    assert sent == []


def test_prepare_cannot_self_classify_or_inject_history(product_case):
    api, _, sent, session, _ = product_case
    response = api.post(
        "/api/enterprise/knowledge/answer-requests",
        json={
            "tenant_id": "t",
            "provider_policy_id": session.context.provider_policy_id,
            "question": "UNKNOWN",
            "document_ids": ["doc"],
            "classification": "public",
            "history": [{"role": "assistant", "content": "UNLABELLED_HISTORY"}],
        },
    )
    assert response.status_code == 422
    assert sent == []


def test_repeated_document_registration_keeps_the_same_source_identity(product_case):
    from app.api.data_policies import register_document

    _, _, sent, session, case = product_case
    result = register_document("doc", "t", case[0].db, case[2], agent_id=None)
    assert result["envelope_id"] == session.intent.envelope_refs[-1].envelope_id
    assert sent == []


def duplicate_document(store, ref):
    original = store.envelope(ref, "t")
    return store._register(
        "t", "member", "document", "doc", original.payload_json, source_stamp=original.source_stamp
    )


def test_legacy_duplicate_cannot_turn_restricted_data_into_unclassified_review(product_case):
    api, actor, sent, session, case = product_case
    store = case[0]
    ref = session.intent.envelope_refs[-1]
    store.approve_source(case[1], ref, classification="restricted", answer_mode="none", grants={})
    duplicate_document(store, ref)
    request = prepare(product_case)
    actor["user"] = case[1]
    response = api.post(
        "/api/enterprise/knowledge/answer-requests/" + request["id"] + "/approve",
        json={
            "tenant_id": "t",
            "review_digest": request["review_digest"],
            "classification": "public",
            "confirm": True,
        },
    )
    assert response.status_code == 409
    assert store.db.get(DataResourcePolicy, request["question_ref"]["envelope_id"]) is None
    assert sent == []


def test_final_answer_cannot_borrow_public_policy_from_duplicate_restricted_source(product_case):
    from app.api.data_policies import AnswerRequest, approved_answer
    from app.security.data_policy import DataPolicyError

    _, _, sent, session, case = product_case
    store = case[0]
    original = session.intent.envelope_refs[-1]
    store.approve_source(
        case[1], original, classification="restricted", answer_mode="none", grants={}
    )
    duplicate = duplicate_document(store, original)
    question = store.register_text("t", "member", "input", "SYNTHETIC_QUESTION")
    for ref in (duplicate, question):
        store.approve_source(
            case[1],
            ref,
            classification="public",
            answer_mode="answer_with_quote",
            grants={
                session.context.provider_policy_id: {
                    "purposes": ["answer"],
                    "representations": ["raw"],
                }
            },
        )
    with pytest.raises(DataPolicyError):
        approved_answer(
            AnswerRequest(
                tenant_id="t",
                provider_policy_id=session.context.provider_policy_id,
                template_ref={"envelope_id": session.intent.envelope_refs[0].envelope_id},
                question_ref={"envelope_id": question.envelope_id},
                source_refs=[{"envelope_id": duplicate.envelope_id}],
            ),
            store.db,
            case[2],
        )
    assert sent == []
