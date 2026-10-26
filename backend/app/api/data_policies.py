"""Data approvals are explicit administrator operations, never upload metadata."""

from contextlib import contextmanager
from dataclasses import asdict
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlmodel import Session

from app.db import get_session
from app.db.models import KnowledgeDocument, User
from app.llm.client import LLMClient as model_client
from app.security.auth import ensure_current_user_tenant, get_current_user
from app.security.data_policy import DataEnvelopeRef, DataPolicyError
from app.security.data_policy_store import PolicyStore
from app.security.permissions import ensure_tenant_admin

DbSession = Annotated[Session, Depends(get_session)]
CurrentUser = Annotated[User, Depends(get_current_user)]

router = APIRouter(prefix="/api/enterprise/data-policies", tags=["data-policies"])


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str


class InputRequest(StrictRequest):
    text: str = Field(min_length=1, max_length=20000)


class ProviderRequest(StrictRequest):
    model_config_id: str
    purposes: list[str] = Field(min_length=1)
    classifications: list[str] = Field(default_factory=lambda: ["public"])
    terms_reference: str = Field(min_length=1, max_length=500)


class ApprovalRequest(StrictRequest):
    revision: int = Field(ge=1)
    classification: str
    answer_mode: str
    grants: dict = Field(default_factory=dict)
    denied_providers: list[str] = Field(default_factory=list)


class EnvelopeRefRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    envelope_id: str
    revision: int = Field(default=1, ge=1)


class AnswerRequest(StrictRequest):
    provider_policy_id: str
    agent_id: str | None = None
    template_ref: EnvelopeRefRequest
    question_ref: EnvelopeRefRequest
    source_refs: list[EnvelopeRefRequest] = Field(min_length=1, max_length=20)
    answer_mode: Literal["answer_with_quote", "controlled_answer"] = "answer_with_quote"


class ViewRequest(StrictRequest):
    text: str = Field(min_length=1, max_length=20000)
    parents: list[EnvelopeRefRequest] = Field(min_length=1, max_length=20)


@router.post("/templates")
def register_template(
    request: StrictRequest,
    db: DbSession,
    user: CurrentUser,
):
    from app.security.model_egress import SYSTEM_TEMPLATE

    ensure_tenant_admin(request.tenant_id, user)
    return asdict(
        PolicyStore(db).register_text(
            request.tenant_id,
            user.id,
            "system_template",
            SYSTEM_TEMPLATE,
        )
    )


@router.post("/answer-views")
def register_answer_view(
    request: ViewRequest,
    db: DbSession,
    user: CurrentUser,
):
    ensure_tenant_admin(request.tenant_id, user)
    with policy_errors(db, user):
        return asdict(
            PolicyStore(db).derive(
                request.tenant_id,
                user.id,
                "answer_view",
                request.text,
                [DataEnvelopeRef(**ref.model_dump()) for ref in request.parents],
            )
        )


def approved_answer(request, db, user, *, stream=False):
    from app.db.models import ModelConfig
    from app.security.data_policy import PolicyContext
    from app.security.model_egress import ModelPolicySession

    ensure_current_user_tenant(request.tenant_id, user)
    store = PolicyStore(db)
    question = DataEnvelopeRef(**request.question_ref.model_dump())
    template = DataEnvelopeRef(**request.template_ref.model_dump())
    if (
        store.envelope(question, request.tenant_id).source_kind != "input"
        or store.envelope(template, request.tenant_id).source_kind != "system_template"
    ):
        raise DataPolicyError("DATA_SOURCE_INVALID")
    refs = [
        template,
        question,
        *[DataEnvelopeRef(**ref.model_dump()) for ref in request.source_refs],
    ]
    context = PolicyContext(
        request.tenant_id, user.id, request.provider_policy_id, "answer", agent_id=request.agent_id
    )
    session = ModelPolicySession(store, context, refs, answer_mode=request.answer_mode)
    from app.llm.model_config_resolver import snapshot_model_config
    config = snapshot_model_config(db.get(ModelConfig, session.model_config_id))
    client = model_client(config, policy_session=session)
    try:
        messages = session.request(client)["messages"]
        answer = ("".join(client.generate_text_stream(messages[0]["content"], messages[1]["content"]))
                  if stream else client.generate_text(messages[0]["content"], messages[1]["content"]))
    finally:
        client.close()
    history = store.derive(request.tenant_id, user.id, "history", answer, refs)
    return {"answer": answer, "history_ref": asdict(history)}


@router.post("/answer")
def answer(
    request: AnswerRequest,
    db: DbSession,
    user: CurrentUser,
):
    with policy_errors(db, user):
        return approved_answer(request, db, user)


@router.post("/answer/stream")
def answer_stream(
    request: AnswerRequest,
    db: DbSession,
    user: CurrentUser,
):
    import json

    from fastapi.responses import StreamingResponse

    # Validate/select completely before exposing any SSE token.
    with policy_errors(db, user):
        result = approved_answer(request, db, user, stream=True)
    return StreamingResponse(
        iter(["data: " + json.dumps(result, ensure_ascii=False) + "\n\n", "data: [DONE]\n\n"]),
        media_type="text/event-stream",
    )


@contextmanager
def policy_errors(db, user):
    try:
        yield
    except DataPolicyError as exc:
        PolicyStore(db).audit(user.tenant_id, user.id, "policy_denied", "", exc.code)
        raise HTTPException(409, detail=exc.public_detail()) from exc


@router.post("/inputs")
def register_input(
    request: InputRequest,
    db: DbSession,
    user: CurrentUser,
):
    ensure_current_user_tenant(request.tenant_id, user)
    with policy_errors(db, user):
        return asdict(
            PolicyStore(db).register_text(
                request.tenant_id,
                user.id,
                "input",
                request.text,
            )
        )


@router.post("/documents/{document_id}/register")
def register_document(
    document_id: str,
    tenant_id: Annotated[str, Query()],
    db: DbSession,
    user: CurrentUser,
    agent_id: str | None = None,
):
    ensure_current_user_tenant(tenant_id, user)
    document = db.get(KnowledgeDocument, document_id)
    if document is None or document.tenant_id != tenant_id:
        raise HTTPException(404, "Document not found")
    with policy_errors(db, user):
        store = PolicyStore(db)
        store.check_document_access(document, user, agent_id)
        return asdict(store.register_document(document, user))


@router.post("/providers")
def approve_provider(
    request: ProviderRequest,
    db: DbSession,
    user: CurrentUser,
):
    ensure_tenant_admin(request.tenant_id, user)
    with policy_errors(db, user):
        row = PolicyStore(db).approve_provider(
            user,
            request.model_config_id,
            purposes=request.purposes,
            classifications=request.classifications,
            terms_reference=request.terms_reference,
        )
        return {"id": row.id, "revision": row.revision}


@router.put("/sources/{envelope_id}")
def approve_source(
    envelope_id: str,
    request: ApprovalRequest,
    db: DbSession,
    user: CurrentUser,
):
    ensure_tenant_admin(request.tenant_id, user)
    with policy_errors(db, user):
        row = PolicyStore(db).approve_source(
            user,
            DataEnvelopeRef(envelope_id, request.revision),
            classification=request.classification,
            answer_mode=request.answer_mode,
            grants=request.grants,
            denied_providers=request.denied_providers,
        )
        return {"envelope_id": row.envelope_id, "revision": row.revision}


@router.post("/providers/{provider_id}/revoke")
def revoke_provider(
    provider_id: str,
    request: StrictRequest,
    db: DbSession,
    user: CurrentUser,
):
    ensure_tenant_admin(request.tenant_id, user)
    with policy_errors(db, user):
        PolicyStore(db).revoke_provider(user, provider_id)
    return {"status": "revoked"}


@router.post("/sources/{envelope_id}/revoke")
def revoke_source(
    envelope_id: str,
    request: StrictRequest,
    db: DbSession,
    user: CurrentUser,
):
    ensure_tenant_admin(request.tenant_id, user)
    with policy_errors(db, user):
        PolicyStore(db).revoke_source(user, DataEnvelopeRef(envelope_id))
    return {"status": "revoked"}
