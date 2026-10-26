"""Local preparation and explicit review for the knowledge-page answer flow."""

from dataclasses import asdict
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import Field
from sqlalchemy import text
from sqlmodel import select

from app.api.data_policies import (
    AnswerRequest,
    CurrentUser,
    DbSession,
    StrictRequest,
    approved_answer,
    policy_errors,
)
from app.db.models import (
    DataEnvelope,
    DataPolicyAudit,
    DataResourcePolicy,
    KnowledgeDocument,
    ModelConfig,
    ProviderDataPolicy,
    User,
)
from app.security.auth import ensure_current_user_tenant
from app.security.data_policy import DataEnvelopeRef, DataPolicyError, PolicyContext
from app.security.data_policy_store import PolicyStore, document_stamp
from app.security.model_egress import SYSTEM_TEMPLATE, ModelPolicySession
from app.security.permissions import ensure_tenant_admin

router = APIRouter(prefix="/api/enterprise/knowledge", tags=["knowledge-answers"])


class PrepareRequest(StrictRequest):
    provider_policy_id: str
    agent_id: str | None = None
    question: str = Field(min_length=1, max_length=20000)
    document_ids: list[str] = Field(min_length=1, max_length=5)
    answer_mode: Literal["answer_with_quote", "controlled_answer"] = "answer_with_quote"
    view_ids: list[str] = Field(default_factory=list, max_length=5)


class ReviewRequest(StrictRequest):
    review_digest: str
    classification: Literal["public", "internal"]
    confirm: Literal[True]


def context_for(row):
    return PolicyContext(
        row.tenant_id,
        row.owner_id,
        row.payload_json["provider_policy_id"],
        "answer",
        agent_id=row.payload_json.get("agent_id"),
    )


def refs_for(row):
    body = row.payload_json
    return [
        DataEnvelopeRef(**value)
        for value in [body["template_ref"], body["question_ref"], *body["source_refs"]]
    ]


def load_request(store, request_id, user):
    row = store.db.get(DataEnvelope, request_id, populate_existing=True)
    if (
        row is None
        or row.tenant_id != user.tenant_id
        or row.source_kind != "answer_request"
        or (row.owner_id != user.id and user.role != "admin")
    ):
        raise HTTPException(404, "Request not found")
    return store.envelope(DataEnvelopeRef(row.id, row.revision), user.tenant_id)


def source_rows(store, row, viewer):
    values = []
    for ref in refs_for(row):
        source = store.envelope(ref, row.tenant_id)
        if source.source_kind == "document":
            document = store.db.get(KnowledgeDocument, source.source_id, populate_existing=True)
            if document is None:
                raise DataPolicyError("DATA_SOURCE_STALE")
            store.check_document_access(document, viewer, row.payload_json.get("agent_id"))
            if document.status != "ready" or source.source_stamp != document_stamp(
                document, store.db
            ):
                raise DataPolicyError("DATA_SOURCE_STALE")
        elif source.source_kind == "input":
            if source.owner_id != row.owner_id or source.parents_json:
                raise DataPolicyError("DATA_SOURCE_INVALID")
        elif source.source_kind == "system_template":
            if source.payload_json != {"text": SYSTEM_TEMPLATE}:
                raise DataPolicyError("DATA_TEMPLATE_INVALID")
        elif source.source_kind == "answer_view":
            view_document_ids(store, source, viewer, row.payload_json.get("agent_id"))
        else:
            raise DataPolicyError("DATA_SOURCE_INVALID")
        values.append(source)
    return values


def view_document_ids(store, view, viewer, agent_id=None, visiting=None):
    visiting = set(visiting or ())
    if view.id in visiting or len(visiting) >= 32 or not view.parents_json:
        raise DataPolicyError("DATA_LINEAGE_INVALID")
    visiting.add(view.id)
    result = set()
    for value in view.parents_json:
        parent = store.envelope(DataEnvelopeRef(**value), viewer.tenant_id)
        if parent.source_kind == "document":
            document = store.db.get(KnowledgeDocument, parent.source_id, populate_existing=True)
            if document is None:
                raise DataPolicyError("DATA_SOURCE_STALE")
            store.check_document_access(document, viewer, agent_id)
            if document.status != "ready" or parent.source_stamp != document_stamp(
                document, store.db
            ):
                raise DataPolicyError("DATA_SOURCE_STALE")
            result.add(document.id)
        elif parent.source_kind == "answer_view":
            result.update(view_document_ids(store, parent, viewer, agent_id, visiting))
        else:
            raise DataPolicyError("DATA_SOURCE_INVALID")
    return result


def provider_details(store, provider_id):
    provider = store.db.get(ProviderDataPolicy, provider_id, populate_existing=True)
    model = store.db.get(ModelConfig, provider.model_config_id) if provider else None
    if model is None:
        raise DataPolicyError("DATA_PROVIDER_STALE")
    return {
        "id": provider.id,
        "name": model.name,
        "endpoint": model.base_url,
        "model": model.model,
        "classifications": provider.classifications_json,
        "terms_reference": provider.terms_reference,
    }


def describe(store, row, user):
    question = store.envelope(DataEnvelopeRef(**row.payload_json["question_ref"]), row.tenant_id)
    result = {
        "id": row.id,
        "owner_id": row.owner_id,
        "question": question.payload_json["text"],
        "question_ref": row.payload_json["question_ref"],
        "review_digest": row.digest,
        "answer_mode": row.payload_json.get("answer_mode", "answer_with_quote"),
        "provider": provider_details(store, row.payload_json["provider_policy_id"]),
        "sources": [],
        "status": "ready",
        "code": None,
        "reason": "许可完整，可以单独点击生成回答。",
    }
    if user.role == "admin":
        result["admin_review_sources"] = []
        for value in (row.payload_json["template_ref"], row.payload_json["question_ref"]):
            source = store.envelope(DataEnvelopeRef(**value), row.tenant_id)
            if source.source_kind in {"system_template", "input"}:
                result["admin_review_sources"].append({
                    "envelope_id": source.id, "kind": source.source_kind,
                    "label": "固定回答模板政策" if source.source_kind == "system_template" else "本次问题政策",
                    "agent_id": row.payload_json.get("agent_id"),
                })
    try:
        sources = source_rows(store, row, user)
        for source in sources:
            if source.source_kind not in {"document", "answer_view"}:
                continue
            policy = store.db.get(DataResourcePolicy, source.id, populate_existing=True)
            result["sources"].append(
                {
                    "title": source.payload_json.get("title", "批准答复视图"),
                    "text": source.payload_json["text"],
                    "classification": policy.classification if policy else "unclassified",
                }
            )
        ModelPolicySession(
            store, context_for(row), refs_for(row), answer_mode=result["answer_mode"]
        )
    except DataPolicyError as exc:
        result.update(status="blocked", code=exc.code, reason=exc.public_message)
    except HTTPException:
        result.update(
            status="blocked",
            code="DATA_ACCESS_DENIED",
            reason="资料访问权限已改变，请重新准备问题。",
        )
    return result


@router.get("/answer-providers")
def list_providers(tenant_id: str, db: DbSession, user: CurrentUser):
    ensure_current_user_tenant(tenant_id, user)
    store = PolicyStore(db)
    rows = db.exec(
        select(ProviderDataPolicy).where(
            ProviderDataPolicy.tenant_id == tenant_id,
            ProviderDataPolicy.active == True,
        )
    ).all()
    result = []
    for row in rows:
        try:
            store.provider(PolicyContext(tenant_id, user.id, row.id, "answer"))
            result.append(provider_details(store, row.id))
        except DataPolicyError:
            continue
    return result


@router.get("/documents/{document_id}/approved-answer-views")
def list_approved_views(
    document_id: str,
    tenant_id: str,
    provider_policy_id: str,
    db: DbSession,
    user: CurrentUser,
    agent_id: str | None = None,
):
    ensure_current_user_tenant(tenant_id, user)
    store = PolicyStore(db)
    doc = db.get(KnowledgeDocument, document_id, populate_existing=True)
    if doc is None or doc.tenant_id != tenant_id:
        raise HTTPException(404, "Document not found")
    with policy_errors(db, user):
        store.check_document_access(doc, user, agent_id)
        result = []
        for row in db.exec(
            select(DataEnvelope)
            .where(
                DataEnvelope.tenant_id == tenant_id,
                DataEnvelope.source_kind == "answer_view",
                DataEnvelope.active == True,
            )
            .order_by(DataEnvelope.created_at.desc())
        ).all():
            try:
                if view_document_ids(store, row, user, agent_id) != {document_id}:
                    continue
                store.issue_intent(
                    PolicyContext(
                        tenant_id, user.id, provider_policy_id, "answer", agent_id=agent_id
                    ),
                    [DataEnvelopeRef(row.id, row.revision)],
                    representation="answer_view",
                    answer_mode="controlled_answer",
                )
                result.append(
                    {
                        "id": row.id,
                        "text": row.payload_json["text"],
                        "created_at": row.created_at.isoformat(),
                    }
                )
            except (DataPolicyError, HTTPException):
                continue
        return result


@router.post("/answer-requests")
def prepare(request: PrepareRequest, db: DbSession, user: CurrentUser):
    ensure_current_user_tenant(request.tenant_id, user)
    store = PolicyStore(db)
    with policy_errors(db, user):
        store.provider(PolicyContext(user.tenant_id, user.id, request.provider_policy_id, "answer"))
        source_refs = []
        for document_id in dict.fromkeys(request.document_ids):
            doc = db.get(KnowledgeDocument, document_id, populate_existing=True)
            if doc is None or doc.tenant_id != user.tenant_id:
                raise HTTPException(404, "Document not found")
            store.check_document_access(doc, user, request.agent_id)
            if doc.status != "ready":
                raise DataPolicyError("DATA_SOURCE_STALE")
            existing = db.exec(
                select(DataEnvelope)
                .where(
                    DataEnvelope.tenant_id == user.tenant_id,
                    DataEnvelope.source_kind == "document",
                    DataEnvelope.source_id == doc.id,
                    DataEnvelope.source_stamp == document_stamp(doc, db),
                    DataEnvelope.active == True,
                )
                .order_by(DataEnvelope.created_at.desc())
            ).first()
            source_refs.append(
                DataEnvelopeRef(existing.id, existing.revision)
                if existing
                else store.register_document(doc, user)
            )
        if request.answer_mode == "controlled_answer":
            if not request.view_ids:
                raise DataPolicyError("DATA_ANSWER_VIEW_REQUIRED")
            source_refs = []
            for view_id in dict.fromkeys(request.view_ids):
                view = db.get(DataEnvelope, view_id, populate_existing=True)
                if (
                    view is None
                    or view.tenant_id != user.tenant_id
                    or view.source_kind != "answer_view"
                ):
                    raise DataPolicyError("DATA_SOURCE_INVALID")
                ref = DataEnvelopeRef(view.id, view.revision)
                store.envelope(ref, user.tenant_id)
                if not view_document_ids(store, view, user, request.agent_id) <= set(
                    request.document_ids
                ):
                    raise DataPolicyError("DATA_SOURCE_INVALID")
                store.issue_intent(
                    PolicyContext(
                        user.tenant_id,
                        user.id,
                        request.provider_policy_id,
                        "answer",
                        agent_id=request.agent_id,
                    ),
                    [ref],
                    representation="answer_view",
                    answer_mode="controlled_answer",
                )
                source_refs.append(ref)
        elif request.view_ids:
            raise DataPolicyError("DATA_SOURCE_INVALID")
        template = db.exec(
            select(DataEnvelope)
            .where(
                DataEnvelope.tenant_id == user.tenant_id,
                DataEnvelope.source_kind == "system_template",
                DataEnvelope.active == True,
            )
            .order_by(DataEnvelope.created_at.desc())
        ).first()
        template_ref = (
            DataEnvelopeRef(template.id, template.revision)
            if template and template.payload_json == {"text": SYSTEM_TEMPLATE}
            else store.register_text(user.tenant_id, user.id, "system_template", SYSTEM_TEMPLATE)
        )
        question = store.register_text(user.tenant_id, user.id, "input", request.question)
        body = {
            "provider_policy_id": request.provider_policy_id,
            "agent_id": request.agent_id,
            "template_ref": asdict(template_ref),
            "question_ref": asdict(question),
            "source_refs": [asdict(ref) for ref in source_refs],
            "answer_mode": request.answer_mode,
        }
        ref = store._register(
            user.tenant_id,
            user.id,
            "answer_request",
            "",
            body,
            representation="local_request",
            parents=[template_ref, question, *source_refs],
        )
        return describe(store, store.envelope(ref, user.tenant_id), user)


@router.get("/answer-requests")
def list_requests(tenant_id: str, db: DbSession, user: CurrentUser):
    ensure_current_user_tenant(tenant_id, user)
    query = select(DataEnvelope).where(
        DataEnvelope.tenant_id == tenant_id, DataEnvelope.source_kind == "answer_request"
    )
    if user.role != "admin":
        query = query.where(DataEnvelope.owner_id == user.id)
    rows = db.exec(query.order_by(DataEnvelope.created_at.desc()).limit(30)).all()
    with policy_errors(db, user):
        return [
            describe(PolicyStore(db), load_request(PolicyStore(db), row.id, user), user)
            for row in rows
        ]


@router.get("/answer-requests/{request_id}")
def get_request(request_id: str, tenant_id: str, db: DbSession, user: CurrentUser):
    ensure_current_user_tenant(tenant_id, user)
    with policy_errors(db, user):
        store = PolicyStore(db)
        return describe(store, load_request(store, request_id, user), user)


@router.post("/answer-requests/{request_id}/approve")
def approve_request(request_id: str, request: ReviewRequest, db: DbSession, user: CurrentUser):
    ensure_tenant_admin(request.tenant_id, user)
    store = PolicyStore(db)
    with policy_errors(db, user):
        try:
            # SQLite is the supported migration target. Hold the writer lock
            # through all checks/inserts, preventing concurrent policy downgrade.
            db.exec(text("BEGIN IMMEDIATE"))
            row = load_request(store, request_id, user)
            if row.digest != request.review_digest:
                raise DataPolicyError("DATA_PROJECTION_MISMATCH")
            context = context_for(row)
            provider = store.provider(context)
            if request.classification not in provider.classifications_json:
                raise DataPolicyError("DATA_CLASSIFICATION_DENIED")
            owner = db.get(User, row.owner_id)
            if owner is None:
                raise DataPolicyError("DATA_ACCESS_DENIED")
            sources = source_rows(store, row, user)
            source_rows(store, row, owner)
            missing = []
            # Check the entire set before approving anything. Existing policies
            # are only evaluated, never rewritten by this convenience action.
            for source in sources:
                policy = db.get(DataResourcePolicy, source.id, populate_existing=True)
                if policy is not None:
                    controlled = row.payload_json.get("answer_mode") == "controlled_answer"
                    store.issue_intent(
                        context,
                        [DataEnvelopeRef(source.id, source.revision)],
                        representation="answer_view" if controlled else "raw",
                        answer_mode="controlled_answer" if controlled else "answer_with_quote",
                    )
                else:
                    if source.source_kind == "answer_view":
                        raise DataPolicyError("DATA_ANSWER_VIEW_REQUIRED")
                    if source.source_kind == "document":
                        store.check_document_origin_policies(context, source, provider)
                    missing.append(source)
            for source in missing:
                db.add(
                    DataResourcePolicy(
                        envelope_id=source.id,
                        tenant_id=user.tenant_id,
                        classification=request.classification,
                        answer_mode="answer_with_quote",
                        grants_json={
                            provider.id: {"purposes": ["answer"], "representations": ["raw"]}
                        },
                        approved_by=user.id,
                    )
                )
                db.add(
                    DataPolicyAudit(
                        tenant_id=user.tenant_id,
                        principal_id=user.id,
                        action="request_source_approved",
                        object_id=source.id,
                        reason="APPROVED",
                    )
                )
            store._invalidate(user.tenant_id)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return describe(store, row, user)


@router.post("/answer-requests/{request_id}/answer")
def answer_request(request_id: str, request: StrictRequest, db: DbSession, user: CurrentUser):
    ensure_current_user_tenant(request.tenant_id, user)
    with policy_errors(db, user):
        store = PolicyStore(db)
        row = load_request(store, request_id, user)
        if row.owner_id != user.id:
            raise HTTPException(403, "Only the requester can send this question")
        source_rows(store, row, user)
        return approved_answer(
            AnswerRequest(tenant_id=user.tenant_id, **row.payload_json), db, user
        )
