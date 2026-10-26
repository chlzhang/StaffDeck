"""Explicit local administrator review; no mutation sends data to a model."""

import copy
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import Field
from sqlalchemy import text as sql_text
from sqlmodel import select

from app.api.data_policies import (
    CurrentUser,
    DbSession,
    EnvelopeRefRequest,
    StrictRequest,
    policy_errors,
)
from app.api.knowledge_answers import view_document_ids
from app.db.models import (
    DataEnvelope,
    DataPolicyAudit,
    DataResourcePolicy,
    KnowledgeDocument,
    ModelConfig,
    ProviderDataPolicy,
)
from app.security.data_policy import DataEnvelopeRef, DataPolicyError, PolicyContext
from app.security.data_policy_store import PolicyStore, digest, document_stamp, model_digest
from app.security.model_egress import SYSTEM_TEMPLATE
from app.security.permissions import ensure_tenant_admin

router = APIRouter(prefix="/api/enterprise/knowledge/governance", tags=["knowledge-governance"])


class ReviewBase(StrictRequest):
    provider_policy_id: str | None = None
    agent_id: str | None = None
    expected_digest: str
    confirm: Literal[True]


class PolicyReview(ReviewBase):
    classification: Literal["unclassified", "public", "internal", "confidential", "restricted"]
    answer_mode: Literal["none", "controlled_answer", "answer_with_quote"]
    provider_decision: Literal["pending", "allow", "deny"]


class ViewDraft(StrictRequest):
    provider_policy_id: str | None = None
    agent_id: str | None = None
    parent_ref: EnvelopeRefRequest
    text: str = Field(min_length=1, max_length=20000)


class ReplaceView(ReviewBase):
    text: str = Field(min_length=1, max_length=20000)


@contextmanager
def atomic(db):
    try:
        db.exec(sql_text("BEGIN IMMEDIATE"))
        yield
        db.commit()
    except Exception:
        db.rollback()
        raise


def audit(db, user, action, object_id):
    db.add(
        DataPolicyAudit(
            tenant_id=user.tenant_id,
            principal_id=user.id,
            action=action,
            object_id=object_id,
            reason="EXPLICIT_ADMIN_ACTION",
        )
    )


def read_row(store, envelope_id, user, agent_id=None, visiting=None):
    row = store.db.get(DataEnvelope, envelope_id, populate_existing=True)
    if row is None or row.tenant_id != user.tenant_id:
        raise HTTPException(404, "Source not found")
    if row.source_kind not in {"document", "answer_view", "input", "system_template"}:
        raise DataPolicyError("DATA_SOURCE_INVALID")
    if row.digest != digest(
        {
            "payload": row.payload_json,
            "parents": row.parents_json,
            "representation": row.representation,
        }
    ):
        raise DataPolicyError("DATA_CONTENT_CHANGED")
    visiting = set(visiting or ())
    if row.id in visiting or len(visiting) >= 32:
        raise DataPolicyError("DATA_LINEAGE_INVALID")
    visiting.add(row.id)
    if row.source_kind == "document":
        document = store.db.get(KnowledgeDocument, row.source_id, populate_existing=True)
        if document is None:
            raise DataPolicyError("DATA_SOURCE_STALE")
        store.check_document_access(document, user, agent_id)
    for parent in row.parents_json:
        read_row(store, parent["envelope_id"], user, agent_id, visiting)
    return row


def fresh(store, row, user, agent_id):
    if not row.active:
        return False
    if row.source_kind == "document":
        doc = store.db.get(KnowledgeDocument, row.source_id, populate_existing=True)
        return bool(
            doc and doc.status == "ready" and row.source_stamp == document_stamp(doc, store.db)
        )
    if row.source_kind == "answer_view":
        try:
            view_document_ids(store, row, user, agent_id)
        except (DataPolicyError, HTTPException):
            return False
    return not (
        row.source_kind == "system_template" and row.payload_json != {"text": SYSTEM_TEMPLATE}
    )


def policy_value(policy):
    if policy is None:
        return None
    return {
        "classification": policy.classification,
        "answer_mode": policy.answer_mode,
        "grants": copy.deepcopy(policy.grants_json),
        "denied_providers": list(policy.denied_providers_json),
        "revision": policy.revision,
        "active": policy.active,
        "approved_by": policy.approved_by,
    }


def state(store, row, user, provider_id=None, agent_id=None):
    policy = store.db.get(DataResourcePolicy, row.id, populate_existing=True)
    current = fresh(store, row, user, agent_id)
    provider = (
        store.db.get(ProviderDataPolicy, provider_id, populate_existing=True)
        if provider_id
        else None
    )
    if provider_id and (provider is None or provider.tenant_id != user.tenant_id):
        raise DataPolicyError("DATA_PROVIDER_UNAPPROVED")
    model = (
        store.db.get(ModelConfig, provider.model_config_id, populate_existing=True)
        if provider
        else None
    )
    dependencies = []
    for parent in row.parents_json:
        ancestor = read_row(store, parent["envelope_id"], user, agent_id)
        ancestor_policy = store.db.get(DataResourcePolicy, ancestor.id, populate_existing=True)
        dependencies.append(
            [
                ancestor.id,
                ancestor.revision,
                ancestor.active,
                ancestor.source_stamp,
                policy_value(ancestor_policy),
                fresh(store, ancestor, user, agent_id),
            ]
        )
    related = []
    if row.source_kind == "document":
        related = store.db.exec(
            select(DataResourcePolicy)
            .join(DataEnvelope, DataEnvelope.id == DataResourcePolicy.envelope_id)
            .where(
                DataEnvelope.tenant_id == user.tenant_id,
                DataEnvelope.source_kind == "document",
                DataEnvelope.source_id == row.source_id,
                DataEnvelope.source_stamp == row.source_stamp,
            )
        ).all()
    value = {
        "ref": asdict(DataEnvelopeRef(row.id, row.revision)),
        "kind": row.source_kind,
        "text": row.payload_json.get("text", ""),
        "title": row.payload_json.get(
            "title", "批准答复视图" if row.source_kind == "answer_view" else "本地来源"
        ),
        "policy": policy_value(policy),
        "fresh": current,
        "active": row.active,
        "created_at": row.created_at.isoformat(),
        "send_allowed": False,
        "reason": "请先选择供应商并完成所有来源审批。",
    }
    value["review_digest"] = digest(
        {
            "envelope": [row.id, row.revision, row.active, row.digest, row.source_stamp],
            "policy": value["policy"],
            "fresh": current,
            "parents": dependencies,
            "related": sorted(
                [(p.envelope_id, policy_value(p)) for p in related], key=lambda item: item[0]
            ),
            "provider": [
                provider.id,
                provider.revision,
                provider.active,
                provider.config_digest,
                model_digest(model) if model else None,
            ]
            if provider
            else None,
        }
    )
    if provider:
        try:
            store.issue_intent(
                PolicyContext(user.tenant_id, user.id, provider.id, "answer", agent_id=agent_id),
                [DataEnvelopeRef(row.id, row.revision)],
                representation="answer_view" if row.source_kind == "answer_view" else "raw",
                answer_mode="controlled_answer"
                if row.source_kind == "answer_view"
                else "answer_with_quote",
            )
            value.update(send_allowed=True, reason="当前所选供应商许可完整。")
        except DataPolicyError as exc:
            value["reason"] = exc.public_message
    return value


def checked(store, envelope_id, user, body):
    row = read_row(store, envelope_id, user, body.agent_id)
    current = state(store, row, user, body.provider_policy_id, body.agent_id)
    if current["review_digest"] != body.expected_digest:
        raise DataPolicyError("DATA_POLICY_STALE")
    return row, current


@router.get("/documents/{document_id}")
def document_state(
    document_id: str,
    tenant_id: str,
    db: DbSession,
    user: CurrentUser,
    provider_policy_id: str | None = None,
    agent_id: str | None = None,
):
    ensure_tenant_admin(tenant_id, user)
    store = PolicyStore(db)
    with policy_errors(db, user):
        doc = db.get(KnowledgeDocument, document_id, populate_existing=True)
        if doc is None or doc.tenant_id != tenant_id:
            raise HTTPException(404, "Document not found")
        store.check_document_access(doc, user, agent_id)
        roots = db.exec(
            select(DataEnvelope)
            .where(
                DataEnvelope.tenant_id == tenant_id,
                DataEnvelope.source_kind == "document",
                DataEnvelope.source_id == doc.id,
            )
            .order_by(DataEnvelope.created_at)
        ).all()
        latest = next(
            (row for row in roots if row.active and row.source_stamp == document_stamp(doc, db)),
            None,
        )
        current_ids = {row.id for row in roots}
        views = db.exec(
            select(DataEnvelope)
            .where(DataEnvelope.tenant_id == tenant_id, DataEnvelope.source_kind == "answer_view")
            .order_by(DataEnvelope.created_at.desc())
        ).all()
        views = [
            row for row in views if any(p["envelope_id"] in current_ids for p in row.parents_json)
        ]
        return {
            "document_id": doc.id,
            "title": doc.title,
            "text": str((doc.metadata_json or {}).get("raw_text") or ""),
            "updated_at": doc.updated_at.isoformat(),
            "source": state(store, latest, user, provider_policy_id, agent_id) if latest else None,
            "related_sources": [
                state(store, row, user, provider_policy_id, agent_id)
                for row in roots
                if latest and row.id != latest.id and row.source_stamp == latest.source_stamp
            ],
            "views": [
                state(
                    store,
                    read_row(store, row.id, user, agent_id),
                    user,
                    provider_policy_id,
                    agent_id,
                )
                for row in views
            ],
        }


@router.get("/sources/{envelope_id}")
def get_source(
    envelope_id: str,
    tenant_id: str,
    db: DbSession,
    user: CurrentUser,
    provider_policy_id: str | None = None,
    agent_id: str | None = None,
):
    ensure_tenant_admin(tenant_id, user)
    with policy_errors(db, user):
        store = PolicyStore(db)
        return state(
            store, read_row(store, envelope_id, user, agent_id), user, provider_policy_id, agent_id
        )


@router.put("/sources/{envelope_id}/policy")
def review_policy(envelope_id: str, body: PolicyReview, db: DbSession, user: CurrentUser):
    ensure_tenant_admin(body.tenant_id, user)
    store = PolicyStore(db)
    with policy_errors(db, user), atomic(db):
        row, current = checked(store, envelope_id, user, body)
        if body.provider_decision != "pending" and not body.provider_policy_id:
            raise DataPolicyError("DATA_PROVIDER_UNAPPROVED")
        if body.provider_decision == "allow" and not current["fresh"]:
            raise DataPolicyError("DATA_SOURCE_STALE")
        if row.source_kind == "answer_view" and body.answer_mode not in {
            "none",
            "controlled_answer",
        }:
            raise DataPolicyError("DATA_QUOTE_DENIED")
        old = db.get(DataResourcePolicy, row.id, populate_existing=True)
        reset = (
            old is None
            or not old.active
            or old.classification != body.classification
            or old.answer_mode != body.answer_mode
            or body.classification not in {"public", "internal"}
            or body.answer_mode == "none"
        )
        grants = {} if reset else copy.deepcopy(old.grants_json)
        denied = list(old.denied_providers_json) if old else []
        if body.provider_decision == "allow":
            if not body.provider_policy_id:
                raise DataPolicyError("DATA_PROVIDER_UNAPPROVED")
            provider = store.provider(
                PolicyContext(user.tenant_id, user.id, body.provider_policy_id, "answer")
            )
            if (
                body.classification not in provider.classifications_json
                or body.classification not in {"public", "internal"}
            ):
                raise DataPolicyError("DATA_CLASSIFICATION_DENIED")
            if body.answer_mode == "none":
                raise DataPolicyError("DATA_ANSWER_DENIED")
            grants[provider.id] = {
                "purposes": ["answer"],
                "representations": ["answer_view"]
                if body.answer_mode == "controlled_answer"
                else ["raw", "answer_view"],
            }
            denied = [value for value in denied if value != provider.id]
        elif body.provider_policy_id:
            grants.pop(body.provider_policy_id, None)
            denied = [value for value in denied if value != body.provider_policy_id]
            if body.provider_decision == "deny":
                denied.append(body.provider_policy_id)
        policy = old or DataResourcePolicy(
            envelope_id=row.id, tenant_id=user.tenant_id, approved_by=user.id
        )
        policy.classification, policy.answer_mode = body.classification, body.answer_mode
        policy.grants_json, policy.denied_providers_json = grants, denied
        policy.active = True
        policy.revision += int(old is not None)
        policy.approved_by = user.id
        policy.approved_at = datetime.now(UTC).replace(tzinfo=None)
        db.add(policy)
        store._invalidate(user.tenant_id)
        audit(db, user, "source_policy_reviewed", row.id)
    return state(store, row, user, body.provider_policy_id, body.agent_id)


@router.post("/sources/{envelope_id}/revoke")
def revoke(envelope_id: str, body: ReviewBase, db: DbSession, user: CurrentUser):
    ensure_tenant_admin(body.tenant_id, user)
    store = PolicyStore(db)
    with policy_errors(db, user), atomic(db):
        row, _ = checked(store, envelope_id, user, body)
        policy = db.get(DataResourcePolicy, row.id, populate_existing=True)
        if policy is None:
            raise DataPolicyError("DATA_UNCLASSIFIED")
        policy.active = False
        policy.revision += 1
        policy.grants_json = {}
        db.add(policy)
        store._invalidate(user.tenant_id)
        audit(db, user, "source_policy_revoked", row.id)
    return state(store, row, user, body.provider_policy_id, body.agent_id)


@router.post("/documents/{document_id}/views")
def create_view(document_id: str, body: ViewDraft, db: DbSession, user: CurrentUser):
    ensure_tenant_admin(body.tenant_id, user)
    store = PolicyStore(db)
    with policy_errors(db, user), atomic(db):
        parent = read_row(store, body.parent_ref.envelope_id, user, body.agent_id)
        # Validate optional review context before creating even a local draft.
        state(store, parent, user, body.provider_policy_id, body.agent_id)
        if (
            parent.source_kind != "document"
            or parent.source_id != document_id
            or parent.revision != body.parent_ref.revision
            or not fresh(store, parent, user, body.agent_id)
        ):
            raise DataPolicyError("DATA_SOURCE_STALE")
        ref = store._register(
            user.tenant_id,
            user.id,
            "answer_view",
            "",
            {"text": body.text},
            parents=[DataEnvelopeRef(parent.id, parent.revision)],
            representation="answer_view",
            commit=False,
        )
        audit(db, user, "view_draft_created", ref.envelope_id)
    return state(
        store,
        read_row(store, ref.envelope_id, user, body.agent_id),
        user,
        body.provider_policy_id,
        body.agent_id,
    )


@router.post("/sources/{envelope_id}/replace-view")
def replace_view(envelope_id: str, body: ReplaceView, db: DbSession, user: CurrentUser):
    ensure_tenant_admin(body.tenant_id, user)
    store = PolicyStore(db)
    with policy_errors(db, user), atomic(db):
        old, current = checked(store, envelope_id, user, body)
        if old.source_kind != "answer_view" or not current["fresh"]:
            raise DataPolicyError("DATA_SOURCE_STALE")
        ref = store._register(
            user.tenant_id,
            user.id,
            "answer_view",
            "",
            {"text": body.text},
            parents=[DataEnvelopeRef(**p) for p in old.parents_json],
            representation="answer_view",
            commit=False,
        )
        old.active = False
        old.revision += 1
        db.add(old)
        policy = db.get(DataResourcePolicy, old.id, populate_existing=True)
        if policy:
            policy.active = False
            policy.revision += 1
            policy.grants_json = {}
            db.add(policy)
        store._invalidate(user.tenant_id)
        audit(db, user, "view_replaced", old.id)
    return state(
        store,
        read_row(store, ref.envelope_id, user, body.agent_id),
        user,
        body.provider_policy_id,
        body.agent_id,
    )
