"""Data access, answer rights and provider send are separate server-side decisions."""

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.agents.branching import ensure_knowledge_base_version, ensure_open_gallery_binding
from app.db.models import AgentProfile, KnowledgeBase, KnowledgeDocument, ModelConfig, Tenant, User


@pytest.fixture
def policy_case():
    from app.security.data_policy_store import PolicyStore

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as db:
        admin = User(id="admin", tenant_id="t", username="admin", role="admin", password_hash="x")
        member = User(
            id="member", tenant_id="t", username="member", role="member", password_hash="x"
        )
        db.add_all(
            [
                Tenant(id="t", name="Synthetic"),
                admin,
                member,
                AgentProfile(id="overall", tenant_id="t", name="All", is_overall=True),
            ]
        )
        kb = KnowledgeBase(id="kb", tenant_id="t", name="Public library")
        db.add(kb)
        db.commit()
        ensure_open_gallery_binding(db, "t", "knowledge_base", kb.id)
        version = ensure_knowledge_base_version(db, kb, "1.0.0")
        doc = KnowledgeDocument(
            id="doc",
            tenant_id="t",
            knowledge_base_id=kb.id,
            knowledge_base_version_id=version.id,
            filename="policy.md",
            file_type="md",
            status="ready",
            title="Synthetic policy",
            metadata_json={"raw_text": "RAW_PRIVATE_MARKER"},
        )
        model = ModelConfig(
            id="model",
            tenant_id="t",
            name="Synthetic",
            model="test-model",
            base_url="https://provider-a.example.test/v1",
            api_key_encrypted="unused",
        )
        db.add_all([doc, model])
        db.commit()
        store = PolicyStore(db)
        yield store, admin, member, doc, model
    engine.dispose()


def approved_case(case, *, mode="answer_with_quote"):
    from app.security.data_policy import PolicyContext

    store, admin, member, doc, model = case
    provider = store.approve_provider(
        admin,
        model.id,
        purposes=["answer", "ingest", "route"],
        terms_reference="synthetic reviewed terms",
    )
    ref = store.register_document(doc, member)
    store.approve_source(
        admin,
        ref,
        classification="public",
        answer_mode=mode,
        grants={
            provider.id: {
                "purposes": ["answer", "ingest", "route"],
                "representations": ["raw", "answer_view"],
            },
        },
    )
    context = PolicyContext("t", member.id, provider.id, "answer")
    return store, context, ref, provider


def test_read_permission_does_not_grant_provider_send(policy_case):
    from app.security.data_policy import DataPolicyError, PolicyContext

    store, admin, member, doc, model = policy_case
    provider = store.approve_provider(
        admin, model.id, purposes=["answer"], terms_reference="synthetic reviewed terms"
    )
    ref = store.register_document(doc, member)
    with pytest.raises(DataPolicyError, match="DATA_UNCLASSIFIED"):
        store.issue_intent(PolicyContext("t", member.id, provider.id, "answer"), [ref])


@pytest.mark.parametrize("classification", ["unclassified", "confidential", "restricted"])
def test_unknown_or_restricted_sources_cannot_send(policy_case, classification):
    from app.security.data_policy import DataPolicyError

    store, context, ref, provider = approved_case(policy_case)
    store.approve_source(
        policy_case[1],
        ref,
        classification=classification,
        answer_mode="answer_with_quote",
        grants={provider.id: {"purposes": ["answer"], "representations": ["raw"]}},
    )
    with pytest.raises(DataPolicyError):
        store.issue_intent(context, [ref])


def test_provider_approval_does_not_grant_resource_visibility(policy_case):
    from app.security.data_policy import DataPolicyError

    store, context, ref, _ = approved_case(policy_case)
    policy_case[3].knowledge_base_version_id = "private-version"
    store.db.add(policy_case[3])
    store.db.commit()
    with pytest.raises(DataPolicyError):
        store.issue_intent(context, [ref])


def test_owner_cannot_approve_or_lower_classification(policy_case):
    from fastapi import HTTPException

    store, _, member, doc, _ = policy_case
    ref = store.register_document(doc, member)
    with pytest.raises(HTTPException) as error:
        store.approve_source(
            member, ref, classification="public", answer_mode="answer_with_quote", grants={}
        )
    assert error.value.status_code == 403


def test_admin_approval_binds_provider_purpose_version_and_revocation(policy_case):
    from dataclasses import replace

    from app.security.data_policy import DataPolicyError

    store, context, ref, _provider = approved_case(policy_case)
    intent = store.issue_intent(context, [ref])
    store.validate(intent)
    with pytest.raises(DataPolicyError):
        store.issue_intent(replace(context, purpose="memory"), [ref])
    policy_case[4].base_url = "https://provider-b.example.test/v1"
    store.db.add(policy_case[4])
    store.db.commit()
    with pytest.raises(DataPolicyError):
        store.validate(intent)
    policy_case[4].base_url = "https://provider-a.example.test/v1"
    store.db.add(policy_case[4])
    store.db.commit()
    store.revoke_source(policy_case[1], ref)
    with pytest.raises(DataPolicyError):
        store.validate(intent)


def test_mixed_and_derived_sources_never_wash_unknown_parent(policy_case):
    from app.security.data_policy import DataPolicyError

    store, context, ref, _ = approved_case(policy_case)
    unknown = store.register_text("t", context.principal_id, "input", "UNCLASSIFIED_MARKER")
    summary = store.derive("t", context.principal_id, "summary", "Short summary", [ref, unknown])
    with pytest.raises(DataPolicyError):
        store.issue_intent(context, [ref, unknown])
    with pytest.raises(DataPolicyError):
        store.issue_intent(context, [summary])


def test_content_edit_and_archive_invalidate_source(policy_case):
    from app.security.data_policy import DataPolicyError

    store, context, ref, _ = approved_case(policy_case)
    intent = store.issue_intent(context, [ref])
    doc = policy_case[3]
    doc.status = "archived"
    store.db.add(doc)
    store.db.commit()
    with pytest.raises(DataPolicyError):
        store.validate(intent)

    doc.status = "ready"
    doc.metadata_json = {"raw_text": "CHANGED_MARKER"}
    store.db.add(doc)
    store.db.commit()
    with pytest.raises(DataPolicyError):
        store.validate(intent)


def test_api_archive_restore_does_not_resurrect_old_model_intent(policy_case):
    from app.api.knowledge import update_document
    from app.knowledge.schema import KnowledgeDocumentUpdateRequest
    from app.security.data_policy import DataPolicyError

    store, context, ref, _provider = approved_case(policy_case)
    intent = store.issue_intent(context, [ref])
    for status in ("archived", "ready"):
        update_document(
            policy_case[3].id,
            KnowledgeDocumentUpdateRequest(tenant_id="t", status=status),
            db=store.db,
            current_user=policy_case[1],
        )
    with pytest.raises(DataPolicyError):
        store.validate(intent)


def test_base_archive_restore_does_not_resurrect_descendant_intent(policy_case):
    from app.api.knowledge_bases import update_knowledge_base
    from app.knowledge.schema import KnowledgeBaseUpdateRequest
    from app.security.data_policy import DataPolicyError

    store, context, ref, _provider = approved_case(policy_case)
    intent = store.issue_intent(context, [ref])
    for status in ("archived", "active"):
        update_knowledge_base(
            "kb",
            KnowledgeBaseUpdateRequest(tenant_id="t", status=status),
            agent_id=None,
            db=store.db,
            current_user=policy_case[1],
        )
    with pytest.raises(DataPolicyError):
        store.validate(intent)


def test_no_quote_requires_an_explicitly_approved_view(policy_case):
    from app.security.data_policy import DataPolicyError

    store, context, ref, provider = approved_case(policy_case, mode="controlled_answer")
    with pytest.raises(DataPolicyError):
        store.issue_intent(context, [ref])
    view = store.derive("t", context.principal_id, "answer_view", "APPROVED_SUMMARY", [ref])
    with pytest.raises(DataPolicyError):
        store.issue_intent(
            context, [view], representation="answer_view", answer_mode="controlled_answer"
        )
    store.approve_source(
        policy_case[1],
        view,
        classification="public",
        answer_mode="controlled_answer",
        grants={provider.id: {"purposes": ["answer"], "representations": ["answer_view"]}},
    )
    store.validate(
        store.issue_intent(
            context, [view], representation="answer_view", answer_mode="controlled_answer"
        )
    )


def test_legacy_verified_model_does_not_approve_data(policy_case):
    from app.security.data_policy import DataPolicyError, PolicyContext

    store, _, member, doc, model = policy_case
    model.trust_status = "verified"
    store.db.add(model)
    store.db.commit()
    ref = store.register_document(doc, member)
    with pytest.raises(DataPolicyError):
        store.issue_intent(PolicyContext("t", member.id, "missing-provider", "answer"), [ref])
