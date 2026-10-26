"""Knowledge authorization and lifecycle regressions against real local services."""
from __future__ import annotations

import base64
import json
import socket
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.agents.branching import (
    ensure_agent_private_knowledge_branch,
    ensure_knowledge_base_version,
    ensure_open_gallery_binding,
)
from app.api.knowledge import router
from app.db import get_session
from app.db.models import (
    AgentProfile,
    KnowledgeBase,
    KnowledgeConcept,
    KnowledgeDocument,
    Message,
    Tenant,
    User,
)
from app.knowledge.citations import knowledge_citations_from_results
from app.knowledge.result_projection import model_facing_knowledge
from app.knowledge.schema import KnowledgeSearchRequest
from app.knowledge.service import IngestPayload, KnowledgeService
from app.security.auth import get_current_user

PUBLIC_MARKER = "PUBLIC_POLICY_2031"
PRIVATE_MARKER = "PRIVATE_POLICY_6042"
SEARCH = "/api/enterprise/knowledge/search"
RESULT_FIELDS = (
    "selected_buckets", "chunks", "selected_documents", "selected_concepts",
    "expanded_sections", "okf_citations", "evidence_pack",
)


@pytest.fixture
def knowledge_scope(monkeypatch):
    # Any accidental model/provider network call must fail instead of using a credential.
    def deny_network(*args, **kwargs):
        raise AssertionError("Knowledge regressions must never open a network connection")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as db:
        member = User(
            id="member", tenant_id="t1", username="member", role="member", password_hash="x"
        )
        owner = User(
            id="owner", tenant_id="t1", username="owner", role="member", password_hash="x"
        )
        admin = User(
            id="admin", tenant_id="t1", username="admin", role="admin", password_hash="x"
        )
        db.add_all([
            Tenant(id="t1", name="Synthetic tenant"), member, owner, admin,
            AgentProfile(id="overall", tenant_id="t1", name="Overall", is_overall=True),
            AgentProfile(
                id="private-agent", tenant_id="t1", name="Private employee",
                metadata_json={"owner_user_id": owner.id},
            ),
        ])
        public = KnowledgeBase(id="public", tenant_id="t1", name="Public policies")
        private = KnowledgeBase(id="private", tenant_id="t1", name="Private policies")
        db.add_all([public, private])
        db.commit()
        ensure_open_gallery_binding(db, "t1", "knowledge_base", public.id)
        ensure_agent_private_knowledge_branch(
            db, "t1", "private-agent", private, metadata_json={"owner_user_id": owner.id}
        )
        public_version = ensure_knowledge_base_version(db, public, "1.0.0")
        private_version = ensure_knowledge_base_version(db, private, "1.0.0")
        db.commit()

        service = KnowledgeService(db)

        def ingest(base_id, version_id, filename, text):
            job = service.create_ingest_job(IngestPayload(
                tenant_id="t1", knowledge_base_id=base_id,
                knowledge_base_version_id=version_id, filename=filename,
                content_base64=base64.b64encode(text.encode()).decode(),
            ))
            service._run_ingest_job(job.id)
            db.refresh(job)
            assert job.status == "succeeded", job.error
            return db.get(KnowledgeDocument, job.document_id)

        public_document = ingest(
            public.id, public_version.id, "public.md", f"# 部门制度\n部门制度公开说明 {PUBLIC_MARKER}。"
        )
        private_document = ingest(
            private.id, private_version.id, "private.md", f"# 部门制度\n部门制度私有说明 {PRIVATE_MARKER}。"
        )
        actor = {"user": member}
        app = FastAPI()
        app.include_router(router)

        def session_override():
            yield db

        app.dependency_overrides[get_session] = session_override
        app.dependency_overrides[get_current_user] = lambda: actor["user"]
        with TestClient(app) as client:
            yield SimpleNamespace(
                db=db, client=client, actor=actor, member=member, owner=owner, admin=admin,
                public=public, private=private, public_version=public_version,
                private_version=private_version, public_document=public_document,
                private_document=private_document, ingest=ingest,
            )
    engine.dispose()


def search(scope, **filters):
    response = scope.client.post(SEARCH, json={
        "tenant_id": "t1", "query": "部门制度", **filters,
    })
    assert response.status_code == 200, response.text
    return response.json()


def assert_empty_results(payload):
    assert all(payload[field] == [] for field in RESULT_FIELDS), payload


@pytest.mark.parametrize("requested", ["private", "missing"])
def test_private_or_unknown_version_never_removes_scope(knowledge_scope, monkeypatch, requested):
    scope = knowledge_scope
    calls = []
    original = KnowledgeService.search

    def record_call(self, request, model_config=None):
        calls.append(request)
        return original(self, request, model_config)

    monkeypatch.setattr(KnowledgeService, "search", record_call)
    version_id = scope.private_version.id if requested == "private" else "does-not-exist"
    payload = search(scope, knowledge_base_version_ids=[version_id])
    assert_empty_results(payload)
    assert PRIVATE_MARKER not in json.dumps(payload)
    assert payload["trace"][0]["phase"] == "no_visible_knowledge"
    assert calls == []


@pytest.mark.parametrize("filters", [{}, {"knowledge_base_version_ids": []}])
def test_default_and_explicit_empty_version_lists_keep_public_search(knowledge_scope, filters):
    payload = search(knowledge_scope, **filters)
    assert PUBLIC_MARKER in json.dumps(payload)
    assert PRIVATE_MARKER not in json.dumps(payload)


def test_mixed_version_filters_only_keep_authorized_version(knowledge_scope):
    scope = knowledge_scope
    payload = search(scope, knowledge_base_version_ids=[
        scope.public_version.id, scope.private_version.id,
    ])
    assert PUBLIC_MARKER in json.dumps(payload)
    assert PRIVATE_MARKER not in json.dumps(payload)


@pytest.mark.parametrize("filter_kind", ["base", "document", "both"])
@pytest.mark.parametrize("explicit_version", [False, True])
def test_unavailable_base_and_document_filters_cannot_widen_scope(
    knowledge_scope, filter_kind, explicit_version,
):
    scope = knowledge_scope
    filters = (
        {"knowledge_base_version_ids": [scope.public_version.id]} if explicit_version else {}
    )
    if filter_kind in {"base", "both"}:
        filters["knowledge_base_ids"] = [scope.private.id]
    if filter_kind in {"document", "both"}:
        filters["document_ids"] = [scope.private_document.id]
    assert_empty_results(search(scope, **filters))


@pytest.mark.parametrize("filters", [
    {"tenant_id": "foreign-tenant"}, {"agent_id": "private-agent"},
])
def test_tenant_and_private_agent_controls_remain_denied(knowledge_scope, filters):
    response = knowledge_scope.client.post(SEARCH, json={
        "tenant_id": "t1", "query": "部门制度", **filters,
    })
    assert response.status_code == 403


@pytest.mark.parametrize("actor_name", ["owner", "admin"])
def test_authorized_private_agent_still_retrieves_its_bound_version(knowledge_scope, actor_name):
    scope = knowledge_scope
    scope.actor["user"] = getattr(scope, actor_name)
    payload = search(scope, agent_id="private-agent")
    assert PRIVATE_MARKER in json.dumps(payload)
    assert PUBLIC_MARKER not in json.dumps(payload)


RETIRED_MARKER = "RETIRED_POLICY_7053"


def retire_document(scope):
    document = scope.ingest(
        scope.public.id, scope.public_version.id, "retired.md",
        f"# 废止差旅规定\n废止差旅规定 {RETIRED_MARKER}。",
    )
    before = search(scope, query="废止差旅规定", document_ids=[document.id])
    assert RETIRED_MARKER in json.dumps(before)
    scope.actor["user"] = scope.admin
    response = scope.client.put(
        f"/api/enterprise/knowledge/documents/{document.id}",
        json={"tenant_id": "t1", "status": "archived"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "archived"
    scope.actor["user"] = scope.member
    return document


def test_archived_document_does_not_return_derived_concepts(knowledge_scope):
    scope = knowledge_scope
    document = retire_document(scope)
    payload = search(scope, query="废止差旅规定", document_ids=[document.id])
    assert_empty_results(payload)
    assert RETIRED_MARKER not in json.dumps(payload)


@pytest.mark.parametrize("status", ["processing", "failed", "missing"])
def test_nonready_or_missing_document_does_not_supply_concepts(knowledge_scope, status):
    scope = knowledge_scope
    parent_id = "not-present"
    if status != "missing":
        parent = KnowledgeDocument(
            id="unavailable-parent", tenant_id="t1", knowledge_base_id=scope.public.id,
            knowledge_base_version_id=scope.public_version.id, filename="unavailable.md",
            file_type="md", status=status,
        )
        scope.db.add(parent)
        parent_id = parent.id
    concept = KnowledgeConcept(
        id="unavailable-concept", tenant_id="t1", knowledge_base_id=scope.public.id,
        knowledge_base_version_id=scope.public_version.id, document_id=parent_id,
        concept_id="unavailable", concept_type="Topic", title="不可用资料",
        content_md="不可用资料 UNAVAILABLE_MARKER",
    )
    scope.db.add(concept)
    scope.db.commit()
    payload = search(scope, query="不可用资料", document_ids=[parent_id])
    assert_empty_results(payload)
    assert "UNAVAILABLE_MARKER" not in json.dumps(payload)


@pytest.mark.parametrize("mismatch", ["tenant", "base", "version", "parent_null", "concept_null"])
def test_mismatched_parent_scope_does_not_supply_concepts(knowledge_scope, mismatch):
    scope = knowledge_scope
    parent = KnowledgeDocument(
        id="mismatched-parent",
        tenant_id="foreign" if mismatch == "tenant" else "t1",
        knowledge_base_id=scope.private.id if mismatch == "base" else scope.public.id,
        knowledge_base_version_id=(
            None if mismatch == "parent_null"
            else scope.private_version.id if mismatch == "version"
            else scope.public_version.id
        ),
        filename="mismatched.md", file_type="md", status="ready",
    )
    concept = KnowledgeConcept(
        id="mismatched-concept", tenant_id="t1", knowledge_base_id=scope.public.id,
        knowledge_base_version_id=None if mismatch == "concept_null" else scope.public_version.id,
        document_id=parent.id, concept_id="mismatched", concept_type="Topic",
        title="错配概念", content_md="错配概念 MISMATCHED_MARKER",
    )
    scope.db.add_all([parent, concept])
    scope.db.commit()
    result = KnowledgeService(scope.db)._load_concepts_for_search(KnowledgeSearchRequest(
        tenant_id="t1", query="错配概念", knowledge_base_ids=[scope.public.id],
        document_ids=[parent.id],
    ))
    assert result == []


def test_standalone_active_okf_concept_remains_searchable(knowledge_scope):
    scope = knowledge_scope
    scope.db.add(KnowledgeConcept(
        id="standalone", tenant_id="t1", knowledge_base_id=scope.public.id,
        knowledge_base_version_id=scope.public_version.id, document_id=None,
        concept_id="standalone", concept_type="Topic", title="独立手册",
        content_md="独立手册 STANDALONE_MARKER",
    ))
    scope.db.commit()
    payload = search(scope, query="独立手册")
    assert any(c["concept_id"] == "standalone" for c in payload["selected_concepts"])
    assert "STANDALONE_MARKER" in json.dumps(payload)


def test_null_version_legacy_data_uses_explicit_match(knowledge_scope):
    scope = knowledge_scope
    parent = KnowledgeDocument(
        id="legacy-parent", tenant_id="t1", knowledge_base_id=scope.public.id,
        knowledge_base_version_id=None, filename="legacy.md", file_type="md", status="ready",
    )
    concept = KnowledgeConcept(
        id="legacy-concept", tenant_id="t1", knowledge_base_id=scope.public.id,
        knowledge_base_version_id=None, document_id=parent.id, concept_id="legacy",
        concept_type="Topic", title="旧版手册", content_md="旧版手册 LEGACY_MARKER",
    )
    scope.db.add_all([parent, concept])
    scope.db.commit()
    result = KnowledgeService(scope.db).search(KnowledgeSearchRequest(
        tenant_id="t1", query="旧版手册", knowledge_base_ids=[scope.public.id],
        document_ids=[parent.id],
    ))
    assert [c["concept_id"] for c in result.selected_concepts] == ["legacy"]
    assert "LEGACY_MARKER" in json.dumps(result.model_dump())


def test_restore_ready_reenables_search_without_deleting_history(knowledge_scope):
    scope = knowledge_scope
    before = search(scope, document_ids=[scope.public_document.id])
    concept_path = before["selected_concepts"][0]["concept_id"]
    citations = [{"document_id": scope.public_document.id, "concept_id": concept_path}]
    history = Message(
        id="historical-answer", tenant_id="t1", session_id="historical-session",
        role="assistant", content="先前部门制度回答。[1]", metadata_json={"citations": citations},
    )
    scope.db.add(history)
    scope.db.commit()
    scope.actor["user"] = scope.admin
    path = f"/api/enterprise/knowledge/documents/{scope.public_document.id}"
    for status in ("archived", "ready"):
        response = scope.client.put(path, json={"tenant_id": "t1", "status": status})
        assert response.status_code == 200, response.text
        payload = search(scope, document_ids=[scope.public_document.id])
        if status == "archived":
            assert_empty_results(payload)
        else:
            assert PUBLIC_MARKER in json.dumps(payload)
        # Historical citations can still resolve their original document and logical concept.
        assert scope.client.get(path, params={"tenant_id": "t1"}).status_code == 200
        scope.db.refresh(history)
        assert history.metadata_json == {"citations": citations}
        assert history.content == "先前部门制度回答。[1]"
        assert scope.db.exec(select(KnowledgeConcept).where(
            KnowledgeConcept.concept_id == concept_path,
            KnowledgeConcept.document_id == scope.public_document.id,
        )).first() is not None


def test_archived_payload_is_absent_at_model_boundary(knowledge_scope):
    scope = knowledge_scope
    document = retire_document(scope)
    payload = search(scope, query="废止差旅规定", document_ids=[document.id])
    # Exercise the production projection used by KnowledgeFacade, without invoking a model.
    model_payload = model_facing_knowledge(payload, knowledge_citations_from_results([payload]))
    assert model_payload["hit_count"] == 0
    assert RETIRED_MARKER not in json.dumps(model_payload)


@pytest.mark.parametrize("status", ["archived", "ready"])
def test_concept_source_references_only_expand_available_documents(knowledge_scope, status):
    scope = knowledge_scope
    linked = scope.ingest(
        scope.public.id, scope.public_version.id, "referenced.md",
        f"# 引用条款\n引用条款 {RETIRED_MARKER}。",
    )
    scope.db.add(KnowledgeConcept(
        id="reference-entry", tenant_id="t1", knowledge_base_id=scope.public.id,
        knowledge_base_version_id=scope.public_version.id, document_id=None,
        concept_id="reference-entry", concept_type="Topic", title="引用条款导读",
        content_md="引用条款的导读 REFERENCE_ENTRY_MARKER。",
        source_refs_json=[{"document_id": linked.id}],
    ))
    scope.db.commit()
    if status == "archived":
        scope.actor["user"] = scope.admin
        response = scope.client.put(
            f"/api/enterprise/knowledge/documents/{linked.id}",
            json={"tenant_id": "t1", "status": status},
        )
        assert response.status_code == 200, response.text
        scope.actor["user"] = scope.member
    payload = search(scope, query="引用条款")
    assert "REFERENCE_ENTRY_MARKER" in json.dumps(payload)
    if status == "archived":
        assert RETIRED_MARKER not in json.dumps(payload)
        model_payload = model_facing_knowledge(payload, knowledge_citations_from_results([payload]))
        assert RETIRED_MARKER not in json.dumps(model_payload)
    else:
        assert RETIRED_MARKER in json.dumps(payload)
        assert any(b["document_id"] == linked.id for b in payload["selected_buckets"])
