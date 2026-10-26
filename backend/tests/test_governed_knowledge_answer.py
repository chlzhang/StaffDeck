"""Synthetic local ingestion -> local search -> explicit approval -> SDK answer."""

import base64
import json

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import select
from test_data_policy import policy_case as policy_case  # noqa: PLC0414
from test_model_data_egress import PROTOCOLS, reply, setup_session


def test_local_ingest_search_and_governed_answer_with_history(policy_case, monkeypatch):
    from app.api import data_policies
    from app.db import get_session
    from app.db.models import DataPolicyAudit, KnowledgeDocument
    from app.knowledge.schema import KnowledgeSearchRequest
    from app.knowledge.service import IngestPayload, KnowledgeService
    from app.llm.client import LLMClient
    from app.security.auth import get_current_user
    from app.security.data_policy import DataEnvelopeRef

    store, admin, member, _, _model = policy_case
    _, refs = setup_session(policy_case)
    provider = store.db.exec(
        select(__import__("app.db.models", fromlist=["ProviderDataPolicy"]).ProviderDataPolicy)
    ).one()
    service = KnowledgeService(store.db)
    monkeypatch.setattr("app.knowledge.service.engine", store.db.get_bind())
    job = service.create_ingest_job(
        IngestPayload(
            tenant_id="t",
            knowledge_base_id="kb",
            filename="synthetic.md",
            content_base64=base64.b64encode(
                b"# Synthetic leave policy\n\nSynthetic leave allowance is 12 days."
            ).decode(),
            knowledge_base_version_id=policy_case[3].knowledge_base_version_id,
        )
    )
    service.run_ingest_job(job.id)
    store.db.refresh(job)
    assert job.status == "succeeded"
    document = store.db.get(KnowledgeDocument, job.document_id)
    result = service.search(
        KnowledgeSearchRequest(
            tenant_id="t",
            query="Synthetic leave allowance",
            knowledge_base_ids=["kb"],
            knowledge_base_version_ids=[document.knowledge_base_version_id],
            document_ids=[document.id],
        ),
        model_config=None,
    )
    assert result.chunks or result.selected_documents
    source = store.register_document(document, member)
    question = store.register_text("t", member.id, "input", "How many synthetic leave days?")
    sent = []

    def factory(config, **kw):
        return LLMClient(
            config,
            **kw,
            transport=httpx.MockTransport(
                lambda r: (
                    sent.append(r)
                    or httpx.Response(200, json=reply(PROTOCOLS[0], "12 synthetic days"))
                )
            ),
        )

    monkeypatch.setattr(data_policies, "model_client", factory)
    app = FastAPI()
    app.include_router(data_policies.router)
    app.dependency_overrides[get_session] = lambda: store.db
    app.dependency_overrides[get_current_user] = lambda: member
    payload = {
        "tenant_id": "t",
        "provider_policy_id": provider.id,
        "template_ref": {"envelope_id": refs[0].envelope_id},
        "question_ref": {"envelope_id": question.envelope_id},
        "source_refs": [{"envelope_id": source.envelope_id}],
    }
    with TestClient(app) as api:
        assert api.post("/api/enterprise/data-policies/answer", json=payload).status_code == 409
        assert sent == []
        assert any(
            row.reason == "DATA_UNCLASSIFIED"
            for row in store.db.exec(select(DataPolicyAudit)).all()
        )
        for ref in (source, question):
            store.approve_source(
                admin,
                ref,
                classification="public",
                answer_mode="answer_with_quote",
                grants={provider.id: {"purposes": ["answer"], "representations": ["raw"]}},
            )
        response = api.post("/api/enterprise/data-policies/answer", json=payload)
        assert response.status_code == 200, response.text
        assert response.json()["answer"] == "12 synthetic days"
        assert len(sent) == 1
        history = DataEnvelopeRef(**response.json()["history_ref"])
        store.revoke_source(admin, source)
        import pytest

        from app.security.data_policy import DataPolicyError, PolicyContext

        with pytest.raises(DataPolicyError):
            store.issue_intent(PolicyContext("t", member.id, provider.id, "answer"), [history])
        assert api.post("/api/enterprise/data-policies/answer", json=payload).status_code == 409
        assert len(sent) == 1
    audits = store.db.exec(select(DataPolicyAudit)).all()
    assert "Synthetic leave allowance" not in json.dumps(
        [r.model_dump(mode="json") for r in audits]
    )
