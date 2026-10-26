from sqlmodel import select
from test_controlled_knowledge_product import login_case as login_case  # noqa: PLC0414
from test_data_policy import policy_case as policy_case  # noqa: PLC0414

from app.db.models import DataEnvelope


def source_state(case):
    api, tokens, _, _, _, _ = case
    provider = api.get(
        "/api/enterprise/knowledge/answer-providers?tenant_id=t", headers=tokens["admin"]
    ).json()[0]
    response = api.get(
        "/api/enterprise/knowledge/governance/documents/doc",
        headers=tokens["admin"],
        params={"tenant_id": "t", "provider_policy_id": provider["id"]},
    )
    assert response.status_code == 200, response.text
    return response.json(), provider["id"]


def review_body(state, provider, **changes):
    return {
        "tenant_id": "t",
        "provider_policy_id": provider,
        "expected_digest": state["review_digest"],
        "classification": "public",
        "answer_mode": "controlled_answer",
        "provider_decision": "allow",
        "confirm": True,
        **changes,
    }


def test_real_member_cannot_manage_policy_or_views(login_case):
    api, tokens, sent, _, _, _ = login_case
    assert (
        api.get(
            "/api/enterprise/knowledge/governance/documents/doc?tenant_id=t",
            headers=tokens["member"],
        ).status_code
        == 403
    )
    assert (
        api.post(
            "/api/enterprise/knowledge/governance/documents/doc/views",
            headers=tokens["member"],
            json={"tenant_id": "t", "parent_ref": {"envelope_id": "unknown"}, "text": "forged"},
        ).status_code
        == 403
    )
    assert sent == []


def test_policy_review_revoke_and_explicit_fresh_reapproval(login_case):
    api, tokens, sent, _, _, _ = login_case
    document, provider = source_state(login_case)
    state = document["source"]
    path = "/api/enterprise/knowledge/governance/sources/" + state["ref"]["envelope_id"]
    original = review_body(state, provider)
    response = api.put(path + "/policy", headers=tokens["admin"], json=original)
    assert response.status_code == 200, response.text
    revised = response.json()
    assert revised["policy"]["answer_mode"] == "controlled_answer"
    assert revised["policy"]["grants"][provider]["representations"] == ["answer_view"]
    assert api.put(path + "/policy", headers=tokens["admin"], json=original).status_code == 409
    revoked = api.post(
        path + "/revoke",
        headers=tokens["admin"],
        json={
            "tenant_id": "t",
            "provider_policy_id": provider,
            "expected_digest": revised["review_digest"],
            "confirm": True,
        },
    )
    assert revoked.status_code == 200
    assert revoked.json()["policy"]["active"] is False
    assert (
        api.put(
            path + "/policy", headers=tokens["admin"], json=review_body(revised, provider)
        ).status_code
        == 409
    )
    restored = api.put(
        path + "/policy", headers=tokens["admin"], json=review_body(revoked.json(), provider)
    )
    assert restored.status_code == 200
    assert restored.json()["policy"]["active"] is True
    assert sent == []


def test_view_draft_approval_replace_and_version_change_never_copy_permission(login_case):
    api, tokens, sent, _selected, _, case = login_case
    document, provider = source_state(login_case)
    source = document["source"]
    path = "/api/enterprise/knowledge/governance/sources/" + source["ref"]["envelope_id"]
    assert (
        api.put(
            path + "/policy", headers=tokens["admin"], json=review_body(source, provider)
        ).status_code
        == 200
    )
    created = api.post(
        "/api/enterprise/knowledge/governance/documents/doc/views",
        headers=tokens["admin"],
        json={
            "tenant_id": "t",
            "provider_policy_id": provider,
            "parent_ref": source["ref"],
            "text": "FIRST_APPROVED_VIEW",
        },
    )
    assert created.status_code == 200, created.text
    view = created.json()
    assert view["policy"] is None
    view_path = "/api/enterprise/knowledge/governance/sources/" + view["ref"]["envelope_id"]
    approved = api.put(
        view_path + "/policy", headers=tokens["admin"], json=review_body(view, provider)
    )
    assert approved.status_code == 200, approved.text
    views = api.get(
        "/api/enterprise/knowledge/documents/doc/approved-answer-views",
        headers=tokens["member"],
        params={"tenant_id": "t", "provider_policy_id": provider},
    ).json()
    assert [v["id"] for v in views] == [view["ref"]["envelope_id"]]
    replaced = api.post(
        view_path + "/replace-view",
        headers=tokens["admin"],
        json={
            "tenant_id": "t",
            "provider_policy_id": provider,
            "expected_digest": approved.json()["review_digest"],
            "text": "SECOND_UNAPPROVED_VIEW",
            "confirm": True,
        },
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["policy"] is None
    assert replaced.json()["ref"]["envelope_id"] != view["ref"]["envelope_id"]
    assert (
        api.get(
            "/api/enterprise/knowledge/documents/doc/approved-answer-views",
            headers=tokens["member"],
            params={"tenant_id": "t", "provider_policy_id": provider},
        ).json()
        == []
    )
    new = replaced.json()
    newpath = "/api/enterprise/knowledge/governance/sources/" + new["ref"]["envelope_id"]
    assert (
        api.put(
            newpath + "/policy", headers=tokens["admin"], json=review_body(new, provider)
        ).status_code
        == 200
    )
    from app.knowledge.service import KnowledgeService

    KnowledgeService(case[0].db).replace_document_content(case[3], "NEW_SYNTHETIC_DOCUMENT_VERSION")
    assert (
        api.get(
            "/api/enterprise/knowledge/documents/doc/approved-answer-views",
            headers=tokens["member"],
            params={"tenant_id": "t", "provider_policy_id": provider},
        ).json()
        == []
    )
    stale = api.get(
        newpath, headers=tokens["admin"], params={"tenant_id": "t", "provider_policy_id": provider}
    ).json()
    assert stale["fresh"] is False
    assert (
        api.put(
            newpath + "/policy", headers=tokens["admin"], json=review_body(stale, provider)
        ).status_code
        == 409
    )
    assert sent == []


def test_invalid_provider_draft_has_no_partial_write(login_case):
    api, tokens, sent, _, _, case = login_case
    document, _ = source_state(login_case)
    before = len(case[0].db.exec(select(DataEnvelope)).all())
    response = api.post(
        "/api/enterprise/knowledge/governance/documents/doc/views",
        headers=tokens["admin"],
        json={
            "tenant_id": "t",
            "provider_policy_id": "missing-provider",
            "parent_ref": document["source"]["ref"],
            "text": "UNAPPROVED_DRAFT",
        },
    )
    assert response.status_code == 409
    assert len(case[0].db.exec(select(DataEnvelope)).all()) == before
    assert sent == []


def test_deny_requires_an_exact_provider_target(login_case):
    api, tokens, sent, _, _, _ = login_case
    state, _provider = source_state(login_case)
    source = state["source"]
    response = api.put(
        "/api/enterprise/knowledge/governance/sources/" + source["ref"]["envelope_id"] + "/policy",
        headers=tokens["admin"],
        json=review_body(source, None, provider_decision="deny"),
    )
    assert response.status_code == 409
    assert sent == []


def test_existing_template_policy_can_be_explicitly_reviewed_for_a_new_provider(login_case):
    api,tokens,sent,_,_,_=login_case
    created=api.post('/api/enterprise/data-policies/providers',headers=tokens['admin'],json={
        'tenant_id':'t','model_config_id':'model','purposes':['answer'],'terms_reference':'Synthetic supplier B terms'})
    provider=created.json()['id']
    document=api.get('/api/enterprise/knowledge/governance/documents/doc',headers=tokens['admin'],
                     params={'tenant_id':'t','provider_policy_id':provider}).json()
    source=document['source']
    assert api.put('/api/enterprise/knowledge/governance/sources/'+source['ref']['envelope_id']+'/policy',
                   headers=tokens['admin'],json=review_body(source,provider,answer_mode='answer_with_quote')).status_code==200
    prepared=api.post('/api/enterprise/knowledge/answer-requests',headers=tokens['member'],json={
        'tenant_id':'t','provider_policy_id':provider,'document_ids':['doc'],'question':'SYNTHETIC_SUPPLIER_B_QUESTION'}).json()
    path='/api/enterprise/knowledge/answer-requests/'+prepared['id']
    assert prepared['status']=='blocked'
    assert 'admin_review_sources' not in prepared
    details=api.get(path,headers=tokens['admin'],params={'tenant_id':'t'}).json()
    refs=details['admin_review_sources']
    template=next(row for row in refs if row['kind']=='system_template')
    state=api.get('/api/enterprise/knowledge/governance/sources/'+template['envelope_id'],headers=tokens['admin'],
                  params={'tenant_id':'t','provider_policy_id':provider}).json()
    assert api.put('/api/enterprise/knowledge/governance/sources/'+template['envelope_id']+'/policy',
                   headers=tokens['admin'],json=review_body(state,provider,answer_mode='answer_with_quote')).status_code==200
    assert sent==[]
    assert api.post(path+'/approve',headers=tokens['admin'],json={
        'tenant_id':'t','review_digest':prepared['review_digest'],'classification':'public','confirm':True}).status_code==200
    assert api.post(path+'/answer',headers=tokens['member'],json={'tenant_id':'t'}).status_code==200
    assert len(sent)==1


def test_admin_can_review_request_after_its_view_is_replaced(login_case):
    api, tokens, sent, _, refs, case = login_case
    from app.db.models import ProviderDataPolicy
    store, admin, _, _, _ = case
    provider = store.db.exec(select(ProviderDataPolicy)).one()
    view = store.derive('t', admin.id, 'answer_view', 'OLD_VIEW', [refs[-1]])
    store.approve_source(admin, view, classification='public', answer_mode='controlled_answer',
                         grants={provider.id: {'purposes': ['answer'], 'representations': ['answer_view']}})
    prepared = api.post('/api/enterprise/knowledge/answer-requests', headers=tokens['member'],
                        json={'tenant_id': 't', 'provider_policy_id': provider.id,
                              'question': 'REPLACED_VIEW_QUESTION', 'document_ids': ['doc'],
                              'answer_mode': 'controlled_answer', 'view_ids': [view.envelope_id]})
    assert prepared.status_code == 200, prepared.text
    path = '/api/enterprise/knowledge/governance/sources/' + view.envelope_id
    state = api.get(path, headers=tokens['admin'], params={'tenant_id': 't', 'provider_policy_id': provider.id}).json()
    replacement = api.post(path + '/replace-view', headers=tokens['admin'], json={
        'tenant_id': 't', 'provider_policy_id': provider.id, 'expected_digest': state['review_digest'],
        'text': 'NEW_UNAPPROVED_VIEW', 'confirm': True})
    assert replacement.status_code == 200, replacement.text
    reviewed = api.get('/api/enterprise/knowledge/answer-requests/' + prepared.json()['id'],
                       headers=tokens['admin'], params={'tenant_id': 't'})
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()['status'] == 'blocked'
    assert {source['kind'] for source in reviewed.json()['admin_review_sources']} == {'input', 'system_template'}
    assert sent == []
