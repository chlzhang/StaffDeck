import pytest
from sqlmodel import SQLModel, select
from test_data_policy import approved_case
from test_data_policy import policy_case as policy_case  # noqa: PLC0414


def test_additive_initialization_never_grants_legacy_data(policy_case):
    from app.db.models import DataResourcePolicy, ProviderDataPolicy

    store, *_ = policy_case
    SQLModel.metadata.create_all(store.db.get_bind())
    SQLModel.metadata.create_all(store.db.get_bind())
    assert store.db.exec(select(DataResourcePolicy)).all() == []
    assert store.db.exec(select(ProviderDataPolicy)).all() == []
    assert policy_case[3].metadata_json["raw_text"] == "RAW_PRIVATE_MARKER"


def test_restore_reset_disables_even_previously_approved_provider(policy_case):
    from app.security.data_policy import DataPolicyError
    from app.security.data_policy_migrations import reset_after_restore

    store, context, ref, _provider = approved_case(policy_case)
    intent = store.issue_intent(context, [ref])
    assert reset_after_restore(store.db) == 1
    assert reset_after_restore(store.db) == 0
    with pytest.raises(DataPolicyError):
        store.validate(intent)
    with pytest.raises(DataPolicyError):
        store.issue_intent(context, [ref])


def test_provider_terms_and_explicit_revoke(policy_case):
    from app.security.data_policy import DataPolicyError

    store, admin, _, _, model = policy_case
    with pytest.raises(DataPolicyError, match="DATA_TERMS_REQUIRED"):
        store.approve_provider(admin, model.id, purposes=["answer"])
    provider = store.approve_provider(
        admin, model.id, purposes=["answer"], terms_reference="synthetic terms"
    )
    from app.security.data_policy import PolicyContext

    context = PolicyContext("t", "member", provider.id, "answer")
    store.revoke_provider(admin, provider.id)
    with pytest.raises(DataPolicyError):
        store.provider(context)
