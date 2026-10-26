import httpx
import pytest
from test_data_policy import policy_case as policy_case  # noqa: PLC0414
from test_model_data_egress import PROTOCOLS, reply, setup_session

from app.llm.client import LLMClient
from app.llm.model_config_resolver import snapshot_model_config
from app.security.data_policy import DataPolicyError


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_resolved_production_snapshot_matches_approved_model(policy_case, protocol):
    session, _ = setup_session(policy_case, protocol)
    sent = []
    client = LLMClient(
        snapshot_model_config(policy_case[4]),
        policy_session=session,
        transport=httpx.MockTransport(
            lambda r: sent.append(r) or httpx.Response(200, json=reply(protocol))
        ),
    )
    try:
        assert session.complete(client) == "Synthetic answer"
        assert len(sent) == 1
    finally:
        client.close()


@pytest.mark.parametrize("stream", [False, True])
def test_existing_client_wrapper_only_dispatches_exact_approved_input(policy_case, stream):
    session, _ = setup_session(policy_case)
    sent = []

    def handle(request):
        sent.append(request)
        if stream:
            return httpx.Response(
                200,
                content='data: {"choices":[{"index":0,"delta":{"content":"OK"}}]}\n\n',
                headers={"content-type": "text/event-stream"},
            )
        return httpx.Response(200, json=reply(PROTOCOLS[0], "OK"))

    client = LLMClient(
        policy_case[4], policy_session=session, transport=httpx.MockTransport(handle)
    )
    messages = session.request(client)["messages"]
    try:
        if stream:
            assert list(
                client.generate_text_stream(messages[0]["content"], messages[1]["content"])
            ) == ["OK"]
        else:
            assert client.generate_text(messages[0]["content"], messages[1]["content"]) == "OK"
        assert len(sent) == 1
        with pytest.raises(DataPolicyError):
            client.generate_text(messages[0]["content"], "UNKNOWN_FREE_INPUT")
        with pytest.raises(DataPolicyError):
            list(client.generate_text_stream("UNAPPROVED_SYSTEM", messages[1]["content"]))
        assert len(sent) == 1
    finally:
        client.close()


def test_snapshot_option_or_key_revision_change_is_not_a_matching_model(policy_case):
    from dataclasses import replace

    session, _ = setup_session(policy_case)
    config = snapshot_model_config(policy_case[4])
    sent = []
    client = LLMClient(
        replace(config, key_revision=config.key_revision + 1),
        policy_session=session,
        transport=httpx.MockTransport(lambda r: sent.append(r)),
    )
    try:
        with pytest.raises(DataPolicyError):
            session.complete(client)
        assert sent == []
    finally:
        client.close()


def test_uncovered_call_has_an_actionable_non_retryable_policy_reason():
    error = DataPolicyError("DATA_TRUSTED_DISPATCH_REQUIRED")
    assert "受控问答" in str(error)
    assert error.public_detail()["code"] == "DATA_TRUSTED_DISPATCH_REQUIRED"
    assert error.public_detail()["retryable"] is False
