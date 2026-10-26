"""Actual SDK serialization is intercepted locally; denied calls delegate zero times."""

import json

import httpx
import pytest
from anthropic import APIConnectionError as AnthropicConnectionError
from test_data_policy import approved_case
from test_data_policy import policy_case as policy_case  # noqa: PLC0414

from app.llm.protocol_drivers import ProtocolCallError
from app.security.data_policy import DataPolicyError

PROTOCOLS = [
    "openai_chat_completions",
    "openai_responses",
    "anthropic_messages",
    "gemini_generate_content",
]


def setup_session(case, protocol="openai_chat_completions", mode="answer_with_quote"):
    from app.security.encryption import encrypt_secret
    from app.security.model_egress import SYSTEM_TEMPLATE, ModelPolicySession

    case[4].api_protocol = protocol
    case[4].api_key_encrypted = encrypt_secret("synthetic-not-a-credential")
    case[0].db.add(case[4])
    case[0].db.commit()
    store, context, ref, provider = approved_case(case, mode=mode)
    template = store.register_text("t", context.principal_id, "system_template", SYSTEM_TEMPLATE)
    store.approve_source(
        case[1],
        template,
        classification="public",
        answer_mode="answer_with_quote",
        grants={provider.id: {"purposes": ["answer"], "representations": ["raw", "answer_view"]}},
    )
    refs = [template, ref]
    if mode == "controlled_answer":
        view = store.derive("t", context.principal_id, "answer_view", "APPROVED_VIEW_ONLY", [ref])
        store.approve_source(
            case[1],
            view,
            classification="public",
            answer_mode=mode,
            grants={provider.id: {"purposes": ["answer"], "representations": ["answer_view"]}},
        )
        refs = [template, view]
    return ModelPolicySession(store, context, refs, answer_mode=mode), refs


def reply(protocol, text="Synthetic answer"):
    if protocol == "openai_chat_completions":
        return {
            "id": "mock",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
        }
    if protocol == "openai_responses":
        return {
            "id": "mock",
            "object": "response",
            "output": [
                {
                    "type": "message",
                    "id": "msg",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": text, "annotations": []}],
                }
            ],
        }
    if protocol == "anthropic_messages":
        return {
            "id": "mock",
            "type": "message",
            "role": "assistant",
            "model": "test-model",
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
    return {
        "candidates": [
            {"content": {"parts": [{"text": text}], "role": "model"}, "finishReason": "STOP"}
        ]
    }


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_real_sdk_approved_projection_and_direct_raw_bypass(policy_case, protocol):
    from app.llm.client import LLMClient

    session, _ = setup_session(policy_case, protocol)
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=reply(protocol))

    client = LLMClient(
        policy_case[4], policy_session=session, transport=httpx.MockTransport(handler)
    )
    result = session.complete(client)
    assert result == "Synthetic answer"
    assert len(requests) == 1
    assert "RAW_PRIVATE_MARKER" in requests[0].content.decode()
    # A direct driver/SDK call has no trusted dispatch scope, even with identical JSON.
    with pytest.raises((DataPolicyError, ProtocolCallError)):
        client.driver.complete(session.request(client))
    assert len(requests) == 1
    client.close()


@pytest.mark.parametrize(
    "attack",
    [
        "body",
        "query",
        "header",
        "url",
        "method",
        "missing",
        "stale",
        "unknown-parent",
        "duplicate-json-key",
        "idempotency-header",
    ],
)
def test_serialized_request_tamper_delegates_zero(policy_case, attack):
    from app.llm.client import LLMClient
    from app.security.data_policy import DataPolicyError
    from app.security.model_egress import ModelPolicySession

    session, refs = setup_session(policy_case)
    sent = []
    client = LLMClient(
        policy_case[4],
        policy_session=session,
        transport=httpx.MockTransport(
            lambda r: sent.append(r) or httpx.Response(200, json=reply(PROTOCOLS[0]))
        ),
    )
    if attack == "missing":
        client._model_policy_session = None
    elif attack == "stale":
        policy_case[0].revoke_source(policy_case[1], refs[-1])
    elif attack == "unknown-parent":
        unknown = policy_case[0].register_text("t", "member", "history", "UNKNOWN_HISTORY")
        with pytest.raises(DataPolicyError):
            ModelPolicySession(policy_case[0], session.context, [*refs, unknown])
        assert sent == []
        return
    else:
        original = client._egress_transport.handle_request

        def mutate(r):
            if attack == "body":
                r = httpx.Request(
                    "POST",
                    r.url,
                    headers=r.headers,
                    json={**json.loads(r.content), "secret": "EXFIL_MARKER"},
                )
            elif attack == "duplicate-json-key":
                raw = b'{"messages":"UNAPPROVED_DUPLICATE_MARKER",' + r.content[1:]
                headers = dict(r.headers)
                headers["content-length"] = str(len(raw))
                r = httpx.Request("POST", r.url, headers=headers, content=raw)
            elif attack == "idempotency-header":
                r.headers["idempotency-key"] = (
                    "stainless-python-retry-12345678-1234-1234-1234-123456789abc"
                )
            elif attack == "query":
                r.url = r.url.copy_add_param("secret", "EXFIL_MARKER")
            elif attack == "header":
                r.headers["x-exfil"] = "EXFIL_MARKER"
            elif attack == "url":
                r.url = httpx.URL("https://elsewhere.example.test/v1/chat/completions")
            elif attack == "method":
                r.method = "PUT"
            return original(r)

        client._egress_transport.handle_request = mutate
    with pytest.raises(DataPolicyError):
        session.complete(client)
    assert sent == []
    client.close()


def test_sdk_retry_revalidates_after_revocation(policy_case):
    from app.llm.client import LLMClient

    session, refs = setup_session(policy_case)
    sent = []

    def handler(request):
        sent.append(request)
        policy_case[0].revoke_source(policy_case[1], refs[-1])
        return httpx.Response(500, json={"error": {"message": "mock retry"}})

    client = LLMClient(
        policy_case[4], policy_session=session, transport=httpx.MockTransport(handler)
    )
    with pytest.raises(DataPolicyError):
        session.complete(client)
    assert len(sent) == 1  # Retry is rejected before the delegate.
    client.close()


def test_controlled_answer_never_sends_raw_and_renders_only_approved_view(policy_case):
    from app.llm.client import LLMClient

    session, refs = setup_session(policy_case, mode="controlled_answer")
    sent = []
    result = {"view_ids": [refs[-1].envelope_id]}

    def handler(request):
        sent.append(request)
        return httpx.Response(200, json=reply(PROTOCOLS[0], json.dumps(result)))

    client = LLMClient(
        policy_case[4], policy_session=session, transport=httpx.MockTransport(handler)
    )
    assert session.complete(client) == "APPROVED_VIEW_ONLY"
    assert "RAW_PRIVATE_MARKER" not in sent[0].content.decode()
    result["free_text"] = "MODEL_UNAPPROVED_TEXT"
    with pytest.raises(DataPolicyError):
        session.complete(client)
    assert len(sent) == 2
    client.close()


def test_legacy_call_refuses_before_diagnostics_or_send(policy_case, monkeypatch):
    from app.llm.client import LLMClient
    from app.security.encryption import encrypt_secret

    policy_case[4].api_key_encrypted = encrypt_secret("synthetic-not-a-credential")
    sent, spans = [], []
    monkeypatch.setattr("app.llm.client.start_llm_call", lambda **kw: spans.append(kw))
    client = LLMClient(policy_case[4], transport=httpx.MockTransport(lambda r: sent.append(r)))
    with pytest.raises(DataPolicyError):
        client.generate_text("PRIVATE_SYSTEM", "PRIVATE_INPUT")
    assert sent == [] and spans == []
    client.close()


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_real_sdk_lazy_stream_uses_own_scope(policy_case, protocol):
    from app.llm.client import LLMClient

    session, _ = setup_session(policy_case, protocol)
    sent = []
    text = "STREAM_APPROVED"
    if protocol == "openai_chat_completions":
        events = [{"id": "mock", "choices": [{"index": 0, "delta": {"content": text}}]}]
    elif protocol == "openai_responses":
        events = [{"type": "response.output_text.delta", "delta": text}]
    elif protocol == "anthropic_messages":
        events = [
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": text},
            }
        ]
    else:
        events = [reply(protocol, text)]

    def handler(request):
        sent.append(request)
        sse = "".join(
            ("event: " + e["type"] + "\n" if protocol == "anthropic_messages" else "")
            + "data: "
            + json.dumps(e)
            + "\n\n"
            for e in events
        )
        return httpx.Response(200, content=sse, headers={"content-type": "text/event-stream"})

    client = LLMClient(
        policy_case[4], policy_session=session, transport=httpx.MockTransport(handler)
    )
    assert list(session.stream(client)) == [text]
    assert len(sent) == 1
    client.close()


def test_mutated_projection_and_stream_revoke_release_no_output(policy_case):
    from app.llm.client import LLMClient

    session, refs = setup_session(policy_case)
    sent = []

    def handler(request):
        sent.append(request)
        policy_case[0].revoke_source(policy_case[1], refs[-1])
        return httpx.Response(
            200,
            content='data: {"choices":[{"index":0,"delta":{"content":"MUST_NOT_RENDER"}}]}\n\n',
            headers={"content-type": "text/event-stream"},
        )

    client = LLMClient(
        policy_case[4], policy_session=session, transport=httpx.MockTransport(handler)
    )
    output = []
    with pytest.raises(DataPolicyError):
        output.extend(session.stream(client))
    assert output == [] and len(sent) == 1
    client.close()


def test_snapshot_cannot_be_mutated_to_borrow_a_permit(policy_case):
    from app.llm.client import LLMClient

    session, _ = setup_session(policy_case)
    session.sources[0]["data"]["text"] = "UNREGISTERED_TAMPER"
    sent = []
    client = LLMClient(
        policy_case[4],
        policy_session=session,
        transport=httpx.MockTransport(lambda r: sent.append(r)),
    )
    with pytest.raises(DataPolicyError):
        session.complete(client)
    assert sent == []
    client.close()


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_tool_adapter_raw_sdk_has_no_implicit_permit(policy_case, protocol):
    from app.llm.client import LLMClient
    from app.llm.tool_protocols import adapter_for

    session, _ = setup_session(policy_case, protocol)
    sent = []
    client = LLMClient(
        policy_case[4],
        policy_session=session,
        transport=httpx.MockTransport(lambda r: sent.append(r)),
    )
    wire = session.request(client)
    wire["tools"] = [
        {
            "type": "function",
            "function": {"name": "tool", "description": "PRIVATE_TOOL_SCHEMA", "parameters": {}},
        }
    ]
    with pytest.raises((DataPolicyError, ProtocolCallError, AnthropicConnectionError)) as denied:
        adapter_for(client).complete(wire)
    causes = []
    current = denied.value
    while current is not None and len(causes) < 10:
        causes.append(current)
        current = current.__cause__ or current.__context__
    assert any(
        isinstance(error, DataPolicyError) and error.code == "DATA_INTENT_REQUIRED"
        for error in causes
    )
    assert sent == []
    client.close()


@pytest.mark.parametrize("kind", ["history", "tool_result", "tool_schema", "image", "input"])
def test_unlabelled_auxiliary_sources_deny_before_any_send(policy_case, kind):
    from app.security.data_policy import DataPolicyError
    from app.security.model_egress import ModelPolicySession

    session, refs = setup_session(policy_case)
    unknown = policy_case[0].register_text("t", "member", kind, "PRIVATE_AUXILIARY")
    with pytest.raises(DataPolicyError):
        ModelPolicySession(policy_case[0], session.context, [*refs, unknown])


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_diagnostics_never_log_payload_at_debug(policy_case, protocol, caplog):
    import logging

    from app.llm.client import LLMClient

    session, _ = setup_session(policy_case, protocol)
    client = LLMClient(
        policy_case[4],
        policy_session=session,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json=reply(protocol, "PRIVATE_RESPONSE_MARKER"))
        ),
    )
    with caplog.at_level(logging.DEBUG):
        assert session.complete(client) == "PRIVATE_RESPONSE_MARKER"
    assert "RAW_PRIVATE_MARKER" not in caplog.text
    assert "PRIVATE_RESPONSE_MARKER" not in caplog.text
    assert "synthetic-not-a-credential" not in caplog.text
    client.close()


def test_gemini_retains_configured_timeout(policy_case):
    from app.llm.client import LLMClient

    session, _ = setup_session(policy_case, "gemini_generate_content")
    client = LLMClient(
        policy_case[4], policy_session=session, transport=httpx.MockTransport(lambda r: None)
    )
    assert client.client.timeout.read == client.timeout_seconds
    client.close()
