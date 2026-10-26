import json
from types import SimpleNamespace

import httpx
import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient
from test_data_policy import policy_case as policy_case  # noqa: PLC0414
from test_model_data_egress import PROTOCOLS, reply, setup_session

from staffdeck_harness.bridge.capability_mcp import ActivationRegistry
from staffdeck_harness.bridge.model_gateway import CHAT_COMPLETIONS_PATH, ModelGateway


@pytest.mark.parametrize("stream", [False, True])
def test_unknown_gateway_history_tools_and_images_send_zero(policy_case, stream):
    from app.llm.client import LLMClient

    session, _ = setup_session(policy_case)
    sent, traces = [], []
    reg = ActivationRegistry()
    host = SimpleNamespace(
        model_config=policy_case[4],
        model_policy_session=session,
        image_payloads=[{"url": "PRIVATE_IMAGE"}],
        trace=lambda *args: traces.append(args),
    )
    act = reg.register(host, lambda tid: None)
    app = Starlette()
    ModelGateway(
        reg,
        client_factory=lambda model: LLMClient(
            model,
            policy_session=session,
            transport=httpx.MockTransport(lambda r: sent.append(r)),
        ),
    ).mount(app)
    with TestClient(app) as api:
        result = api.post(
            CHAT_COMPLETIONS_PATH,
            headers={"authorization": "Bearer " + act.token},
            json={
                "messages": [{"role": "user", "content": "UNKNOWN_HISTORY"}],
                "stream": stream,
                "tools": [{"name": "UNLABELLED_TOOL"}],
            },
        )
    assert result.status_code == 409
    assert sent == []
    assert "UNKNOWN_HISTORY" not in json.dumps(traces)
    assert "PRIVATE_IMAGE" not in json.dumps(traces)


def test_gateway_without_host_intent_stops_before_client_factory(policy_case):
    created = []
    reg = ActivationRegistry()
    act = reg.register(SimpleNamespace(model_config=policy_case[4]), lambda tid: None)
    app = Starlette()
    ModelGateway(reg, client_factory=lambda model: created.append(model)).mount(app)
    with TestClient(app) as api:
        r = api.post(
            CHAT_COMPLETIONS_PATH,
            headers={"authorization": "Bearer " + act.token},
            json={"messages": [{"role": "user", "content": "UNKNOWN"}]},
        )
    assert r.status_code == 409
    assert "受控问答" in r.json()["error"]["message"]
    assert act.host.model_error == r.json()["error"]["message"]
    assert created == []


@pytest.mark.parametrize("stream", [False, True])
def test_host_approved_gateway_dispatch_crosses_executor(policy_case, stream):
    from app.llm.client import LLMClient

    session, _ = setup_session(policy_case)
    sent = []

    def factory(model):
        def handle(r):
            sent.append(r)
            if stream:
                return httpx.Response(
                    200,
                    content='data: {"id":"mock","choices":[{"index":0,"delta":{"content":"APPROVED_EXECUTOR"}}]}\n\n',
                    headers={"content-type": "text/event-stream"},
                )
            return httpx.Response(200, json=reply(PROTOCOLS[0], "APPROVED_EXECUTOR"))

        return LLMClient(model, policy_session=session, transport=httpx.MockTransport(handle))

    client = factory(policy_case[4])
    messages = session.request(client)["messages"]
    client.close()
    reg = ActivationRegistry()
    act = reg.register(
        SimpleNamespace(model_config=policy_case[4], model_policy_session=session), lambda tid: None
    )
    app = Starlette()
    ModelGateway(reg, client_factory=factory).mount(app)
    with TestClient(app) as api:
        response = api.post(
            CHAT_COMPLETIONS_PATH,
            headers={"authorization": "Bearer " + act.token},
            json={"messages": messages, "stream": stream},
        )
    assert response.status_code == 200
    assert "APPROVED_EXECUTOR" in response.text
    assert len(sent) == 1
