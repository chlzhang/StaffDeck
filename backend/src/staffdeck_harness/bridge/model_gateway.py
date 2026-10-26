"""OpenAI-compatible model gateway for the Harness v3 subprocess.

The Harness v3 engine speaks ``POST {baseURL}/chat/completions`` (OpenAI wire, DeepSeek
extensions). Instead of handing the Node process a real API key and letting it
talk to the provider itself, the bridge points ``baseURL`` at this endpoint,
served on the same localhost port as the capability MCP server, and uses the
per-turn **activation token** as the API key.

F03 pilot: an activation alone does not authorize model data. A dedicated
host-owned ModelPolicySession must match the complete approved projection.
Unknown history, tools, images, remote context IDs and extra fields are rejected.
All four protocols use the guarded driver. Streams are buffered and rendered
before SSE; the general tool-aware engine is intentionally closed until its
provenance is integrated. Provider credentials remain in Python.
"""

from __future__ import annotations

import json
from copy import deepcopy
from collections.abc import Callable
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse

from staffdeck_harness.bridge.capability_mcp import ActivationRegistry

CHAT_COMPLETIONS_PATH = "/v1/chat/completions"
# The engine sends a 256k default; we never let a single step exceed the model's own cap.
_MAX_TOKENS_FLOOR = 256


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "type": code.lower(), "message": message}}, status_code=status)


def _bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return None


def _dump(obj: Any) -> dict[str, Any]:
    """Adapters hand back plain dicts; keep tolerating SDK objects for safety."""
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump(mode="json", exclude_none=True)
        except TypeError:
            return obj.model_dump()
    return {"raw": str(obj)}


def _vision_messages(messages, payloads):
    """Project validated current-turn images through the existing protocol adapters only.

    Never mutate Node messages, replay old images, or persist raw data URLs in checkpoints.
    The activation token scopes these bytes to the authorized Staff/turn/phase.
    """
    from app.core.harness_attachments import ValidatedTaskImagePayload

    parts = [{"type": "image_url", "image_url": {"url": p.data_url}}
             for p in payloads if isinstance(p, ValidatedTaskImagePayload)]
    if not parts:
        return messages
    copied = deepcopy(messages)
    target = next((m for m in reversed(copied) if m.get("role") == "user"), None)
    if target is None:
        target = {"role": "user", "content": []}
        copied.append(target)
    content = target.get("content")
    target["content"] = ([{"type": "text", "text": content}] if isinstance(content, str) else list(content or [])) + parts
    return copied


class ModelGateway:
    """Mounted on the bridge's Starlette app; one instance per HarnessV3Runtime."""

    def __init__(self, registry: ActivationRegistry, *, client_factory: Callable[[Any], Any] | None = None):
        self.registry = registry
        self._client_factory = client_factory or self._default_client

    @staticmethod
    def _default_client(model_config: Any) -> Any:
        from app.llm.client import LLMClient

        return LLMClient(model_config)

    def mount(self, app: Any) -> None:
        app.add_route(CHAT_COMPLETIONS_PATH, self.chat_completions, methods=["POST"])

    # -- endpoint --------------------------------------------------------------

    async def chat_completions(self, request: Request):
        token = _bearer(request)
        if not token:
            return _error(401, "MISSING_CREDENTIAL", "missing activation token")
        act = self.registry.get(token)
        if act is None:
            return _error(404, "ACTIVATION_FENCED", "no live activation for this token (turn finished or cancelled)")
        model_config = getattr(act.host, "model_config", None)
        act.host.model_error = None
        if model_config is None:
            return _error(409, "MODEL_NOT_CONFIGURED", "该员工没有可用的默认模型，请先在「模型配置」中设置")
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return _error(400, "MALFORMED_REQUEST", "request body is not JSON")
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            return _error(400, "MALFORMED_REQUEST", "messages must be a list")

        # The Node engine cannot mint provenance by adding fields to JSON.
        # Only a host-owned, approved projection is accepted by the pilot.
        from app.security.model_egress import ModelPolicySession
        session = getattr(act.host, "model_policy_session", None)
        if not isinstance(session, ModelPolicySession):
            act.host.model_error = "此数字员工尚未接入资料外发审批，模型调用已停用；请使用知识库的受控问答。"
            return _error(409, "DATA_INTENT_REQUIRED", act.host.model_error)
        client = None
        try:
            client = self._client_factory(model_config)
            if getattr(client, "_model_policy_session", None) is not session:
                # The factory must explicitly accept this host session. Never
                # retrofit an arbitrary shared client with a last-call context.
                return _error(409, "DATA_INTENT_REQUIRED", "dedicated approved client required")
            expected = session.request(client)
            if (set(body) - {"messages", "stream"}
                    or body["messages"] != expected["messages"]
                    or getattr(act.host, "image_payloads", ())):
                return _error(409, "DATA_PROJECTION_MISMATCH", "unregistered model input")
            import asyncio
            from functools import partial
            stream = bool(body.get("stream", False))
            loop = asyncio.get_running_loop()
            if stream:
                # Context is established inside each worker dispatch. Buffering
                # also keeps selectors/reasoning/tool arguments out of SSE.
                parts = await loop.run_in_executor(None, lambda: list(session.stream(client)))
                data = {"id": "governed", "choices": [{"index": 0, "delta": {"content": "".join(parts)}, "finish_reason": "stop"}]}
                async def body_iter():
                    yield ("data: " + json.dumps(data, ensure_ascii=False) + "\n\n").encode()
                    yield b"data: [DONE]\n\n"
                return StreamingResponse(body_iter(), media_type="text/event-stream")
            answer = await loop.run_in_executor(None, partial(session.complete, client))
            return JSONResponse({"id": "governed", "choices": [{"index": 0, "message": {"role": "assistant", "content": answer}, "finish_reason": "stop"}]})
        except Exception:  # noqa: BLE001 - do not expose provider data
            act.host.model_error = "DATA_MODEL_CALL_FAILED"
            return _error(409, "DATA_MODEL_CALL_FAILED", "model data policy rejected or call failed")
        finally:
            if client is not None:
                client.close()

    # -- request shaping ----------------------------------------------------------

    @staticmethod
    def _wire_request(client: Any, model_config: Any, body: dict[str, Any]) -> dict[str, Any]:
        from app.llm.client import _thinking_request_kwargs

        cap = int(getattr(model_config, "max_output_tokens", 0) or 0)
        requested = body.get("max_tokens")
        max_tokens = cap if not isinstance(requested, int) or requested <= 0 else (min(requested, cap) if cap else requested)
        # ``stream`` is never part of the wire dict: ChatCompletionsDriver.stream() adds it itself and
        # complete() must not carry it (the OpenAI SDK rejects duplicate keywords).
        streaming = bool(body.get("stream", True))
        wire: dict[str, Any] = {
            "model": client.model,                       # the ModelConfig decides, not the subprocess
            "messages": body["messages"],
            "temperature": getattr(client, "temperature", None),
        }
        if wire["temperature"] is None:
            wire.pop("temperature")
        if max_tokens and max_tokens >= _MAX_TOKENS_FLOOR:
            wire["max_tokens"] = max_tokens
        if isinstance(body.get("tools"), list) and body["tools"]:
            wire["tools"] = body["tools"]
            if body.get("tool_choice") is not None:
                wire["tool_choice"] = body["tool_choice"]
        if isinstance(body.get("stop"), list) and body["stop"]:
            wire["stop"] = body["stop"]
        if streaming and isinstance(body.get("stream_options"), dict):
            wire["stream_options"] = body["stream_options"]
        # Thinking policy = ModelConfig (merged extra_body / protocol options), never the engine's own default.
        wire.update(_thinking_request_kwargs(getattr(client, "thinking_mode", ""), getattr(client, "extra_body", {})))
        return wire


def _usage(usage: Any) -> dict[str, Any]:
    if not isinstance(usage, dict):
        return {}
    out = {}
    for src, dst in (("prompt_tokens", "input_tokens"), ("completion_tokens", "output_tokens"), ("total_tokens", "total_tokens")):
        if isinstance(usage.get(src), int):
            out[dst] = usage[src]
    return out
