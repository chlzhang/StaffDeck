"""Fail-closed model boundary over the final SDK HTTP request.

Only this host-owned dispatch builds a permit. Labels in model/gateway JSON are
never permits. A permit binds the exact projection, destination and SDK headers;
every transport attempt and every streamed chunk rechecks current approvals.
"""

from __future__ import annotations

import copy
import json
import logging
from contextvars import ContextVar
from dataclasses import dataclass

import httpx
from sqlmodel import Session

from app.security.data_policy import DataPolicyError
from app.security.data_policy_store import PolicyStore, digest

SYSTEM_TEMPLATE = "Answer using only the supplied approved sources. Return no unsupported claims."
CONTROLLED_TEMPLATE = "Select approved answer views. Return only JSON with one key view_ids containing their envelope IDs."


class _OpaqueSDKLog(logging.Filter):
    def filter(self, record):
        record.msg = "MODEL_SDK_EVENT"
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


def _protect_sdk_diagnostics():
    # SDK debug logging happens before the transport, so transport redaction is
    # too late. Keep class/level/category only, including SDK exception echoes.
    names = {
        "openai._base_client",
        "anthropic._base_client",
        "httpcore.http11",
        "httpcore.http2",
        "httpcore.connection",
        "httpcore.proxy",
    }
    names.update(
        name
        for name in logging.Logger.manager.loggerDict
        if name.startswith(("openai.", "anthropic.", "httpcore."))
    )
    for name in names:
        logger = logging.getLogger(name)
        if not any(isinstance(item, _OpaqueSDKLog) for item in logger.filters):
            logger.addFilter(_OpaqueSDKLog())


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DataPolicyError("DATA_DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(value):
    raise DataPolicyError("DATA_JSON_CONSTANT_INVALID")


@dataclass(frozen=True)
class PreparedSend:
    session: object
    body_digest: str
    url: str


class GuardedModelTransport(httpx.BaseTransport):
    def __init__(self, delegate):
        self.delegate = delegate
        self.scope = ContextVar("model_data_send", default=None)
        self.headers = {}

    def handle_request(self, request):
        permit = self.scope.get()
        if permit is None:
            raise DataPolicyError("DATA_INTENT_REQUIRED")
        try:
            permit.session.validate()
            if request.method != "POST" or str(request.url) != permit.url:
                raise DataPolicyError("DATA_DESTINATION_MISMATCH")
            if len(request.content) > 1024 * 1024:
                raise DataPolicyError("DATA_REQUEST_TOO_LARGE")
            actual = json.loads(
                request.content, object_pairs_hook=_strict_object, parse_constant=_reject_constant
            )
            if digest(actual) != permit.body_digest:
                raise DataPolicyError("DATA_REQUEST_MISMATCH")
            for name, value in request.headers.multi_items():
                if name == "content-length" and value == str(len(request.content)):
                    continue
                if name == "content-type" and value == "application/json":
                    continue
                if name == "x-stainless-retry-count" and value in {"0", "1", "2"}:
                    continue
                if self.headers.get(name) != value:
                    raise DataPolicyError("DATA_HEADER_MISMATCH")
            return self.delegate.handle_request(request)
        except DataPolicyError:
            raise
        except Exception:  # noqa: BLE001 - fail closed without retaining upstream content
            raise DataPolicyError("DATA_VALIDATION_FAILED") from None

    def close(self):
        self.delegate.close()


class ModelPolicySession:
    """Explicit host context, never attached to a shared client's last request."""

    def __init__(self, store, context, refs, *, answer_mode="answer_with_quote"):
        self.bind = store.db.get_bind()
        self.context = context
        self.intent = store.issue_intent(
            context,
            refs,
            answer_mode=answer_mode,
            representation="answer_view" if answer_mode == "controlled_answer" else "raw",
        )
        self.model_config_id = store.provider(context).model_config_id
        self.model_stamp = store.provider(context).config_digest
        self.sources = []
        templates = 0
        for ref in refs:
            row = store.envelope(ref, context.tenant_id)
            if row.source_kind == "system_template":
                if row.payload_json != {"text": SYSTEM_TEMPLATE}:
                    raise DataPolicyError("DATA_TEMPLATE_INVALID")
                templates += 1
            else:
                if answer_mode == "controlled_answer" and row.source_kind not in {
                    "answer_view",
                    "input",
                }:
                    raise DataPolicyError("DATA_QUOTE_DENIED")
                self.sources.append(
                    {
                        "envelope_id": row.id,
                        "kind": row.source_kind,
                        "data": copy.deepcopy(row.payload_json),
                    }
                )
        if templates != 1 or not self.sources:
            raise DataPolicyError("DATA_TEMPLATE_REQUIRED")
        self._projection_digest = digest(self.sources)

    def validate(self):
        with Session(self.bind) as db:
            PolicyStore(db).validate(self.intent)

    def request(self, client):
        self.validate()
        if digest(self.sources) != self._projection_digest:
            raise DataPolicyError("DATA_CONTENT_CHANGED")
        if (
            client.model_config_id != self.model_config_id
            or client.model_policy_stamp != self.model_stamp
        ):
            raise DataPolicyError("DATA_PROVIDER_MISMATCH")
        # Options containing arbitrary text/tool schemas/images require a future
        # explicit projection. They cannot be smuggled through extra_body here.
        if client.extra_body or client.thinking_mode:
            raise DataPolicyError("DATA_OPTIONS_UNSUPPORTED")
        return {
            "model": client.model,
            "messages": [
                {
                    "role": "system",
                    "content": CONTROLLED_TEMPLATE
                    if self.intent.answer_mode == "controlled_answer"
                    else SYSTEM_TEMPLATE,
                },
                {
                    "role": "user",
                    "content": json.dumps(self.sources, ensure_ascii=False, sort_keys=True),
                },
            ],
            "temperature": client.temperature,
            "max_tokens": client.max_output_tokens,
        }

    def check_input(self, client, system_prompt, user_payload, *, response_format=None):
        expected = self.request(client)["messages"]
        if (
            response_format is not None
            or not isinstance(user_payload, str)
            or system_prompt != expected[0]["content"]
            or user_payload != expected[1]["content"]
        ):
            raise DataPolicyError("DATA_PROJECTION_MISMATCH")

    def _permit(self, client, request, stream):
        if getattr(client, "_model_policy_session", None) is not self:
            raise DataPolicyError("DATA_INTENT_REQUIRED")
        driver = client.driver
        body = driver.observable_request(request, stream=stream)
        protocol = str(client.api_protocol)
        # StrEnum values are wire names; tolerate Enum's display spelling only
        # through the explicit .value field.
        protocol = getattr(client.api_protocol, "value", protocol)
        if protocol == "anthropic_messages":
            body["stream"] = stream
            url = str(client.client.base_url).rstrip("/") + "/v1/messages"
        elif protocol == "gemini_generate_content":
            from app.llm.protocol_drivers import _gemini_endpoint

            url = _gemini_endpoint(
                client.base_url,
                client.model,
                "streamGenerateContent" if stream else "generateContent",
                stream=stream,
            )
        else:
            url = str(client.client.base_url).rstrip("/") + (
                "/responses" if protocol == "openai_responses" else "/chat/completions"
            )
        return PreparedSend(self, digest(body), url)

    def _audit(self, code):
        with Session(self.bind) as db:
            PolicyStore(db).audit(
                self.context.tenant_id,
                self.context.principal_id,
                "model_egress",
                self.context.provider_policy_id,
                code,
            )

    def complete(self, client):
        try:
            request = self.request(client)
            permit = self._permit(client, request, False)
            token = client._egress_transport.scope.set(permit)
            try:
                completion = client.driver.complete(request)
            finally:
                client._egress_transport.scope.reset(token)
            content = str(completion.choices[0].message.content or "")
            result = self.render(content)
            self._audit("ALLOWED")
            return result
        except Exception:  # noqa: BLE001 - fail closed without retaining upstream content
            self._audit("DENIED_OR_FAILED")
            raise DataPolicyError("DATA_MODEL_CALL_FAILED") from None

    def stream(self, client):
        """Buffer before rendering; no uncontrolled output escapes a view policy."""
        try:
            request = self.request(client)
            permit = self._permit(client, request, True)
            transport = client._egress_transport
            token = transport.scope.set(permit)
            try:
                iterator = iter(client.driver.stream(request))
            finally:
                transport.scope.reset(token)
            parts = []
            while True:
                self.validate()
                token = transport.scope.set(permit)
                try:
                    chunk = next(iterator)
                except StopIteration:
                    break
                finally:
                    transport.scope.reset(token)
                for choice in chunk.choices or []:
                    parts.append(str(getattr(choice.delta, "content", "") or ""))
            result = self.render("".join(parts))
            self._audit("ALLOWED")
            yield result
        except Exception:  # noqa: BLE001 - fail closed without retaining upstream content
            self._audit("DENIED_OR_FAILED")
            raise DataPolicyError("DATA_MODEL_CALL_FAILED") from None
        finally:
            if "iterator" in locals():
                close = getattr(iterator, "close", None)
                if close:
                    close()

    def render(self, content):
        self.validate()
        if self.intent.answer_mode != "controlled_answer":
            return content
        try:
            selection = json.loads(content)
            views = {
                row["envelope_id"]: row["data"]["text"]
                for row in self.sources
                if row["kind"] == "answer_view"
            }
            if (
                not isinstance(selection, dict)
                or set(selection) != {"view_ids"}
                or not isinstance(selection["view_ids"], list)
                or not selection["view_ids"]
                or len(selection["view_ids"]) > len(views)
                or any(
                    not isinstance(key, str) or key not in views for key in selection["view_ids"]
                )
            ):
                raise ValueError
            return "\n\n".join(views[key] for key in dict.fromkeys(selection["view_ids"]))
        except Exception:  # noqa: BLE001 - fail closed without retaining upstream content
            raise DataPolicyError("DATA_ANSWER_VIEW_INVALID") from None


def configure_transport(client, guard, api_key):
    """Freeze factory headers; later SDK options cannot extend their authority."""
    _protect_sdk_diagnostics()
    protocol = getattr(client.api_protocol, "value", str(client.api_protocol))
    if protocol == "gemini_generate_content":
        from app.llm.protocol_drivers import _gemini_headers

        headers = dict(client.client.headers)
        headers.update(_gemini_headers(api_key))
    else:
        headers = dict(client.client._client.headers)
        headers.update(
            {
                k.lower(): str(v)
                for k, v in client.client.default_headers.items()
                if isinstance(v, (str, int))
            }
        )
        headers.update(client.client.auth_headers)
    headers["host"] = httpx.URL(client.base_url).netloc.decode()
    sdk_timeout = client.client.timeout
    headers["x-stainless-read-timeout"] = str(getattr(sdk_timeout, "read", sdk_timeout))
    headers["x-stainless-timeout"] = "NOT_GIVEN"
    guard.headers = {key.lower(): value for key, value in headers.items()}
