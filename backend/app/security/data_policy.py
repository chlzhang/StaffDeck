"""Explicit immutable host context. Wire JSON never grants model data permission."""

from dataclasses import dataclass


class DataPolicyError(Exception):
    def __init__(self, code: str):
        self.code = code
        self.public_message = {
            "DATA_TRUSTED_DISPATCH_REQUIRED": "此功能尚未接入资料外发审批；请使用知识库的受控问答。",
            "DATA_INTENT_REQUIRED": "当前调用没有资料外发许可；请使用知识库的受控问答。",
            "DATA_UNCLASSIFIED": "本次问题或资料尚未完成外发审批，请联系管理员审核。",
            "DATA_PROVIDER_UNAPPROVED": "尚无适用于本次回答的已批准供应商，请联系管理员。",
            "DATA_PROVIDER_STALE": "模型配置已改变，请管理员重新确认供应商许可。",
            "DATA_SOURCE_STALE": "资料已变更或归档，请重新准备并审核本次问题。",
            "DATA_POLICY_REVOKED": "资料外发许可已撤回，本次回答已停止。",
            "DATA_QUOTE_DENIED": "该资料只允许使用批准的答复视图，不能发送原文。",
            "DATA_CLASSIFICATION_DENIED": "该资料分类不允许发送给所选供应商。",
            "DATA_PROJECTION_MISMATCH": "本次输入与批准的内容不一致，请重新准备问题。",
        }.get(code, "资料外发校验未通过，本次操作已停止，请管理员检查许可。")
        super().__init__(f"{code}: {self.public_message}")

    def public_detail(self):
        return {"code": self.code, "message": self.public_message, "retryable": False}


@dataclass(frozen=True)
class PolicyContext:
    tenant_id: str
    principal_id: str
    provider_policy_id: str
    purpose: str
    agent_id: str | None = None
    session_id: str | None = None
    activation_id: str | None = None


@dataclass(frozen=True)
class DataEnvelopeRef:
    envelope_id: str
    revision: int = 1


@dataclass(frozen=True)
class ModelCallIntent:
    context: PolicyContext
    envelope_refs: tuple[DataEnvelopeRef, ...]
    answer_mode: str
    representation: str
    policy_epoch: int
