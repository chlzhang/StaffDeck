"""Additive data-governance tables; importing registers them with SQLModel metadata."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


def _now():
    return datetime.now(UTC).replace(tzinfo=None)


class DataResourcePolicy(SQLModel, table=True):
    __tablename__ = "data_resource_policies"
    envelope_id: str = Field(primary_key=True)
    tenant_id: str = Field(index=True)
    classification: str = "unclassified"
    answer_mode: str = "none"
    grants_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    denied_providers_json: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    revision: int = 1
    active: bool = True
    approved_by: str
    approved_at: datetime = Field(default_factory=_now)


class DataEnvelope(SQLModel, table=True):
    __tablename__ = "data_envelopes"
    id: str = Field(default_factory=lambda: "data_" + uuid4().hex, primary_key=True)
    tenant_id: str = Field(index=True)
    owner_id: str
    source_kind: str
    source_id: str
    source_stamp: str = ""
    representation: str = "raw"
    payload_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    parents_json: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    digest: str
    revision: int = 1
    active: bool = True
    created_at: datetime = Field(default_factory=_now)


class ProviderDataPolicy(SQLModel, table=True):
    __tablename__ = "provider_data_policies"
    id: str = Field(default_factory=lambda: "provider_policy_" + uuid4().hex, primary_key=True)
    tenant_id: str = Field(index=True)
    model_config_id: str = Field(index=True)
    config_digest: str
    purposes_json: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    classifications_json: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    approved_by: str
    terms_reference: str = ""
    revision: int = 1
    active: bool = True
    created_at: datetime = Field(default_factory=_now)


class DataPolicyAudit(SQLModel, table=True):
    __tablename__ = "data_policy_audits"
    id: str = Field(default_factory=lambda: "data_audit_" + uuid4().hex, primary_key=True)
    tenant_id: str = Field(index=True)
    principal_id: str
    action: str
    object_id: str
    reason: str
    created_at: datetime = Field(default_factory=_now)
