"""Current SQLite data approvals and immutable provenance. No legacy implicit grants."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Sequence
from urllib.parse import urlsplit

from sqlalchemy import update
from sqlmodel import Session, select

from app.agents.branching import visible_knowledge_base_version_ids
from app.db.models import (
    DataEnvelope,
    DataPolicyAudit,
    DataResourcePolicy,
    KnowledgeBase,
    KnowledgeBaseVersion,
    KnowledgeDocument,
    ModelConfig,
    ProviderDataPolicy,
    User,
)
from app.security.data_policy import (
    DataEnvelopeRef,
    DataPolicyError,
    ModelCallIntent,
    PolicyContext,
)
from app.security.permissions import ensure_tenant_admin, require_agent_scope_viewer


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
    ).hexdigest()


def model_digest(model) -> str:
    from collections.abc import Mapping

    from app.llm.model_config_resolver import snapshot_model_config

    snapshot = snapshot_model_config(model)

    def plain(value):
        if isinstance(value, Mapping):
            return {key: plain(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [plain(item) for item in value]
        return value

    return digest(
        {
            name: plain(getattr(snapshot, name))
            for name in (
                "id",
                "tenant_id",
                "base_url",
                "model",
                "api_protocol",
                "config_revision",
                "security_revision",
                "key_revision",
                "protocol_options",
                "legacy_extra_body",
                "api_key_encrypted",
                "temperature",
                "max_output_tokens",
            )
        }
    )


def document_payload(document: KnowledgeDocument) -> dict:
    return {
        "document_id": document.id,
        "filename": document.filename,
        "title": document.title,
        "text": str((document.metadata_json or {}).get("raw_text") or ""),
        "knowledge_base_id": document.knowledge_base_id,
        "knowledge_base_version_id": document.knowledge_base_version_id,
    }


def document_stamp(document, db):
    # Supported edits/archive/restore advance updated_at. Matching old text is
    # insufficient to resurrect an approval, view, history or in-flight intent.
    parents = []
    for model, identifier in (
        (KnowledgeBase, document.knowledge_base_id),
        (KnowledgeBaseVersion, document.knowledge_base_version_id),
    ):
        row = db.get(model, identifier, populate_existing=True) if identifier else None
        parents.append(
            None
            if row is None
            else {
                "id": row.id,
                "tenant_id": row.tenant_id,
                "updated_at": row.updated_at.isoformat(),
                "status": row.status,
            }
        )
    return digest(
        {
            "payload": document_payload(document),
            "updated_at": document.updated_at.isoformat(),
            "parents": parents,
        }
    )


class PolicyStore:
    def __init__(self, db: Session):
        self.db = db

    def check_document_access(self, document, user, agent_id=None):
        if document.tenant_id != user.tenant_id:
            raise DataPolicyError("DATA_ACCESS_DENIED")
        require_agent_scope_viewer(user.tenant_id, agent_id, user, self.db)
        if document.knowledge_base_version_id not in visible_knowledge_base_version_ids(
            self.db,
            user.tenant_id,
            agent_id,
        ):
            raise DataPolicyError("DATA_ACCESS_DENIED")
        from app.security.module_policy import require_resource
        from staffdeck_harness.contracts.security import ResourceRef

        require_resource(
            user,
            ResourceRef(
                type="knowledge_base",
                id=document.knowledge_base_id,
                tenant_id=user.tenant_id,
            ),
            "use",
            module="knowledge",
            local_checked=True,
        )

    def audit(self, tenant, principal, action, object_id, reason):
        self.db.add(
            DataPolicyAudit(
                tenant_id=tenant,
                principal_id=principal,
                action=action,
                object_id=object_id,
                reason=reason,
            )
        )
        self.db.commit()

    def _invalidate(self, tenant):
        self.db.exec(
            update(ProviderDataPolicy)
            .where(
                ProviderDataPolicy.tenant_id == tenant,
            )
            .values(revision=ProviderDataPolicy.revision + 1)
        )
        self.db.flush()

    def approve_provider(
        self,
        admin: User,
        model_id: str,
        *,
        purposes: list[str],
        classifications: list[str] | None = None,
        terms_reference: str = "",
    ) -> ProviderDataPolicy:
        model = self.db.get(ModelConfig, model_id, populate_existing=True)
        if model is None:
            raise DataPolicyError("DATA_PROVIDER_NOT_FOUND")
        ensure_tenant_admin(model.tenant_id, admin)
        if not terms_reference.strip():
            raise DataPolicyError("DATA_TERMS_REQUIRED")
        url = urlsplit(model.base_url or "")
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise DataPolicyError("DATA_PROVIDER_DESTINATION_INVALID")
        allowed = classifications if classifications is not None else ["public"]
        if not allowed or not set(allowed) <= {"public", "internal"} or not purposes:
            raise DataPolicyError("DATA_PROVIDER_SCOPE_INVALID")
        row = ProviderDataPolicy(
            tenant_id=model.tenant_id,
            model_config_id=model.id,
            config_digest=model_digest(model),
            purposes_json=sorted(set(purposes)),
            classifications_json=sorted(set(allowed)),
            approved_by=admin.id,
            terms_reference=terms_reference,
        )
        self.db.add(row)
        self.db.commit()
        self.audit(row.tenant_id, admin.id, "provider_approved", row.id, "APPROVED")
        return row

    def revoke_provider(self, admin: User, provider_id: str):
        row = self.db.get(ProviderDataPolicy, provider_id, populate_existing=True)
        if row is None:
            raise DataPolicyError("DATA_PROVIDER_NOT_FOUND")
        ensure_tenant_admin(row.tenant_id, admin)
        row.active = False
        row.revision += 1
        self.db.add(row)
        self.db.commit()
        self.audit(row.tenant_id, admin.id, "provider_revoked", row.id, "REVOKED")

    def _register(
        self,
        tenant,
        owner,
        kind,
        source_id,
        payload,
        *,
        source_stamp="",
        representation="raw",
        parents=(),
        commit=True,
    ) -> DataEnvelopeRef:
        parent_values = [
            {"envelope_id": ref.envelope_id, "revision": ref.revision} for ref in parents
        ]
        for ref in parents:
            self.envelope(ref, tenant)
        value = {"payload": payload, "parents": parent_values, "representation": representation}
        row = DataEnvelope(
            tenant_id=tenant,
            owner_id=owner,
            source_kind=kind,
            source_id=source_id,
            source_stamp=source_stamp,
            representation=representation,
            payload_json=copy.deepcopy(payload),
            parents_json=parent_values,
            digest=digest(value),
        )
        self.db.add(row)
        if commit:
            self.db.commit()
        else:
            self.db.flush()
        return DataEnvelopeRef(row.id, row.revision)

    def register_document(self, document: KnowledgeDocument, actor: User) -> DataEnvelopeRef:
        if actor.tenant_id != document.tenant_id:
            raise DataPolicyError("DATA_ACCESS_DENIED")
        stamp = document_stamp(document, self.db)
        existing = self.db.exec(
            select(DataEnvelope)
            .where(
                DataEnvelope.tenant_id == document.tenant_id,
                DataEnvelope.source_kind == "document",
                DataEnvelope.source_id == document.id,
                DataEnvelope.source_stamp == stamp,
                DataEnvelope.active == True,
            )
            .order_by(DataEnvelope.created_at, DataEnvelope.id)
        ).first()
        if existing is not None:
            ref = DataEnvelopeRef(existing.id, existing.revision)
            self.envelope(ref, document.tenant_id)
            return ref
        return self._register(
            document.tenant_id,
            actor.id,
            "document",
            document.id,
            document_payload(document),
            source_stamp=document_stamp(document, self.db),
        )

    def register_text(self, tenant, owner, kind, text) -> DataEnvelopeRef:
        user = self.db.get(User, owner, populate_existing=True)
        if (
            user is None
            or user.tenant_id != tenant
            or kind
            not in {
                "input",
                "system_template",
                "history",
                "tool_result",
                "tool_schema",
                "image",
            }
        ):
            raise DataPolicyError("DATA_SOURCE_INVALID")
        return self._register(tenant, owner, kind, "", {"text": str(text)})

    def derive(
        self,
        tenant,
        owner,
        kind,
        text,
        parents: Sequence[DataEnvelopeRef],
    ) -> DataEnvelopeRef:
        if not parents:
            raise DataPolicyError("DATA_LINEAGE_MISSING")
        return self._register(
            tenant,
            owner,
            kind,
            "",
            {"text": str(text)},
            parents=parents,
            representation="answer_view" if kind == "answer_view" else "derived",
        )

    def envelope(self, ref: DataEnvelopeRef, tenant: str) -> DataEnvelope:
        row = self.db.get(DataEnvelope, ref.envelope_id, populate_existing=True)
        if row is None or row.tenant_id != tenant or not row.active or row.revision != ref.revision:
            raise DataPolicyError("DATA_SOURCE_STALE")
        if row.digest != digest(
            {
                "payload": row.payload_json,
                "parents": row.parents_json,
                "representation": row.representation,
            }
        ):
            raise DataPolicyError("DATA_CONTENT_CHANGED")
        return row

    def approve_source(
        self,
        admin: User,
        ref: DataEnvelopeRef,
        *,
        classification: str,
        answer_mode: str,
        grants: dict,
        denied_providers: list[str] | None = None,
    ):
        row = self.envelope(ref, admin.tenant_id)
        ensure_tenant_admin(row.tenant_id, admin)
        if classification not in {
            "unclassified",
            "public",
            "internal",
            "confidential",
            "restricted",
        }:
            raise DataPolicyError("DATA_CLASSIFICATION_INVALID")
        if answer_mode not in {"none", "controlled_answer", "answer_with_quote"}:
            raise DataPolicyError("DATA_ANSWER_MODE_INVALID")
        existing = self.db.get(DataResourcePolicy, ref.envelope_id)
        policy = existing or DataResourcePolicy(
            envelope_id=ref.envelope_id,
            tenant_id=row.tenant_id,
            approved_by=admin.id,
        )
        policy.classification = classification
        policy.answer_mode = answer_mode
        policy.grants_json = copy.deepcopy(grants)
        policy.denied_providers_json = list(denied_providers or ())
        policy.approved_by = admin.id
        policy.active = True
        policy.revision += int(existing is not None)
        self.db.add(policy)
        self._invalidate(row.tenant_id)
        self.db.commit()
        self.audit(row.tenant_id, admin.id, "source_approved", ref.envelope_id, "APPROVED")
        return policy

    def revoke_source(self, admin: User, ref: DataEnvelopeRef):
        row = self.envelope(ref, admin.tenant_id)
        ensure_tenant_admin(row.tenant_id, admin)
        policy = self.db.get(DataResourcePolicy, ref.envelope_id, populate_existing=True)
        if policy is None:
            raise DataPolicyError("DATA_UNCLASSIFIED")
        policy.active = False
        policy.revision += 1
        self._invalidate(row.tenant_id)
        self.db.commit()
        self.audit(row.tenant_id, admin.id, "source_revoked", ref.envelope_id, "REVOKED")

    def provider(self, context: PolicyContext) -> ProviderDataPolicy:
        row = self.db.get(ProviderDataPolicy, context.provider_policy_id, populate_existing=True)
        if row is None or row.tenant_id != context.tenant_id or not row.active:
            raise DataPolicyError("DATA_PROVIDER_UNAPPROVED")
        model = self.db.get(ModelConfig, row.model_config_id, populate_existing=True)
        if model is None or not model.enabled or model_digest(model) != row.config_digest:
            raise DataPolicyError("DATA_PROVIDER_STALE")
        if context.purpose not in row.purposes_json:
            raise DataPolicyError("DATA_PURPOSE_DENIED")
        return row

    def _check(
        self,
        context: PolicyContext,
        ref: DataEnvelopeRef,
        provider: ProviderDataPolicy,
        representation: str,
        answer_mode: str,
        visiting: set[str],
    ):
        if ref.envelope_id in visiting or len(visiting) > 32:
            raise DataPolicyError("DATA_LINEAGE_INVALID")
        visiting = visiting | {ref.envelope_id}
        row = self.envelope(ref, context.tenant_id)
        user = self.db.get(User, context.principal_id, populate_existing=True)
        if user is None or user.tenant_id != context.tenant_id:
            raise DataPolicyError("DATA_ACCESS_DENIED")
        if row.source_kind == "document":
            document = self.db.get(KnowledgeDocument, row.source_id, populate_existing=True)
            if document is None or document.tenant_id != context.tenant_id:
                raise DataPolicyError("DATA_ACCESS_DENIED")
            self.check_document_access(document, user, context.agent_id)
            if document.status != "ready" or document_stamp(document, self.db) != row.source_stamp:
                raise DataPolicyError("DATA_SOURCE_STALE")
        elif not row.parents_json and row.source_kind != "system_template":
            if row.owner_id != user.id and user.role != "admin":
                raise DataPolicyError("DATA_ACCESS_DENIED")
        for parent in row.parents_json:
            self._check(
                context, DataEnvelopeRef(**parent), provider, representation, answer_mode, visiting
            )
        policy = self.db.get(DataResourcePolicy, row.id, populate_existing=True)
        if policy is None:
            if row.parents_json and row.source_kind != "answer_view":
                return
            raise DataPolicyError("DATA_UNCLASSIFIED")
        self._check_policy(policy, context, provider, representation, answer_mode)
        if row.source_kind == "document":
            self.check_document_origin_policies(context, row, provider, representation, answer_mode)

    def check_document_origin_policies(
        self, context, source, provider, representation="raw", answer_mode="answer_with_quote"
    ):
        # Legacy/concurrent duplicate snapshots cannot shed another approval's
        # restrictions. Absence of a policy still never grants this envelope.
        policies = self.db.exec(
            select(DataResourcePolicy)
            .join(
                DataEnvelope,
                DataEnvelope.id == DataResourcePolicy.envelope_id,
            )
            .where(
                DataEnvelope.tenant_id == context.tenant_id,
                DataEnvelope.source_kind == "document",
                DataEnvelope.source_id == source.source_id,
                DataEnvelope.source_stamp == source.source_stamp,
                DataEnvelope.id != source.id,
            )
        ).all()
        for policy in policies:
            self._check_policy(policy, context, provider, representation, answer_mode)

    def _check_policy(self, policy, context, provider, representation, answer_mode):
        if not policy.active or policy.tenant_id != context.tenant_id:
            raise DataPolicyError("DATA_POLICY_REVOKED")
        if (
            policy.classification not in provider.classifications_json
            or policy.classification not in {"public", "internal"}
        ):
            raise DataPolicyError("DATA_CLASSIFICATION_DENIED")
        if provider.id in policy.denied_providers_json:
            raise DataPolicyError("DATA_PROVIDER_DENIED")
        grant = policy.grants_json.get(provider.id, {})
        if context.purpose not in grant.get("purposes", []) or representation not in grant.get(
            "representations", []
        ):
            raise DataPolicyError("DATA_SEND_DENIED")
        if policy.answer_mode == "none":
            raise DataPolicyError("DATA_ANSWER_DENIED")
        if policy.answer_mode == "controlled_answer" and (
            representation != "answer_view" or answer_mode != "controlled_answer"
        ):
            raise DataPolicyError("DATA_QUOTE_DENIED")

    def issue_intent(
        self,
        context: PolicyContext,
        refs: Sequence[DataEnvelopeRef],
        *,
        representation="raw",
        answer_mode="answer_with_quote",
    ) -> ModelCallIntent:
        provider = self.provider(context)
        if not refs:
            raise DataPolicyError("DATA_LINEAGE_MISSING")
        for ref in refs:
            source = self.envelope(ref, context.tenant_id)
            effective_representation = (
                "raw" if source.source_kind in {"input", "system_template"} else representation
            )
            self._check(context, ref, provider, effective_representation, answer_mode, set())
        return ModelCallIntent(context, tuple(refs), answer_mode, representation, provider.revision)

    def validate(self, intent: ModelCallIntent):
        fresh = self.issue_intent(
            intent.context,
            intent.envelope_refs,
            representation=intent.representation,
            answer_mode=intent.answer_mode,
        )
        if fresh.policy_epoch != intent.policy_epoch:
            raise DataPolicyError("DATA_POLICY_STALE")

    def payload(self, ref: DataEnvelopeRef, tenant: str):
        return copy.deepcopy(self.envelope(ref, tenant).payload_json)
