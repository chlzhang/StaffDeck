"""Stable saved-tool requests using the existing external task state machine."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import update
from sqlalchemy.dialects.sqlite import insert

from app.db.models import ExternalBusinessTask, new_id, utc_now
from app.tools.external_tasks import callback_token_hash, new_callback_token
from staffdeck_harness.contracts.invocation import ModuleResult, normalize_result


def request_task_id(tenant_id, user_id, client_request_id):
    if not isinstance(client_request_id, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{1,128}", client_request_id
    ):
        raise HTTPException(422, "client_request_id is required (1-128 letters, digits, _ or -)")
    body = json.dumps([tenant_id, user_id, client_request_id], separators=(",", ":"))
    return "tooltest_" + hashlib.sha256(body.encode()).hexdigest()


def lookup_tool_test(db, *, tenant_id, user_id, tool_id, client_request_id):
    row = db.get(
        ExternalBusinessTask,
        request_task_id(tenant_id, user_id, client_request_id),
        populate_existing=True,
    )
    if row is None or (row.tenant_id, row.user_id, row.tool_id) != (tenant_id, user_id, tool_id):
        raise HTTPException(
            404, "Tool test request not found; do not submit a new request while outcome is unknown"
        )
    return row


def receipt(row):
    return ModuleResult.ok(
        {
            "accepted": True,
            "detached": True,
            "task_id": row.id,
            "status": row.status,
            "query_required": True,
        }
    )


def run_tool_test_once(
    db, *, tenant_id, user_id, tool_id, agent_id, client_request_id, arguments, dispatch
):
    task_id = request_task_id(tenant_id, user_id, client_request_id)
    try:
        canonical = json.dumps(
            [tool_id, agent_id, arguments], sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, "Tool arguments must contain finite JSON values") from exc
    if len(canonical.encode()) > 1024 * 1024:
        raise HTTPException(413, "Tool test request too large")
    binding = hashlib.sha256(canonical.encode()).hexdigest()
    owner = new_id("tooltestclaim")
    row = ExternalBusinessTask(
        id=task_id,
        tenant_id=tenant_id,
        user_id=user_id,
        tool_id=tool_id,
        agent_id=agent_id,
        invocation_id=task_id,
        request_json=arguments,
        idempotency_key=f"staffdeck:{tenant_id}:{tool_id}:{task_id}",
        callback_token_hash=callback_token_hash(new_callback_token()),
        status="submitting",
        lease_owner=owner,
        lease_expires_at=utc_now() + timedelta(seconds=3660),
        expires_at=utc_now() + timedelta(days=1),
        status_config_json={"_tool_test_request": {"binding": binding}},
    )
    inserted = db.exec(
        insert(ExternalBusinessTask)
        .values(**row.model_dump())
        .on_conflict_do_nothing(index_elements=["id"])
    )
    claimed = inserted.rowcount == 1
    db.commit()
    row = db.get(ExternalBusinessTask, task_id, populate_existing=True)
    if (
        row is None
        or (row.tenant_id, row.user_id, row.tool_id) != (tenant_id, user_id, tool_id)
        or (row.status_config_json or {}).get("_tool_test_request", {}).get("binding") != binding
    ):
        raise HTTPException(
            409,
            {
                "code": "IDEMPOTENCY_CONFLICT",
                "message": "该请求标识已绑定其他工具、员工或参数，本次没有执行。",
            },
        )
    if not claimed:
        return receipt(row)  # Never reset unknown, cancelled, expired, failed or completed.
    db.info["tool_test_claim"] = (task_id, owner)
    try:
        result = normalize_result(dispatch())
        from staffdeck_harness.capabilities.ledger import NOT_SENT_CODES

        code = str((result.error or {}).get("code") or "")
        status = (
            "completed"
            if result.success
            else "failed"
            if code in NOT_SENT_CODES
            else "outcome_unknown"
        )
        data, error = result.data, dict(result.error or {})
    except BaseException as exc:
        status, data = "outcome_unknown", None
        error = {
            "code": "TOOL_TEST_OUTCOME_UNKNOWN",
            "message": "调用可能已执行，结果尚未确认；仅查询状态，不会重放。",
        }
        if not isinstance(exc, Exception):
            _finish(db, task_id, owner, status, data, error)
            raise
    finally:
        db.info.pop("tool_test_claim", None)
    _finish(db, task_id, owner, status, data, error)
    return receipt(db.get(ExternalBusinessTask, task_id, populate_existing=True))


def _finish(db, task_id, owner, status, data, error):
    # A detached enqueue transfers this very row to the existing worker. Its
    # result/state must never be overwritten by the submitting HTTP request.
    db.exec(
        update(ExternalBusinessTask)
        .where(
            ExternalBusinessTask.id == task_id,
            ExternalBusinessTask.status == "submitting",
            ExternalBusinessTask.lease_owner == owner,
        )
        .values(
            status=status,
            result_json=data if isinstance(data, dict) else {"value": data},
            error_json=error,
            finished_at=utc_now(),
            updated_at=utc_now(),
            lease_owner=None,
            lease_expires_at=None,
        )
        .execution_options(synchronize_session=False)
    )
    db.commit()


def freeze_restored_tool_tests(db):
    """Offline restore: pending backup state is not proof a side effect was unsent."""
    from sqlmodel import select

    candidates = db.exec(
        select(ExternalBusinessTask).where(
            ExternalBusinessTask.status.in_(["queued", "submitting", "working", "accepted"])
        )
    ).all()
    count = 0
    for row in candidates:
        if not (row.status_config_json or {}).get("_tool_test_request"):
            continue
        row.status = "outcome_unknown"
        row.error_json = {
            "code": "RESTORED_TOOL_TEST_UNCONFIRMED",
            "message": "恢复的调用结果须人工核实，不会重新发送业务操作。",
        }
        row.lease_owner = None
        row.lease_expires_at = None
        row.next_poll_at = None
        row.finished_at = utc_now()
        row.updated_at = utc_now()
        db.add(row)
        count += 1
    db.commit()
    return count


def main():
    import argparse
    from pathlib import Path

    from sqlmodel import Session, SQLModel, create_engine

    parser = argparse.ArgumentParser(
        description="Freeze restored saved-tool test requests before starting workers."
    )
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--freeze-after-restore", action="store_true", required=True)
    args = parser.parse_args()
    engine = create_engine("sqlite:///" + str(args.database.resolve(strict=True)))
    try:
        SQLModel.metadata.create_all(engine)
        with Session(engine) as db:
            count = freeze_restored_tool_tests(db)
        print(
            f"Restored pending tool tests frozen: {count}; reconcile external outcomes before new calls."
        )
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
