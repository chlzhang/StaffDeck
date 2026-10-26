"""Offline restore interlock: discard all restored provider approvals before startup.

Additive tables are registered in app.db.models. Absence of a source row is
unclassified; no scan of legacy metadata or gallery flags creates permission.
"""

from sqlalchemy import update
from sqlmodel import Session

from app.db.models import ProviderDataPolicy


def reset_after_restore(db: Session) -> int:
    result = db.exec(
        update(ProviderDataPolicy)
        .where(
            ProviderDataPolicy.active == True,
        )
        .values(active=False, revision=ProviderDataPolicy.revision + 1)
    )
    db.commit()
    return result.rowcount


def main():
    import argparse
    from pathlib import Path

    from sqlmodel import SQLModel, create_engine

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--reset-after-restore", action="store_true", required=True)
    args = parser.parse_args()
    path = args.database.resolve(strict=True)
    engine = create_engine("sqlite:///" + str(path))
    try:
        SQLModel.metadata.create_all(engine)
        with Session(engine) as db:
            count = reset_after_restore(db)
        print(f"Disabled restored provider approvals: {count}")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
