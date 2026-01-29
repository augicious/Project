from __future__ import annotations

import argparse
import sys
from datetime import datetime


def _parse_ymd(text: str) -> str:
    t = (text or "").strip()
    if not t:
        return ""
    return t[:10]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Capture a point-in-time risk score snapshot into the SQLite database."
    )
    parser.add_argument(
        "--date",
        dest="snapshot_date",
        default="",
        help="Snapshot date in YYYY-MM-DD (defaults to UTC today)",
    )
    parser.add_argument(
        "--actor",
        default="scheduler",
        help="Name recorded as created_by (default: scheduler)",
    )
    args = parser.parse_args(argv)

    # Import app.py as a module (does NOT start the server).
    try:
        import app as risk_app  # type: ignore
    except Exception as exc:
        print(f"ERROR: failed to import app.py: {exc}", file=sys.stderr)
        return 2

    # Ensure tables exist.
    try:
        risk_app.init_db()
    except Exception as exc:
        print(f"ERROR: init_db failed: {exc}", file=sys.stderr)
        return 2

    now = datetime.utcnow().isoformat()
    snap_date = _parse_ymd(args.snapshot_date) or risk_app._today_ymd()  # type: ignore
    actor = (args.actor or "scheduler").strip() or "scheduler"

    inserted = 0
    scored = 0

    try:
        with risk_app.get_db_connection() as conn:  # type: ignore
            risks = conn.execute(
                """
                SELECT id, likelihood_initial, impact_initial, likelihood_residual, impact_residual, likelihood, impact
                FROM risks
                """.strip()
            ).fetchall()

            for r in risks:
                rid = int(r["id"])

                li = risk_app._rating_1_to_5(r["likelihood_initial"] or r["likelihood"])  # type: ignore
                ii = risk_app._rating_1_to_5(r["impact_initial"] or r["impact"])  # type: ignore
                lr = risk_app._rating_1_to_5(r["likelihood_residual"])  # type: ignore
                ir = risk_app._rating_1_to_5(r["impact_residual"])  # type: ignore

                score_i = risk_app._score_1_to_25(li, ii)  # type: ignore
                score_r = risk_app._score_1_to_25(lr, ir)  # type: ignore

                if score_i is None and score_r is None:
                    continue

                scored += 1
                cur = conn.execute(
                    """
                    INSERT OR REPLACE INTO risk_score_snapshots
                        (snapshot_date, risk_id, score_initial, level_initial, score_residual, level_residual, created_by, created_at)
                    VALUES
                        (?, ?, ?, ?, ?, ?, ?, ?)
                    """.strip(),
                    (
                        snap_date,
                        rid,
                        score_i,
                        risk_app._score_band(score_i),  # type: ignore
                        score_r,
                        risk_app._score_band(score_r),  # type: ignore
                        actor,
                        now,
                    ),
                )
                if int(cur.rowcount or 0) > 0:
                    inserted += 1

            conn.commit()

    except Exception as exc:
        print(f"ERROR: snapshot failed: {exc}", file=sys.stderr)
        return 1

    print(
        f"OK: captured snapshot_date={snap_date} for {inserted} row(s) ({scored} scored risk(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
