from __future__ import annotations

import logging
import os
from pathlib import Path

from waitress import serve


def _load_dotenv_if_available() -> None:
    try:
        from dotenv import load_dotenv  # type: ignore
    except Exception:
        return

    env_file = os.getenv("ENV_FILE", "").strip()
    if env_file:
        # For services, ENV_FILE should be the source of truth.
        # Use override=True so blank/stale machine env vars don't win.
        load_dotenv(dotenv_path=env_file, override=True)
    else:
        # For local dev, don't override already-set environment variables.
        load_dotenv(override=False)

if __name__ == "__main__":
    _load_dotenv_if_available()

    base_dir = Path(__file__).resolve().parent
    default_log_dir = Path(os.getenv("ProgramData", "C:\\ProgramData")) / "RiskTicketing" / "logs"
    log_dir = Path(os.getenv("RISK_TICKETING_LOG_DIR", str(default_log_dir)))
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        log_dir = base_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

    log_path = log_dir / "service.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.FileHandler(log_path, encoding="utf-8")],
    )

    logging.info("Log path: %s", log_path)
    logging.info("Working directory: %s", Path.cwd())

    # Diagnostics (no secrets): confirm whether ENV_FILE + OIDC vars are present.
    env_file = os.getenv("ENV_FILE", "").strip()
    logging.info("ENV_FILE set: %s", bool(env_file))
    if env_file:
        logging.info("ENV_FILE path: %s", env_file)
    logging.info("AUTH_REQUIRED env: %s", os.getenv("AUTH_REQUIRED", "<unset>"))
    logging.info("OIDC_TENANT_ID set: %s", bool(os.getenv("OIDC_TENANT_ID", "").strip()))
    logging.info("OIDC_CLIENT_ID set: %s", bool(os.getenv("OIDC_CLIENT_ID", "").strip()))
    logging.info("OIDC_CLIENT_SECRET set: %s", bool(os.getenv("OIDC_CLIENT_SECRET", "").strip()))
    logging.info("OIDC_REDIRECT_URI set: %s", bool(os.getenv("OIDC_REDIRECT_URI", "").strip()))

    try:
        from app import app
    except Exception:
        logging.exception("Failed to import Flask app.")
        raise

    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", "5000"))
    logging.info("Starting Waitress on %s:%s", host, port)
    serve(app, host=host, port=port)


