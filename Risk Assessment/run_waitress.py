from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler

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

    class _RequestIdFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover
            try:
                from flask import has_request_context, g  # type: ignore

                if has_request_context() and hasattr(g, "request_id"):
                    record.request_id = str(getattr(g, "request_id"))
                else:
                    record.request_id = "-"
            except Exception:
                record.request_id = "-"
            return True

    level_name = os.getenv("LOG_LEVEL", "INFO").strip().upper() or "INFO"
    level = getattr(logging, level_name, logging.INFO)

    max_mb = 25
    try:
        max_mb = int(float(os.getenv("RISK_TICKETING_LOG_MAX_MB", "25")))
    except ValueError:
        max_mb = 25
    backups = 5
    try:
        backups = int(float(os.getenv("RISK_TICKETING_LOG_BACKUPS", "5")))
    except ValueError:
        backups = 5

    handler = RotatingFileHandler(
        log_path,
        encoding="utf-8",
        maxBytes=max(1, max_mb) * 1024 * 1024,
        backupCount=max(1, backups),
    )

    class _RedactFilter(logging.Filter):
        _bearer_re = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-\._~\+/]+=*)")
        _kv_re = re.compile(r"(?i)\b(client_secret|secret_key|password|access_token|refresh_token)\s*[:=]\s*([^\s,;]+)")

        def __init__(self) -> None:
            super().__init__()
            self._secrets: list[str] = []
            for name in (
                "OIDC_CLIENT_SECRET",
                "FLASK_SECRET_KEY",
                "ADMIN_PASSWORD",
                "SMTP_PASSWORD",
                "SMTP_PASS",
                "GRAPH_CLIENT_SECRET",
                "MS_GRAPH_CLIENT_SECRET",
            ):
                val = (os.getenv(name, "") or "").strip()
                if val:
                    self._secrets.append(val)

        def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover
            try:
                message = record.getMessage()
                for secret in self._secrets:
                    if secret and secret in message:
                        message = message.replace(secret, "***")
                message = self._bearer_re.sub("Bearer ***", message)
                message = self._kv_re.sub(lambda m: f"{m.group(1)}=***", message)

                # Replace message+args with already-rendered redacted message.
                record.msg = message
                record.args = ()
            except Exception:
                pass
            return True
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [rid=%(request_id)s] %(message)s"
        )
    )
    handler.addFilter(_RequestIdFilter())
    handler.addFilter(_RedactFilter())

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)

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

    try:
        import app as app_module  # type: ignore
        logging.info("App version: %s", app.config.get("APP_VERSION"))
        logging.info("Python: %s", sys.version.split()[0])
        logging.info("AUTH_REQUIRED: %s", app.config.get("AUTH_REQUIRED"))
        logging.info("ENABLE_ADMIN_IMPORT: %s", app.config.get("ENABLE_ADMIN_IMPORT"))
        logging.info("SEED_FROM_EXCEL_ON_STARTUP: %s", app.config.get("SEED_FROM_EXCEL_ON_STARTUP"))
        logging.info("REQUEST_LOGGING_ENABLED: %s", os.getenv("REQUEST_LOGGING_ENABLED", "<unset>"))
        logging.info("DB path: %s", getattr(app_module, "DB_PATH", "<unknown>"))
    except Exception:
        # Keep going even if optional diagnostics fail.
        pass

    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", "5000"))
    logging.info("Starting Waitress on %s:%s", host, port)
    serve(app, host=host, port=port)


