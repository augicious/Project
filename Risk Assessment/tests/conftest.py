from __future__ import annotations

import sys
from pathlib import Path

import pytest


@pytest.fixture()
def risk_app_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Import the app module with an isolated temp DB + storage paths."""

    project_dir = Path(__file__).resolve().parents[1]
    if str(project_dir) not in sys.path:
        sys.path.insert(0, str(project_dir))

    import app as risk_app  # type: ignore

    # Isolate filesystem side effects.
    monkeypatch.setattr(risk_app, "DATA_DIR", tmp_path / "data", raising=False)
    monkeypatch.setattr(risk_app, "DB_PATH", tmp_path / "data" / "risks-test.db", raising=False)
    monkeypatch.setattr(risk_app, "UPLOAD_DIR", tmp_path / "uploads", raising=False)
    monkeypatch.setattr(risk_app, "ARCHIVE_DIR", tmp_path / "uploads_archive", raising=False)

    # Keep tests fast and hermetic.
    monkeypatch.setattr(risk_app, "seed_from_excel", lambda: None, raising=False)

    # Initialize schema explicitly and prevent setup() from doing work.
    risk_app.init_db()
    risk_app.app.config["DB_INITIALIZED"] = True

    # Disable OIDC enforcement for tests.
    risk_app.app.config["AUTH_REQUIRED"] = False
    risk_app.app.config["ADMIN_PASSWORD_ENABLED"] = True
    risk_app.app.config["TESTING"] = True

    return risk_app


@pytest.fixture()
def client(risk_app_module):
    return risk_app_module.app.test_client()
