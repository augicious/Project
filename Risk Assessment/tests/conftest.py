from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


@pytest.fixture()
def risk_app_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Import the app module with an isolated temp DB + storage paths."""

    project_dir = Path(__file__).resolve().parents[1]
    app_path = project_dir / "app.py"
    spec = importlib.util.spec_from_file_location("risk_assessment_app", app_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module spec for {app_path}")

    risk_app = importlib.util.module_from_spec(spec)
    # Some code paths may do `import app`; ensure they resolve to the module under test.
    sys.modules["risk_assessment_app"] = risk_app
    sys.modules["app"] = risk_app
    spec.loader.exec_module(risk_app)

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
