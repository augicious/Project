from __future__ import annotations


def _become_admin(client) -> None:
    with client.session_transaction() as sess:
        sess["is_admin"] = True


def test_index_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200


def test_health_ok(client):
    resp = client.get("/_health")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload and payload.get("ok") is True


def test_admin_heatmap_requires_admin(client):
    resp = client.get("/admin/heatmap")
    assert resp.status_code in {301, 302, 303, 307, 308}


def test_admin_heatmap_loads_for_admin(client):
    _become_admin(client)
    resp = client.get("/admin/heatmap")
    assert resp.status_code == 200
    assert b"Risk Heatmap" in resp.data


def test_admin_tasks_add_and_update_smoke(client, risk_app_module):
    now = risk_app_module.datetime.now(risk_app_module.timezone.utc).replace(tzinfo=None).isoformat()
    with risk_app_module.get_db_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO risks (title, description, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("Test Risk", "Desc", "New", now, now),
        )
        risk_id = int(cur.lastrowid)
        conn.commit()

    with client.session_transaction() as sess:
        sess["is_admin"] = True
        sess["_csrf_token"] = "test-csrf"

    # Add a task
    resp = client.post(
        f"/admin/risk/{risk_id}/tasks/add",
        data={
            "_csrf_token": "test-csrf",
            "title": "Do the thing",
            "assigned_to": "",
            "due_date": "2026-02-06",
            "notes": "",
        },
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)

    with risk_app_module.get_db_connection() as conn:
        task = conn.execute(
            "SELECT id, status FROM risk_tasks WHERE risk_id = ? ORDER BY id DESC LIMIT 1",
            (risk_id,),
        ).fetchone()
        assert task is not None
        task_id = int(task["id"])

    # Update status
    resp = client.post(
        f"/admin/tasks/{task_id}/status",
        data={
            "_csrf_token": "test-csrf",
            "status": "Done",
        },
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)


def test_admin_dashboard_loads_for_admin(client):
    _become_admin(client)
    resp = client.get("/admin/dashboard")
    assert resp.status_code == 200
    assert b"Admin Dashboard" in resp.data
