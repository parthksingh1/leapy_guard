from app.service_auth import issue_service_token


def _login(client, user="alice", password="wonderland"):
    return client.post("/login", json={"username": user, "password": password})


def test_login_and_me(client):
    tokens = _login(client).get_json()
    res = client.get("/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert res.status_code == 200
    assert res.get_json() == {"user": "alice", "roles": ["admin"]}


def test_login_bad_password(client):
    assert _login(client, password="nope").status_code == 401


def test_refresh_flow(client):
    tokens = _login(client, "bob", "builder").get_json()
    res = client.post("/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert res.status_code == 200
    new_access = res.get_json()["access_token"]
    me = client.get("/me", headers={"Authorization": f"Bearer {new_access}"})
    assert me.get_json()["user"] == "bob"


def test_me_rejects_garbage(client):
    res = client.get("/me", headers={"Authorization": "Bearer abc.def.ghi"})
    assert res.status_code == 401


def test_internal_sync_with_service_token(client):
    token = issue_service_token("billing", ["sync:write"])
    res = client.post("/internal/sync", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.get_json()["service"] == "billing"


def test_internal_sync_missing_scope(client):
    token = issue_service_token("billing", ["sync:read"])
    res = client.post("/internal/sync", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403
