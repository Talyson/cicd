import pytest


def _create(client, **payload):
    return client.post("/api/tasks", json=payload or {"title": "Estudar CI/CD"})


def test_list_empty(client):
    resp = client.get("/api/tasks")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_create_and_get(client):
    resp = _create(client, title="  Escrever testes  ")
    assert resp.status_code == 201
    task = resp.get_json()
    assert task == {"id": 1, "title": "Escrever testes", "done": False}

    resp = client.get("/api/tasks/1")
    assert resp.status_code == 200
    assert resp.get_json() == task

    assert len(client.get("/api/tasks").get_json()) == 1


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"title": ""},
        {"title": "   "},
        {"title": 123},
        {"title": "x" * 201},
        {"title": "ok", "done": "sim"},
    ],
)
def test_create_invalid(client, payload):
    resp = client.post("/api/tasks", json=payload)
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_create_non_json_body(client):
    resp = client.post("/api/tasks", data="not json", content_type="text/plain")
    assert resp.status_code == 400


def test_create_json_not_object(client):
    resp = client.post("/api/tasks", json=["lista"])
    assert resp.status_code == 400


def test_update(client):
    _create(client)
    resp = client.put("/api/tasks/1", json={"done": True})
    assert resp.status_code == 200
    assert resp.get_json()["done"] is True

    resp = client.put("/api/tasks/1", json={"title": "Novo título"})
    assert resp.get_json()["title"] == "Novo título"


def test_update_invalid(client):
    _create(client)
    resp = client.put("/api/tasks/1", json={"title": ""})
    assert resp.status_code == 400


def test_update_not_found(client):
    resp = client.put("/api/tasks/99", json={"done": True})
    assert resp.status_code == 404


def test_get_not_found(client):
    assert client.get("/api/tasks/99").status_code == 404


def test_delete(client):
    _create(client)
    assert client.delete("/api/tasks/1").status_code == 204
    assert client.delete("/api/tasks/1").status_code == 404
