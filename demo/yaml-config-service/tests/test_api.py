from test_config import JOB


def test_submit_job(client):
    res = client.post("/jobs", data=JOB, content_type="application/yaml")
    assert res.status_code == 201
    assert res.get_json() == {"queued": "build", "position": 1}


def test_submit_bad_job(client):
    res = client.post("/jobs", data="name: x\n", content_type="application/yaml")
    assert res.status_code == 400


def test_submit_batch(client):
    body = JOB + "---\nname: docs\nimage: python:3.11\nsteps: [mkdocs build]\n"
    res = client.post("/jobs/batch", data=body, content_type="application/yaml")
    assert res.status_code == 201
    assert res.get_json()["queued"] == ["build", "docs"]
