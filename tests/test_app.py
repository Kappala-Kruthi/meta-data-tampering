"""
tests/test_app.py
Comprehensive integration tests for Public Landing Page, Authentication,
Protected Workspace Routes, Differential Comparison, and Security Validation.
"""

import io
import os
import pytest
from app import app
import core.database as db

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "samples"))
SAMPLE_CAMERA = os.path.join(SAMPLES_DIR, "sample_camera.jpg")
SAMPLE_EDITED = os.path.join(SAMPLES_DIR, "sample_edited.jpg")


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False  # Bypass CSRF in testing mode
    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_client(client):
    """Authenticated client fixture."""
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["user_id"] = "Bhuvana@123"
        sess["_csrf_token"] = "test_csrf_token"
    return client


def test_public_landing_page(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"TRACE" in res.data
    assert b"Metadata Tampering Detection in Media Files" in res.data
    assert b"Core Forensic Capabilities" in res.data
    assert b"Get Started" in res.data


def test_login_flow(client):
    # 1. GET /login
    res_get = client.get("/login")
    assert res_get.status_code == 200
    assert b"Sign in to TRACE" in res_get.data

    # 2. POST with invalid / unregistered credentials on sign in
    res_fail = client.post("/login", data={"user_id": "unregistered_user", "password": "wrong_password"})
    assert res_fail.status_code == 401
    assert b"not registered yet" in res_fail.data

    # 2b. Register a custom user ID
    res_reg = client.post(
        "/login",
        data={"user_id": "Investigator_Alpha", "password": "password456", "action": "register"},
        follow_redirects=True,
    )
    assert res_reg.status_code == 200
    assert b"Forensic Command Dashboard" in res_reg.data

    # Log out
    client.post("/logout")

    # 2c. Log in with the custom user ID
    res_custom = client.post(
        "/login",
        data={"user_id": "Investigator_Alpha", "password": "password456", "action": "login"},
        follow_redirects=True,
    )
    assert res_custom.status_code == 200
    assert b"Forensic Command Dashboard" in res_custom.data

    # Log out again
    client.post("/logout")

    # 3. POST with empty credentials
    res_empty = client.post("/login", data={"user_id": "", "password": ""})
    assert res_empty.status_code == 401

    # 4. POST with valid demo credentials
    res_ok = client.post(
        "/login",
        data={"user_id": "Bhuvana@123", "password": "123"},
        follow_redirects=True,
    )
    assert res_ok.status_code == 200
    assert b"Forensic Command Dashboard" in res_ok.data

    # 5. Accessing /login while authenticated redirects to /dashboard
    res_logged = client.get("/login", follow_redirects=False)
    assert res_logged.status_code == 302
    assert "/dashboard" in res_logged.headers["Location"]


def test_logout(client):
    # Log in first
    client.post("/login", data={"user_id": "Bhuvana@123", "password": "123"})
    # Log out
    res_logout = client.post("/logout", follow_redirects=True)
    assert res_logout.status_code == 200
    assert b"Sign in to TRACE" in res_logout.data


def test_protected_routes_unauthenticated_redirect(client):
    protected_urls = ["/dashboard", "/inspect", "/compare", "/verify", "/history"]
    for url in protected_urls:
        res = client.get(url, follow_redirects=False)
        assert res.status_code == 302
        assert "/login" in res.headers["Location"]


def test_dashboard_authenticated(auth_client):
    res = auth_client.get("/dashboard")
    assert res.status_code == 200
    assert b"Forensic Command Dashboard" in res.data
    assert b"Total Investigations" in res.data


def test_inspect_authenticated(auth_client):
    # GET
    res_get = auth_client.get("/inspect")
    assert res_get.status_code == 200
    assert b"Single-File Forensic Metadata Inspector" in res_get.data

    # POST with genuine sample image
    with open(SAMPLE_CAMERA, "rb") as img:
        data = {
            "evidence_file": (io.BytesIO(img.read()), "sample_camera.jpg"),
            "case_title": "Automated Web Test",
            "notes": "Testing single file upload",
        }
        res_post = auth_client.post("/inspect", data=data, content_type="multipart/form-data")
        assert res_post.status_code == 200
        assert b"Canon" in res_post.data
        assert b"Canon EOS 80D" in res_post.data
        assert b"Cryptographic File Integrity" in res_post.data


def test_compare_authenticated(auth_client):
    # GET
    res_get = auth_client.get("/compare")
    assert res_get.status_code == 200

    # POST with File A and File B
    with open(SAMPLE_CAMERA, "rb") as f_a, open(SAMPLE_EDITED, "rb") as f_b:
        data = {
            "file_a": (io.BytesIO(f_a.read()), "original.jpg"),
            "file_b": (io.BytesIO(f_b.read()), "edited.jpg"),
            "case_title": "Compare Web Test",
            "notes": "Testing dual upload",
        }
        res_post = auth_client.post("/compare", data=data, content_type="multipart/form-data")
        assert res_post.status_code == 200
        assert b"Side-by-Side Metadata Differential Matrix" in res_post.data
        assert b"DIFFERING SHA-256" in res_post.data


def test_verify_authenticated(auth_client):
    with open(SAMPLE_CAMERA, "rb") as f1, open(SAMPLE_CAMERA, "rb") as f2:
        data = {
            "file_1": (io.BytesIO(f1.read()), "orig1.jpg"),
            "file_2": (io.BytesIO(f2.read()), "orig2.jpg"),
        }
        res = auth_client.post("/verify", data=data, content_type="multipart/form-data")
        assert res.status_code == 200
        assert b"BIT-FOR-BIT IDENTICAL" in res.data


def test_history_and_reports_authenticated(auth_client):
    test_id = "WEB-TEST-002"
    db.save_investigation(
        inv_id=test_id,
        case_title="Report Auth Test Case",
        analysis_type="compare",
        file_a_name="a.jpg",
        file_a_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_b_name="b.jpg",
        file_b_hash="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        notes="Automated test note",
        results={"comparison": {"metrics": {"matching_count": 5, "changed_count": 2}}},
        anomaly_count=1,
    )

    # 1. History
    res_hist = auth_client.get("/history")
    assert res_hist.status_code == 200

    # 2. Report
    res_rep = auth_client.get(f"/report/{test_id}")
    assert res_rep.status_code == 200
    assert b"Digital Forensics Investigation Report" in res_rep.data

    # 3. JSON Export
    res_json = auth_client.get(f"/export/json/{test_id}")
    assert res_json.status_code == 200

    # 4. CSV Export
    res_csv = auth_client.get(f"/export/csv/{test_id}")
    assert res_csv.status_code == 200

    # Cleanup
    db.delete_investigation(test_id)


def test_security_extension_rejection(auth_client):
    fake_exe = io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00")
    data = {"evidence_file": (fake_exe, "malicious.exe")}
    res = auth_client.post("/inspect", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert res.status_code == 200
    assert b"Unsupported file format" in res.data
