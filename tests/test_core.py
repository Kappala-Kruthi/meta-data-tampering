"""
tests/test_core.py
Automated test suite validating the Core Forensic Engine modules:
Hasher, ExifTool Runner, Comparator, Anomaly Detector, and Database.
"""

import os
import tempfile
import pytest

from core.hasher import compute_file_hashes, compare_file_hashes
from core.exiftool_runner import find_exiftool_binary, get_exiftool_version
from core.comparator import compare_metadata, normalize_value
from core.anomaly_detector import detect_file_anomalies, detect_comparison_anomalies
import core.database as db


def test_hasher_identical_and_differing():
    with tempfile.NamedTemporaryFile(delete=False) as f1, tempfile.NamedTemporaryFile(delete=False) as f2:
        f1.write(b"Forensic Evidence Sample 1")
        f2.write(b"Forensic Evidence Sample 1")
        p1, p2 = f1.name, f2.name

    try:
        h1 = compute_file_hashes(p1)
        h2 = compute_file_hashes(p2)
        assert h1["sha256"] == h2["sha256"]
        assert len(h1["sha256"]) == 64
        assert len(h1["md5"]) == 32

        comp = compare_file_hashes(p1, p2)
        assert comp["sha256_match"] is True
        assert comp["status"] == "IDENTICAL_BYTES"

        # Modify one file and re-test
        with open(p2, "wb") as f:
            f.write(b"Tampered Evidence Sample 2")
        comp_diff = compare_file_hashes(p1, p2)
        assert comp_diff["sha256_match"] is False
        assert comp_diff["status"] == "DIFFERENT_BYTES"
    finally:
        if os.path.exists(p1):
            os.remove(p1)
        if os.path.exists(p2):
            os.remove(p2)


def test_exiftool_detection():
    binary = find_exiftool_binary()
    assert binary is not None
    assert os.path.isfile(binary)
    ok, ver = get_exiftool_version()
    assert ok is True
    assert "13." in ver


def test_comparator_differential_logic():
    meta_a = {
        "raw": {
            "EXIF:Make": "Canon",
            "EXIF:Model": "EOS 80D",
            "EXIF:ISO": 100,
            "XMP:CreatorTool": "Original Firmware",
        }
    }
    meta_b = {
        "raw": {
            "EXIF:Make": "Canon",
            "EXIF:Model": "EOS 80D",
            "EXIF:ISO": 200,  # Changed
            "XMP:CreatorTool": "Adobe Photoshop 2024",  # Changed
            "File:Comment": "Edited export",  # Only in B
        }
    }
    res = compare_metadata(meta_a, meta_b)
    m = res["metrics"]
    assert m["matching_count"] == 2  # Make and Model
    assert m["changed_count"] == 2  # ISO and CreatorTool
    assert m["only_a_count"] == 0
    assert m["only_b_count"] == 1  # File:Comment
    assert res["matching"][0]["tag"] in ["Make", "Model"]


def test_anomaly_detection_rules():
    # Test software signature detection
    meta = {
        "raw": {"XMP:CreatorTool": "Adobe Photoshop 2025 (Windows)"},
        "summary": {
            "software": "Adobe Photoshop 2025",
            "file_type": "jpeg",
            "mime_type": "image/jpeg",
        },
        "tag_count": 25,
        "groups": {"EXIF": {}, "XMP": {}},
    }
    anomalies = detect_file_anomalies(meta, "test_image.jpg")
    rule_ids = [a["rule_id"] for a in anomalies]
    assert "ANOM_EDITOR_SIGNATURE" in rule_ids

    # Test timestamp inversion detection
    meta_inverted = {
        "raw": {},
        "summary": {
            "file_type": "jpeg",
            "date_original": "2026-10-20 14:00:00",
            "date_modify": "2026-10-15 10:00:00",  # earlier!
        },
        "tag_count": 20,
        "groups": {"EXIF": {}},
    }
    anom_time = detect_file_anomalies(meta_inverted, "sample.jpg")
    assert any(a["rule_id"] == "ANOM_TIMESTAMP_INVERSION" for a in anom_time)


def test_database_lifecycle():
    # Save test investigation
    inv_id = "test-inv-001"
    db.save_investigation(
        inv_id=inv_id,
        case_title="Unit Test Case",
        analysis_type="single",
        file_a_name="test.jpg",
        file_a_hash="abc123456789",
        notes="Automated test entry",
        results={"test": True},
        anomaly_count=1,
    )

    item = db.get_investigation(inv_id)
    assert item is not None
    assert item["case_title"] == "Unit Test Case"
    assert item["results"]["test"] is True

    logs = db.get_audit_logs(limit=5)
    assert len(logs) > 0
    assert any("INVESTIGATION_CREATED" in l["event_type"] for l in logs)

    stats = db.get_dashboard_stats()
    assert stats["total_investigations"] >= 1

    # Cleanup
    db.delete_investigation(inv_id)
    assert db.get_investigation(inv_id) is None


def test_user_authentication_lifecycle():
    # 1. Verify default seed user
    assert db.user_exists("Bhuvana@123")
    assert db.verify_user("Bhuvana@123", "123")
    assert not db.verify_user("Bhuvana@123", "wrongpass")

    # 2. Create custom investigator
    import uuid
    custom_id = f"Agent_Test_{uuid.uuid4().hex[:6]}"
    assert not db.user_exists(custom_id)
    created = db.create_user(custom_id, "agent_password_99", role="field_investigator")
    assert created is True

    # 3. Duplicate user creation is rejected
    dup = db.create_user(custom_id, "different_pass")
    assert dup is False

    # 4. Verify custom investigator authentication
    assert db.user_exists(custom_id)
    assert db.verify_user(custom_id, "agent_password_99")
    assert not db.verify_user(custom_id, "wrong_pass")

    # 5. List users
    users = db.list_users()
    user_ids = [u["user_id"] for u in users]
    assert "Bhuvana@123" in user_ids
    assert custom_id in user_ids
