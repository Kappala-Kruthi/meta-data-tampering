"""
tests/test_advanced_features.py
Comprehensive test suite for advanced digital forensic features:
1. GPS Geolocation & Clock Provenance
2. Hex & Low-Level File Structure (Steganography / EOF Appended Data)
3. Metadata Sanitizer & Privacy Redaction
4. Forensic Chain of Custody Certificate Generator
5. Web endpoints for Batch Triage, Hex Inspector, Sanitizer, and Custody Certificate
"""

import io
import os
import shutil
import pytest
from PIL import Image

from app import app
from core import gps_analyzer, hex_inspector, sanitizer
from reports import custody_generator
import core.database as db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess.clear()
        yield client


@pytest.fixture
def auth_client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = "Bhuvana@123"
            sess["logged_in"] = True
        yield client


@pytest.fixture
def sample_jpeg_path(tmp_path):
    """Creates a valid JPEG image for forensic testing."""
    img_path = str(tmp_path / "test_sample.jpg")
    img = Image.new("RGB", (64, 64), color=(30, 60, 90))
    img.save(img_path, format="JPEG", quality=90)
    return img_path


@pytest.fixture
def stego_jpeg_path(tmp_path, sample_jpeg_path):
    """Creates a JPEG with hidden payload appended past the EOF (FF D9) marker."""
    stego_path = str(tmp_path / "stego_appended.jpg")
    shutil.copy2(sample_jpeg_path, stego_path)
    with open(stego_path, "ab") as f:
        # Append hidden text payload after EOF
        f.write(b"\x00\x00\x00\x00CONFIDENTIAL_FORENSIC_LEAK_ARCHIVE_DATA_12345")
    return stego_path


# ============================================================================
# 1. GPS FORENSICS & GEOLOCATION
# ============================================================================

def test_gps_coordinate_parsing_and_mapping():
    """Tests DMS parsing, decimal conversion, and OpenStreetMap URL generation."""
    sample_meta = {
        "GPSLatitude": "18 deg 48' 19.80\" N",
        "GPSLatitudeRef": "N",
        "GPSLongitude": "84 deg 8' 36.60\" E",
        "GPSLongitudeRef": "E",
        "GPSAltitude": 45.2,
        "GPSTimeStamp": "08:30:15",
        "GPSDateStamp": "2026:10:29",
        "DateTimeOriginal": "2026:10:29 14:00:15",  # 5.5 hours delta (UTC to IST offset)
    }

    result = gps_analyzer.extract_gps_forensics(sample_meta)
    assert result["has_gps"] is True
    assert result["latitude"] is not None
    assert result["longitude"] is not None
    assert 18.8 < result["latitude"] < 18.9
    assert 84.1 < result["longitude"] < 84.2
    assert "openstreetmap.org" in result["osm_external_url"]
    assert "google.com" in result["google_maps_url"]
    assert result["timestamp_consistency"] is not None


def test_gps_no_data_handling():
    """Tests graceful fallback when no GPS coordinates are embedded."""
    empty_meta = {"Make": "Nikon", "Model": "D850"}
    result = gps_analyzer.extract_gps_forensics(empty_meta)
    assert result["has_gps"] is False
    assert result["latitude"] is None
    assert len(result["findings"]) > 0
    assert result["findings"][0]["status"] == "NOT_PRESENT"


# ============================================================================
# 2. HEX & LOW-LEVEL FILE STRUCTURE INSPECTOR
# ============================================================================

def test_hex_inspector_clean_jpeg(sample_jpeg_path):
    """Tests magic byte verification and segment mapping on a clean JPEG."""
    inspection = hex_inspector.inspect_file_structure(sample_jpeg_path)
    assert inspection["detected_format"] == "JPEG"
    assert inspection["is_valid_header"] is True
    assert inspection["has_appended_data"] is False
    assert inspection["appended_data_bytes"] == 0
    assert len(inspection["header_hex_dump"]) > 0
    assert len(inspection["trailer_hex_dump"]) > 0


def test_hex_inspector_stego_appended_payload(stego_jpeg_path):
    """Tests detection of steganographic trailing payload past EOF (FF D9)."""
    inspection = hex_inspector.inspect_file_structure(stego_jpeg_path)
    assert inspection["detected_format"] == "JPEG"
    assert inspection["has_appended_data"] is True
    assert inspection["appended_data_bytes"] > 0
    appended_findings = [f for f in inspection["findings"] if f["category"] == "Appended Payload"]
    assert len(appended_findings) > 0
    assert appended_findings[0]["severity"] == "HIGH"


# ============================================================================
# 3. METADATA SANITIZER & PRIVACY REDACTION
# ============================================================================

def test_metadata_sanitizer_lifecycle(tmp_path, sample_jpeg_path):
    """Tests scrubbing metadata and generating before-and-after cryptographic differentials."""
    out_dir = str(tmp_path / "sanitized")
    res = sanitizer.sanitize_media_file(sample_jpeg_path, out_dir, scrub_mode="ALL")
    assert res["success"] is True
    assert os.path.exists(res["sanitized_full_path"])
    # File hashes must diverge
    assert res["original_sha256"] != res["sanitized_sha256"]
    assert res["sanitized_size"] <= res["original_size"]


# ============================================================================
# 4. CHAIN OF CUSTODY CERTIFICATE GENERATOR
# ============================================================================

def test_chain_of_custody_certificate_generation(sample_jpeg_path):
    """Tests generating official evidentiary custody certificate and tamper seal."""
    cert = custody_generator.generate_custody_certificate(
        file_path=sample_jpeg_path,
        investigator_id="Bhuvana@123",
        investigator_name="Kappala Bhuvana Kruthi",
        investigator_title="Lead Digital Forensics Researcher",
        case_ref="CASE-CAPSTONE-2026",
        source_context="Captured using a camera or phone",
    )
    assert cert["evidence_id"].startswith("TRACE-COC-")
    assert cert["custody_seal"] is not None
    assert len(cert["custody_seal"]) == 27  # XXXX-XXXX-XXXX-XXXX
    assert cert["evidence_file"]["sha256"] is not None
    assert cert["evidence_file"]["sha1"] is not None
    assert cert["evidence_file"]["md5"] is not None
    assert len(cert["transfer_ledger"]) >= 3


# ============================================================================
# 5. ADVANCED ROUTE ACCESSIBILITY TESTS
# ============================================================================

def test_batch_triage_route_get_and_post(auth_client, sample_jpeg_path):
    """Tests batch triage endpoint accessibility and execution."""
    res_get = auth_client.get("/batch-analysis")
    assert res_get.status_code == 200
    assert b"Batch Image Triage" in res_get.data

    with open(sample_jpeg_path, "rb") as f:
        data = {
            "batch_files": (io.BytesIO(f.read()), "batch_sample.jpg"),
        }
        res_post = auth_client.post("/batch-analysis", data=data, content_type="multipart/form-data")
        assert res_post.status_code == 200
        assert b"Evidence Triage Matrix" in res_post.data


def test_hex_inspector_route_get_and_post(auth_client, sample_jpeg_path):
    """Tests hex inspector interface and binary structure analysis POST."""
    res_get = auth_client.get("/hex-inspector")
    assert res_get.status_code == 200
    assert b"Hex &amp; Binary Structure Inspector" in res_get.data or b"Hex & Binary Structure Inspector" in res_get.data

    with open(sample_jpeg_path, "rb") as f:
        data = {
            "evidence_file": (io.BytesIO(f.read()), "test.jpg"),
        }
        res_post = auth_client.post("/hex-inspector", data=data, content_type="multipart/form-data")
        assert res_post.status_code == 200
        assert b"Magic Signature" in res_post.data
        assert b"JPEG" in res_post.data


def test_sanitizer_route_get(auth_client):
    """Tests metadata sanitizer tool page loading."""
    res = auth_client.get("/sanitizer")
    assert res.status_code == 200
    assert b"Metadata Sanitizer" in res.data


def test_custody_certificate_route_view(auth_client):
    """Tests viewing printable chain of custody certificate for an investigation."""
    inv_id = "COC-TEST-101"
    db.save_investigation(
        inv_id=inv_id,
        case_title="Custody Evidence Test Case",
        analysis_type="single_analysis",
        file_a_name="test_custody.jpg",
        file_a_hash="a" * 64,
        notes="Chain of custody integrity verification.",
        results={"file_size": 2048, "file_size_human": "2.0 KB", "source_context": "Laboratory Sample"},
        anomaly_count=0,
    )

    res = auth_client.get(f"/investigation/{inv_id}/custody")
    assert res.status_code == 200
    assert b"FORENSIC DIGITAL EVIDENCE CHAIN OF CUSTODY CERTIFICATE" in res.data
    assert b"Tamper-Evident Seal" in res.data
