"""
tests/test_single_analysis.py
Comprehensive automated test suite for Single Image Metadata Authenticity Analysis.
Validates all requirements of Section 9:
- Ordinary metadata image
- Missing / stripped metadata image
- Conflicting timestamp fields
- Image containing software tag
- Mismatched extension and detected format
- Corrupt / unsupported file handling
- Empty metadata output handling
- ExifTool missing / timeout simulation
- SHA-256 hash calculation correctness
- No false claims of authenticity
- Multiple findings analysis
- Web routes and evidence report generation
"""

import hashlib
import io
import os
import subprocess
from unittest.mock import patch
import pytest

from core.exiftool_runner import extract_metadata
from core.single_analyzer import (
    analyze_single_image,
    check_format_consistency,
    check_metadata_completeness,
    check_software_signatures,
    check_timestamps,
    CLASSIFICATION_CLEAN,
    CLASSIFICATION_INCONCLUSIVE,
    CLASSIFICATION_SUSPICIOUS,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
)
import core.database as db
from app import app


SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
SAMPLE_CAMERA = os.path.join(SAMPLES_DIR, "sample_camera.jpg")
SAMPLE_EDITED = os.path.join(SAMPLES_DIR, "sample_edited.jpg")
SAMPLE_STRIPPED = os.path.join(SAMPLES_DIR, "sample_stripped.png")


@pytest.fixture
def auth_client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user_id"] = "Bhuvana@123"
            sess["_csrf_token"] = "test_csrf_token"
        yield client


# 1. Ordinary Metadata Image
def test_ordinary_metadata_image():
    assert os.path.exists(SAMPLE_CAMERA)
    meta = extract_metadata(SAMPLE_CAMERA)
    with open(SAMPLE_CAMERA, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    res = analyze_single_image(meta, SAMPLE_CAMERA, file_hash, os.path.getsize(SAMPLE_CAMERA))
    # Should not produce high-severity findings
    assert not any(f["severity"] == SEVERITY_HIGH for f in res["findings"])
    # Must never claim absolute "Authentic"
    assert "Authentic" not in res["classification_title"]
    assert "FORENSIC LIMITATION NOTICE" in res["disclaimer"]


# 2. Missing / Stripped Metadata Image
def test_stripped_metadata_image():
    assert os.path.exists(SAMPLE_STRIPPED)
    meta = extract_metadata(SAMPLE_STRIPPED)
    with open(SAMPLE_STRIPPED, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    res = analyze_single_image(meta, SAMPLE_STRIPPED, file_hash, os.path.getsize(SAMPLE_STRIPPED))
    # Stripped metadata should be inconclusive or informational, never HIGH severity tampering
    assert res["classification"] == CLASSIFICATION_INCONCLUSIVE
    assert not any(f["severity"] == SEVERITY_HIGH for f in res["findings"])


# 3. Conflicting Timestamp Fields (Inversion)
def test_conflicting_timestamp_fields():
    raw_meta = {
        "EXIF:DateTimeOriginal": "2026:10:20 14:00:00",
        "EXIF:ModifyDate": "2026:10:15 10:00:00",  # 5 days earlier!
    }
    summary = {
        "date_original": "2026:10:20 14:00:00",
        "date_modify": "2026:10:15 10:00:00",
    }
    findings, chk = check_timestamps(raw_meta, summary)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "RULE_TIME_INVERSION"
    assert findings[0]["severity"] == SEVERITY_HIGH
    assert "precedes the original capture" in findings[0]["explanation"]
    assert "benign_explanation" in findings[0]
    assert "next_step" in findings[0]
    assert chk["status"] == "FLAGGED"


# 4. Image Containing a Software Tag
def test_image_containing_software_tag():
    raw_meta = {
        "XMP:CreatorTool": "Adobe Photoshop 2024 (Windows)",
    }
    summary = {
        "software": "Adobe Photoshop 2024",
    }
    findings, chk = check_software_signatures(raw_meta, summary)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "RULE_EDITOR_SIGNATURE"
    assert findings[0]["severity"] == SEVERITY_MEDIUM
    assert "Adobe Photoshop" in findings[0]["observed_value"]
    # Verify benign explanation is documented
    assert "cropping" in findings[0]["benign_explanation"].lower() or "routine" in findings[0]["benign_explanation"].lower()


# 5. File Extension and Format Mismatch
def test_format_extension_mismatch():
    raw_meta = {
        "File:FileType": "JPEG",
        "File:MIMEType": "image/jpeg",
    }
    summary = {
        "file_type": "jpeg",
        "mime_type": "image/jpeg",
    }
    findings, chk = check_format_consistency("evidence_photo.png", raw_meta, summary)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "RULE_FORMAT_MISMATCH"
    assert findings[0]["severity"] == SEVERITY_MEDIUM
    assert chk["status"] == "FLAGGED"


# 6. Corrupt or Unsupported File Upload via HTTP
def test_corrupt_or_unsupported_file_upload(auth_client):
    # Upload executable file disguised as png
    fake_exe = io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00ThisIsNotAnImage")
    data = {"evidence_file": (fake_exe, "malicious.exe")}
    res = auth_client.post("/single-analysis", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert res.status_code == 200
    assert b"Unsupported file format" in res.data


# 7. Empty Metadata Output Handling
def test_empty_metadata_output():
    empty_meta = {"raw": {}, "summary": {}, "groups": {}, "tag_count": 0}
    res = analyze_single_image(empty_meta, "empty.jpg", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert res["classification"] == CLASSIFICATION_INCONCLUSIVE
    assert res["findings_count"] == 0 or any(f["severity"] == SEVERITY_INFO for f in res["findings"])


# 8. ExifTool Missing / Timeout Handling
def test_exiftool_timeout_handling():
    with patch("subprocess.run") as mock_sub:
        mock_sub.side_effect = subprocess.TimeoutExpired(cmd=["exiftool"], timeout=15)
        res = extract_metadata(SAMPLE_CAMERA)
        assert "error" in res
        assert "timed out" in res["error"].lower()


def test_exiftool_missing_binary_handling():
    with patch("subprocess.run") as mock_sub:
        mock_sub.side_effect = FileNotFoundError("Executable not found")
        res = extract_metadata(SAMPLE_CAMERA)
        assert "error" in res
        assert "not found" in res["error"].lower()


# 9. Cryptographic Hash Calculation Correctness
def test_sha256_hash_calculation():
    test_bytes = b"Digital Forensic Verification Payload 2026"
    expected_hash = hashlib.sha256(test_bytes).hexdigest()
    meta = {"raw": {"File:FileType": "JPEG"}, "summary": {"file_type": "jpeg"}, "groups": {"File": {}}, "tag_count": 1}
    res = analyze_single_image(meta, "test.jpg", expected_hash, len(test_bytes))
    assert res["sha256"] == expected_hash
    chk = next(c for c in res["checks_performed"] if c["check_id"] == "CHECK_SHA256_FINGERPRINT")
    assert chk["status"] == "PASS"


# 10. No False Claim of Authenticity on Clean Metadata
def test_no_false_claim_of_authenticity():
    clean_meta = {
        "raw": {
            "File:FileType": "JPEG",
            "EXIF:Make": "Canon",
            "EXIF:Model": "Canon EOS 80D",
            "EXIF:DateTimeOriginal": "2026:10:20 12:00:00",
            "EXIF:ModifyDate": "2026:10:20 12:00:00",
            "EXIF:ISO": 100,
            "EXIF:FNumber": 2.8,
            "EXIF:ExposureTime": "1/250",
        },
        "summary": {
            "file_type": "jpeg",
            "camera_make": "Canon",
            "camera_model": "Canon EOS 80D",
            "date_original": "2026:10:20 12:00:00",
            "date_modify": "2026:10:20 12:00:00",
        },
        "groups": {"EXIF": {}, "File": {}},
        "tag_count": 35,
    }
    res = analyze_single_image(clean_meta, "clean.jpg", "a" * 64, 50000)
    assert res["classification"] == CLASSIFICATION_CLEAN
    assert res["classification_title"] == "No Significant Indicators Detected"
    # Never claim "Authentic"
    assert "Authentic" not in res["classification_title"]
    assert "does NOT establish authenticity" in res["classification_description"]


# 11. Multiple Findings Analysis
def test_multiple_findings_analysis():
    tampered_meta = {
        "raw": {
            "File:FileType": "JPEG",
            "EXIF:DateTimeOriginal": "2026:10:20 14:00:00",
            "EXIF:ModifyDate": "2026:10:15 10:00:00",  # Inversion
            "XMP:CreatorTool": "Adobe Photoshop 2024",  # Editor tag
            "EXIF:Make": "Nikon",
            "XMP:Make": "Canon",  # Conflict
        },
        "summary": {
            "file_type": "jpeg",
            "date_original": "2026:10:20 14:00:00",
            "date_modify": "2026:10:15 10:00:00",
            "software": "Adobe Photoshop 2024",
        },
        "groups": {"EXIF": {}, "XMP": {}, "File": {}},
        "tag_count": 30,
    }
    res = analyze_single_image(tampered_meta, "tampered.jpg", "b" * 64, 45000)
    assert res["classification"] == CLASSIFICATION_SUSPICIOUS
    assert res["findings_count"] >= 3
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "RULE_TIME_INVERSION" in rule_ids
    assert "RULE_EDITOR_SIGNATURE" in rule_ids
    assert "RULE_STRUCT_MAKE_CONFLICT" in rule_ids


# 12. Full Web Flow: Upload, Results, and Report Download
def test_single_analysis_web_flow(auth_client):
    assert os.path.exists(SAMPLE_CAMERA)
    with open(SAMPLE_CAMERA, "rb") as f:
        file_bytes = f.read()

    data = {
        "evidence_file": (io.BytesIO(file_bytes), "sample_camera.jpg"),
        "case_title": "Automated Web Flow Case",
        "notes": "Testing single image analysis web flow",
    }

    # POST to /single-analysis
    res = auth_client.post("/single-analysis", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    assert b"Single Image Metadata Authenticity Analysis" in res.data
    assert b"Forensic Result Classification" in res.data
    assert b"Cryptographic Evidence Fingerprint" in res.data
    assert b"Checks Performed Matrix" in res.data

    # Retrieve saved investigation
    invs = db.list_investigations()
    sa_inv = next((inv for inv in invs if inv["case_title"] == "Automated Web Flow Case"), None)
    assert sa_inv is not None

    # Test downloadable printable report
    res_report = auth_client.get(f"/single-analysis/report/{sa_inv['id']}")
    assert res_report.status_code == 200
    assert b"TRACE: Single Image Metadata Authenticity Report" in res_report.data
    assert b"Forensic Classification" in res_report.data
    assert b"Forensic Transparency &amp; Uncertainty Disclosure" in res_report.data

    # Cleanup test investigation
    db.delete_investigation(sa_inv["id"])
