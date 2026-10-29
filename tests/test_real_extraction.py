"""
tests/test_real_extraction.py
Runs actual ExifTool against real generated images.
Verifies real metadata extraction, hashing, differential comparison, and anomaly detection.
"""

import os
import pytest
from core.exiftool_runner import extract_metadata
from core.hasher import compute_file_hashes, compare_file_hashes
from core.comparator import compare_metadata
from core.anomaly_detector import detect_file_anomalies, detect_comparison_anomalies

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "samples"))
SAMPLE_CAMERA = os.path.join(SAMPLES_DIR, "sample_camera.jpg")
SAMPLE_EDITED = os.path.join(SAMPLES_DIR, "sample_edited.jpg")
SAMPLE_STRIPPED = os.path.join(SAMPLES_DIR, "sample_stripped.png")


def test_real_exiftool_extraction_camera():
    assert os.path.isfile(SAMPLE_CAMERA)
    result = extract_metadata(SAMPLE_CAMERA)
    assert result["success"] is True
    assert result["tag_count"] > 10

    summary = result["summary"]
    assert summary["camera_make"] == "Canon"
    assert summary["camera_model"] == "Canon EOS 80D"
    assert summary["date_original"] == "2026-10-20 14:35:10"
    assert summary["gps_position"] is not None or summary["gps_latitude"] is not None

    # Verify groups
    assert "EXIF" in result["groups"]
    assert "File" in result["groups"]


def test_real_hashing_and_tampering_differential():
    # 1. Hashes should differ
    hashes_cam = compute_file_hashes(SAMPLE_CAMERA)
    hashes_edt = compute_file_hashes(SAMPLE_EDITED)
    assert hashes_cam["sha256"] != hashes_edt["sha256"]

    comp_hash = compare_file_hashes(SAMPLE_CAMERA, SAMPLE_EDITED)
    assert comp_hash["sha256_match"] is False
    assert comp_hash["status"] == "DIFFERENT_BYTES"

    # 2. Extract metadata from both
    meta_cam = extract_metadata(SAMPLE_CAMERA)
    meta_edt = extract_metadata(SAMPLE_EDITED)

    # 3. Compare metadata
    diff = compare_metadata(meta_cam, meta_edt)
    assert diff["metrics"]["changed_count"] >= 1  # Software or dimensions changed
    assert diff["metrics"]["matching_count"] >= 1  # Make and Model match

    # 4. Check anomaly detection
    # Edited image should trigger editor signature
    anomalies_edt = detect_file_anomalies(meta_edt, SAMPLE_EDITED)
    rule_ids = [a["rule_id"] for a in anomalies_edt]
    assert "ANOM_EDITOR_SIGNATURE" in rule_ids

    # Comparison should detect editor introduced and GPS stripped
    diff_anomalies = detect_comparison_anomalies(
        meta_cam, meta_edt, diff, SAMPLE_CAMERA, SAMPLE_EDITED
    )
    diff_rule_ids = [a["rule_id"] for a in diff_anomalies]
    assert "DIFF_EDITOR_INTRODUCED" in diff_rule_ids
    assert "DIFF_GPS_STRIPPED" in diff_rule_ids or "DIFF_DIMENSIONS_ALTERED" in diff_rule_ids


def test_real_stripped_image():
    meta_strip = extract_metadata(SAMPLE_STRIPPED)
    assert meta_strip["success"] is True
    anomalies = detect_file_anomalies(meta_strip, SAMPLE_STRIPPED)
    # Stripped PNG has no camera info and very few tags
    assert meta_strip["summary"]["camera_make"] is None
