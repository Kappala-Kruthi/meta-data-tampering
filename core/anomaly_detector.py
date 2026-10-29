"""
core/anomaly_detector.py
Defensible, explainable forensic heuristic anomaly detection engine.
Flags editing traces, timestamp inconsistencies, file-type discrepancies, and metadata stripping.
Does not make unverified claims or fabricate statistical probabilities.
"""

from datetime import datetime
import os
import re
from typing import Any, Dict, List, Optional


KNOWN_EDITORS = [
    "photoshop", "gimp", "canva", "lightroom", "exiftool", "snapseed",
    "pixlr", "paint.net", "photopea", "picsart", "vsco", "afterlight",
    "affinity", "corel", "imagemagick", "picasa", "fotor", "inpaint"
]

SEVERITY_INFORMATIONAL = "INFORMATIONAL"
SEVERITY_REVIEW = "REVIEW_RECOMMENDED"
SEVERITY_SIGNIFICANT = "SIGNIFICANT_DIFFERENCE"


def parse_datetime(dt_str: str) -> Optional[datetime]:
    """Attempts to parse common ExifTool date/time formats."""
    if not dt_str or not isinstance(dt_str, str):
        return None
    # Strip timezone suffixes like +05:30 or Z for basic comparison
    clean_str = re.sub(r"([+-]\d{2}:\d{2}|Z)$", "", dt_str.strip())
    # Standard formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y:%m:%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y:%m:%d %H:%M",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(clean_str[:19], fmt)
        except (ValueError, TypeError):
            continue
    return None


def detect_file_anomalies(metadata_dict: Dict[str, Any], file_path: str) -> List[Dict[str, Any]]:
    """
    Analyzes metadata of a single file for anomalies, inconsistencies, and editor signatures.
    """
    anomalies: List[Dict[str, Any]] = []
    raw = metadata_dict.get("raw", {})
    summary = metadata_dict.get("summary", {})

    # 1. File Type and Extension Consistency Check
    ext = os.path.splitext(file_path)[1].lower().lstrip(".")
    detected_type = (summary.get("file_type") or "").lower()
    mime_type = (summary.get("mime_type") or "").lower()

    # Common extension to ExifTool type mapping
    ext_map = {
        "jpg": ["jpeg"],
        "jpeg": ["jpeg"],
        "png": ["png"],
        "webp": ["webp"],
        "tif": ["tiff"],
        "tiff": ["tiff"],
        "heic": ["heic", "heif"],
    }
    if ext in ext_map and detected_type:
        if detected_type not in ext_map[ext] and detected_type != ext:
            anomalies.append({
                "rule_id": "ANOM_EXT_TYPE_MISMATCH",
                "severity": SEVERITY_REVIEW,
                "title": "File Extension and Format Discrepancy",
                "description": (
                    f"The file extension (.{ext}) does not match the actual binary format "
                    f"detected by ExifTool ({detected_type.upper()})."
                ),
                "evidence": f"Extension: .{ext} | Detected Type: {detected_type} ({mime_type})",
                "mitigating_factors": "Renaming a file manually does not alter internal image bytes.",
            })

    # 2. Editing Tool / Software Signature Detection
    software_val = summary.get("software") or ""
    # Also check specific raw tags for editor traces
    potential_editor_tags = [
        "Software", "XMP:CreatorTool", "XMP:HistorySoftwareAgent",
        "Photoshop:History", "IFD0:Software", "XMP-xmp:CreatorTool"
    ]
    detected_editors = []
    for tag in potential_editor_tags:
        for k, v in raw.items():
            if tag.lower() in k.lower():
                v_str = str(v).lower()
                for ed in KNOWN_EDITORS:
                    if ed in v_str and ed not in detected_editors:
                        detected_editors.append(ed.title())

    if detected_editors:
        anomalies.append({
            "rule_id": "ANOM_EDITOR_SIGNATURE",
            "severity": SEVERITY_REVIEW,
            "title": "Editing Software Signature Detected",
            "description": (
                f"Metadata contains signatures from graphic/editing software: {', '.join(detected_editors)}. "
                "This indicates the file was created or re-saved using an editing suite."
            ),
            "evidence": f"Detected tool signatures: {', '.join(detected_editors)} (Software tag: {software_val or 'Present in XMP/IFD'})",
            "mitigating_factors": "May indicate simple cropping, resizing, or intentional creative editing.",
        })

    # 3. Timestamp Relationship Analysis
    date_orig = parse_datetime(summary.get("date_original"))
    date_create = parse_datetime(summary.get("date_create"))
    date_modify = parse_datetime(summary.get("date_modify"))

    # If modify date is significantly earlier than capture date
    if date_orig and date_modify:
        if date_modify < date_orig:
            diff_seconds = (date_orig - date_modify).total_seconds()
            if diff_seconds > 60:  # Allow 1-minute margin for clock variations
                anomalies.append({
                    "rule_id": "ANOM_TIMESTAMP_INVERSION",
                    "severity": SEVERITY_SIGNIFICANT,
                    "title": "Chronological Inconsistency in Timestamps",
                    "description": (
                        "The reported modification timestamp is earlier than the original capture timestamp. "
                        "This is physically impossible under standard operations and suggests clock skew or metadata manipulation."
                    ),
                    "evidence": (
                        f"Original Capture: {summary.get('date_original')} | "
                        f"Modification Date: {summary.get('date_modify')}"
                    ),
                    "mitigating_factors": "Camera clock might have been reset or incorrect timezone offset applied.",
                })

    # 4. Metadata Stripping / Sparsity Assessment
    tag_count = metadata_dict.get("tag_count", 0)
    has_camera = bool(summary.get("camera_make") or summary.get("camera_model"))
    has_exif = "EXIF" in metadata_dict.get("groups", {})

    if detected_type in ["jpeg", "tiff", "heic"] and not has_camera and tag_count < 20:
        anomalies.append({
            "rule_id": "ANOM_METADATA_STRIPPED",
            "severity": SEVERITY_INFORMATIONAL,
            "title": "Sparse Metadata / Potential Privacy Scrubbing",
            "description": (
                f"The image contains only {tag_count} metadata tags and lacks standard camera hardware details. "
                "The metadata may have been stripped by social media platforms, messaging apps, or privacy tools."
            ),
            "evidence": f"Total tags: {tag_count} | Camera Make/Model: None | EXIF Group: {'Yes' if has_exif else 'Missing'}",
            "mitigating_factors": "Platforms like WhatsApp, Twitter/X, and Instagram automatically strip EXIF upon upload.",
        })

    # 5. GPS Metadata Presence (Informational Privacy Flag)
    if summary.get("gps_position") or summary.get("gps_latitude"):
        anomalies.append({
            "rule_id": "INFO_GPS_PRESENT",
            "severity": SEVERITY_INFORMATIONAL,
            "title": "Geotagging / GPS Coordinates Present",
            "description": "The file contains geolocation coordinates indicating physical location where media was recorded.",
            "evidence": f"Coordinates: {summary.get('gps_position') or (summary.get('gps_latitude') + ', ' + summary.get('gps_longitude'))}",
            "mitigating_factors": "Standard feature in smartphones and modern GPS-enabled cameras.",
        })

    return anomalies


def detect_comparison_anomalies(
    meta_a: Dict[str, Any],
    meta_b: Dict[str, Any],
    comp_results: Dict[str, Any],
    file_a_path: str,
    file_b_path: str,
) -> List[Dict[str, Any]]:
    """
    Analyzes differential metadata between two files to flag forensic discrepancies.
    """
    diff_anomalies: List[Dict[str, Any]] = []

    raw_a = meta_a.get("raw", {})
    raw_b = meta_b.get("raw", {})
    sum_a = meta_a.get("summary", {})
    sum_b = meta_b.get("summary", {})

    # 1. Editor Injected into File B
    sw_a = (sum_a.get("software") or "").lower()
    sw_b = (sum_b.get("software") or "").lower()

    has_ed_a = any(ed in sw_a for ed in KNOWN_EDITORS)
    has_ed_b = any(ed in sw_b for ed in KNOWN_EDITORS)

    if not has_ed_a and has_ed_b:
        diff_anomalies.append({
            "rule_id": "DIFF_EDITOR_INTRODUCED",
            "severity": SEVERITY_SIGNIFICANT,
            "title": "Editing Software Introduced in File B",
            "description": (
                "File A shows no editing software signatures, but File B contains explicit editing software tags. "
                "This indicates File B is an edited or re-saved derivative."
            ),
            "evidence": f"File A Software: '{sum_a.get('software') or 'None'}' vs File B Software: '{sum_b.get('software')}'",
            "mitigating_factors": "Normal workflow if File B was an intended production export from File A.",
        })

    # 2. GPS Removal / Modification
    gps_a = sum_a.get("gps_position") or sum_a.get("gps_latitude")
    gps_b = sum_b.get("gps_position") or sum_b.get("gps_latitude")

    if gps_a and not gps_b:
        diff_anomalies.append({
            "rule_id": "DIFF_GPS_STRIPPED",
            "severity": SEVERITY_REVIEW,
            "title": "Geolocation Stripped in File B",
            "description": "File A contains GPS coordinates which have been removed or absent in File B.",
            "evidence": f"File A GPS: {gps_a} | File B GPS: None",
            "mitigating_factors": "Common in privacy-preserving exports and social media sharing.",
        })
    elif gps_a and gps_b and str(gps_a).strip() != str(gps_b).strip():
        diff_anomalies.append({
            "rule_id": "DIFF_GPS_ALTERED",
            "severity": SEVERITY_SIGNIFICANT,
            "title": "Geolocation Coordinates Altered",
            "description": "Both files contain GPS metadata, but the reported coordinates differ between them.",
            "evidence": f"File A GPS: {gps_a} | File B GPS: {gps_b}",
            "mitigating_factors": "Could represent two separate photographs taken at different locations.",
        })

    # 3. Dimension / Resolution Change
    w_a, h_a = sum_a.get("image_width"), sum_a.get("image_height")
    w_b, h_b = sum_b.get("image_width"), sum_b.get("image_height")
    if w_a and h_a and w_b and h_b:
        if str(w_a) != str(w_b) or str(h_a) != str(h_b):
            diff_anomalies.append({
                "rule_id": "DIFF_DIMENSIONS_ALTERED",
                "severity": SEVERITY_REVIEW,
                "title": "Image Dimensions Modified",
                "description": f"Pixel dimensions differ between File A ({w_a}x{h_a}) and File B ({w_b}x{h_b}).",
                "evidence": f"Resolution A: {w_a}x{h_a} vs Resolution B: {w_b}x{h_b}",
                "mitigating_factors": "May be caused by cropping, resizing, or downsampling.",
            })

    # 4. Significant Metadata Purge
    cnt_a = meta_a.get("tag_count", 0)
    cnt_b = meta_b.get("tag_count", 0)
    if cnt_a > 30 and cnt_b < 15:
        diff_anomalies.append({
            "rule_id": "DIFF_METADATA_PURGE",
            "severity": SEVERITY_REVIEW,
            "title": "Major Metadata Reduction in File B",
            "description": (
                f"File A possesses {cnt_a} metadata tags, whereas File B has only {cnt_b}. "
                "Substantial metadata was stripped or omitted during processing."
            ),
            "evidence": f"File A Tag Count: {cnt_a} | File B Tag Count: {cnt_b}",
            "mitigating_factors": "Standard for web-optimization exports ('Save for Web').",
        })

    return diff_anomalies
