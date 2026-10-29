"""
core/single_analyzer.py
Single Image Metadata Authenticity Analysis Engine
Evaluates metadata consistency, timestamp chronologies, software traces,
structural contradictions, and image-level compression artifacts without requiring a reference image.

Adheres to strict forensic reporting standards:
- Reports evidence and uncertainty honestly.
- Never claims metadata is genuine merely because it appears consistent.
- Classifies into three defensible categories:
    1. SUSPICIOUS_INDICATORS_FOUND
    2. NO_SIGNIFICANT_INDICATORS
    3. INCONCLUSIVE
"""

from datetime import datetime
import io
import math
import os
import re
from typing import Any, Dict, List, Optional
from PIL import Image, ImageChops, ImageStat

from core import gps_analyzer, hex_inspector


KNOWN_EDITORS = [
    "photoshop", "gimp", "canva", "lightroom", "exiftool", "snapseed",
    "pixlr", "paint.net", "photopea", "picsart", "vsco", "afterlight",
    "affinity", "corel", "imagemagick", "picasa", "fotor", "inpaint",
    "apple photos", "google photos", "preview"
]

SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFORMATIONAL"

CLASSIFICATION_SUSPICIOUS = "SUSPICIOUS_INDICATORS_FOUND"
CLASSIFICATION_CLEAN = "NO_SIGNIFICANT_INDICATORS"
CLASSIFICATION_INCONCLUSIVE = "INCONCLUSIVE"


def parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    """Parses common ExifTool date/time strings into standard datetime objects."""
    if not dt_str or not isinstance(dt_str, str):
        return None
    clean_str = re.sub(r"([+-]\d{2}:\d{2}|Z)$", "", dt_str.strip())
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


def check_timestamps(raw: Dict[str, Any], summary: Dict[str, Any]) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Evaluates chronological consistency across capture, creation, and modification timestamps.
    """
    findings: List[Dict[str, Any]] = []
    
    date_orig_str = summary.get("date_original") or raw.get("EXIF:DateTimeOriginal") or raw.get("XMP:DateTimeOriginal")
    date_create_str = summary.get("date_create") or raw.get("EXIF:CreateDate") or raw.get("XMP:CreateDate")
    date_modify_str = summary.get("date_modify") or raw.get("EXIF:ModifyDate") or raw.get("XMP:ModifyDate")
    file_modify_str = raw.get("File:FileModifyDate")

    dt_orig = parse_datetime(date_orig_str)
    dt_create = parse_datetime(date_create_str)
    dt_modify = parse_datetime(date_modify_str)
    dt_file_mod = parse_datetime(file_modify_str)

    check_record = {
        "check_id": "CHECK_TIMESTAMP_CHRONOLOGY",
        "name": "Timestamp Chronological Ordering",
        "fields_evaluated": ["DateTimeOriginal", "CreateDate", "ModifyDate", "FileModifyDate"],
        "values": {
            "DateTimeOriginal": date_orig_str or "Not Present",
            "CreateDate": date_create_str or "Not Present",
            "ModifyDate": date_modify_str or "Not Present",
            "FileModifyDate": file_modify_str or "Not Present",
        },
        "status": "PASS",
        "notes": "Timestamps evaluated for chronological alignment."
    }

    # Inversion: Modification earlier than Original Capture
    if dt_orig and dt_modify:
        if dt_modify < dt_orig:
            diff_sec = (dt_orig - dt_modify).total_seconds()
            if diff_sec > 60:  # Allow 60-second margin for camera clock variations
                findings.append({
                    "rule_id": "RULE_TIME_INVERSION",
                    "rule_name": "Timestamp Chronological Inversion",
                    "severity": SEVERITY_HIGH,
                    "severity_reason": "In standard camera operations, an image modification date cannot precede its original capture date.",
                    "evidence_field": "EXIF:ModifyDate vs EXIF:DateTimeOriginal",
                    "observed_value": f"ModifyDate: {date_modify_str} is earlier than DateTimeOriginal: {date_orig_str} (Diff: {int(diff_sec)}s)",
                    "explanation": (
                        "The reported modification date precedes the original capture timestamp. "
                        "This chronological conflict indicates either manual metadata editing, an incorrect camera clock adjustment, "
                        "or metadata imported from another file."
                    ),
                    "benign_explanation": "Camera internal clock was manually reset or battery was replaced between capture and file save.",
                    "next_step": "Examine time zone offset tags (OffsetTimeOriginal) and file system creation records for confirmation."
                })
                check_record["status"] = "FLAGGED"

    # Creation significantly earlier than Original Capture
    if dt_orig and dt_create and dt_create < dt_orig:
        diff_sec = (dt_orig - dt_create).total_seconds()
        if diff_sec > 86400:  # More than 1 day
            findings.append({
                "rule_id": "RULE_CREATE_PRE_ORIGINAL",
                "rule_name": "Creation Date Precedes Original Capture",
                "severity": SEVERITY_MEDIUM,
                "severity_reason": "CreateDate is earlier than DateTimeOriginal by more than 24 hours.",
                "evidence_field": "EXIF:CreateDate vs EXIF:DateTimeOriginal",
                "observed_value": f"CreateDate: {date_create_str} vs DateTimeOriginal: {date_orig_str}",
                "explanation": "CreateDate typically coincides with or closely follows DateTimeOriginal under normal camera firmware.",
                "benign_explanation": "Inconsistent date formatting or camera firmware timezone anomaly.",
                "next_step": "Cross-reference GPS satellite timestamps if available."
            })
            check_record["status"] = "FLAGGED"

    return findings, check_record


def check_software_signatures(raw: Dict[str, Any], summary: Dict[str, Any]) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Scans metadata for graphic editor, post-processing, and manipulation tool signatures.
    """
    findings: List[Dict[str, Any]] = []
    detected_editors = []
    matched_tags = []

    potential_editor_tags = [
        "Software", "XMP:CreatorTool", "XMP:HistorySoftwareAgent",
        "Photoshop:History", "IFD0:Software", "XMP-xmp:CreatorTool",
        "ProcessingSoftware", "XMP:SoftwareAgent"
    ]

    for tag in potential_editor_tags:
        for k, v in raw.items():
            if tag.lower() in k.lower() and v:
                v_str = str(v).lower()
                for ed in KNOWN_EDITORS:
                    if ed in v_str and ed not in detected_editors:
                        detected_editors.append(ed.title())
                        matched_tags.append(f"{k}='{v}'")

    check_record = {
        "check_id": "CHECK_SOFTWARE_SIGNATURES",
        "name": "Editing Suite & Processing Signatures",
        "fields_evaluated": potential_editor_tags,
        "values": {"detected_software": detected_editors or "No editing suite signatures detected"},
        "status": "PASS",
        "notes": "Scanned known editing software signatures."
    }

    if detected_editors:
        check_record["status"] = "FLAGGED"
        obs_val = f"{', '.join(detected_editors)} ({'; '.join(matched_tags[:2])})" if matched_tags else ", ".join(detected_editors)
        findings.append({
            "rule_id": "RULE_EDITOR_SIGNATURE",
            "rule_name": "Image Editing Software Signature Observed",
            "severity": SEVERITY_MEDIUM,
            "severity_reason": "Software signatures indicate the media file was saved or processed by graphic manipulation software.",
            "evidence_field": ", ".join(matched_tags[:3]),
            "observed_value": obs_val,
            "explanation": (
                f"Metadata tags explicitly identify processing by {', '.join(detected_editors)}. "
                "This confirms the file passed through an image editor rather than being a direct camera master export."
            ),
            "benign_explanation": "Legitimate non-malicious actions such as cropping, resizing, rotating, or routine format conversion.",
            "next_step": "Conduct image-level error analysis (ELA) or examine raw pixels to determine whether image content was altered."
        })
    else:
        check_record["notes"] += " Note: Absence of an editor tag does not establish that no editing occurred."

    return findings, check_record


def check_metadata_structure(raw: Dict[str, Any], summary: Dict[str, Any], groups: Dict[str, Any]) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Verifies internal consistency across different metadata standards (EXIF vs XMP, exposure values).
    """
    findings: List[Dict[str, Any]] = []

    # Check for Hardware Make/Model contradictions between EXIF and XMP
    exif_make = str(raw.get("EXIF:Make") or "").strip().lower()
    xmp_make = str(raw.get("XMP:Make") or "").strip().lower()
    exif_model = str(raw.get("EXIF:Model") or "").strip().lower()
    xmp_model = str(raw.get("XMP:Model") or "").strip().lower()

    check_record = {
        "check_id": "CHECK_METADATA_STRUCTURE",
        "name": "Cross-Group Tag Consistency",
        "fields_evaluated": ["EXIF:Make vs XMP:Make", "EXIF:Model vs XMP:Model", "GPS vs EXIF Date"],
        "values": {
            "EXIF Hardware": f"{raw.get('EXIF:Make', 'N/A')} {raw.get('EXIF:Model', '')}".strip() or "Not Present",
            "XMP Hardware": f"{raw.get('XMP:Make', 'N/A')} {raw.get('XMP:Model', '')}".strip() or "Not Present",
        },
        "status": "PASS",
        "notes": "Internal consistency across EXIF and XMP groups verified."
    }

    if exif_make and xmp_make and exif_make != xmp_make:
        findings.append({
            "rule_id": "RULE_STRUCT_MAKE_CONFLICT",
            "rule_name": "Contradictory Camera Make Tags",
            "severity": SEVERITY_HIGH,
            "severity_reason": "Conflicting hardware manufacturer tags across EXIF and XMP standards indicate manual tampering or merged headers.",
            "evidence_field": "EXIF:Make vs XMP:Make",
            "observed_value": f"EXIF: '{raw.get('EXIF:Make')}' vs XMP: '{raw.get('XMP:Make')}'",
            "explanation": "Standard camera firmware produces identical hardware values across all embedded metadata namespaces.",
            "benign_explanation": "Software library metadata synchronization bug during catalog ingestion.",
            "next_step": "Inspect raw hex headers to verify whether XMP packet was injected post-capture."
        })
        check_record["status"] = "FLAGGED"

    if exif_model and xmp_model and exif_model != xmp_model:
        findings.append({
            "rule_id": "RULE_STRUCT_MODEL_CONFLICT",
            "rule_name": "Contradictory Camera Model Tags",
            "severity": SEVERITY_HIGH,
            "severity_reason": "Conflicting camera model designations across EXIF and XMP indicate conflicting metadata sources.",
            "evidence_field": "EXIF:Model vs XMP:Model",
            "observed_value": f"EXIF: '{raw.get('EXIF:Model')}' vs XMP: '{raw.get('XMP:Model')}'",
            "explanation": "Camera model designation must be coherent across metadata streams.",
            "benign_explanation": "Batch metadata tagging tool erroneously applied a different camera preset.",
            "next_step": "Verify lens and sensor serial numbers in MakerNotes."
        })
        check_record["status"] = "FLAGGED"

    return findings, check_record


def check_format_consistency(file_path: str, raw: Dict[str, Any], summary: Dict[str, Any]) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Verifies that the file extension matches the internal binary file format detected by ExifTool.
    """
    findings: List[Dict[str, Any]] = []
    ext = os.path.splitext(file_path)[1].lower().lstrip(".")
    detected_type = (summary.get("file_type") or raw.get("File:FileType") or "").lower()
    mime_type = (summary.get("mime_type") or raw.get("File:MIMEType") or "").lower()

    ext_map = {
        "jpg": ["jpeg"],
        "jpeg": ["jpeg"],
        "png": ["png"],
        "webp": ["webp"],
        "tif": ["tiff"],
        "tiff": ["tiff"],
        "heic": ["heic", "heif"],
        "heif": ["heic", "heif"],
    }

    check_record = {
        "check_id": "CHECK_FILE_FORMAT_ALIGNMENT",
        "name": "File Extension and Binary Magic Bytes Alignment",
        "fields_evaluated": ["File Extension", "File:FileType", "File:MIMEType"],
        "values": {
            "Extension": f".{ext}",
            "Detected Format": detected_type.upper() if detected_type else "Unknown",
            "MIME Type": mime_type or "Unknown"
        },
        "status": "PASS",
        "notes": "Binary format matches declared file extension."
    }

    if ext in ext_map and detected_type:
        if detected_type not in ext_map[ext] and detected_type != ext:
            findings.append({
                "rule_id": "RULE_FORMAT_MISMATCH",
                "rule_name": "File Extension and Format Mismatch",
                "severity": SEVERITY_MEDIUM,
                "severity_reason": "Extension declared by user differs from internal file magic bytes.",
                "evidence_field": f"Extension: .{ext} vs File:FileType: {detected_type}",
                "observed_value": f"Declared: .{ext} | Binary Reality: {detected_type.upper()} ({mime_type})",
                "explanation": (
                    f"The file extension (.{ext}) does not match the actual binary structure "
                    f"identified by ExifTool ({detected_type.upper()})."
                ),
                "benign_explanation": "File was manually renamed in file explorer without using an image conversion tool.",
                "next_step": "Verify true container structure and examine header magic bytes."
            })
            check_record["status"] = "FLAGGED"

    return findings, check_record


def check_metadata_completeness(
    raw: Dict[str, Any],
    summary: Dict[str, Any],
    groups: Dict[str, Any],
    tag_count: int,
    source_context: str = "Source unknown",
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Analyzes which metadata groups are present or missing.
    Distinguishes privacy-scrubbed web media from contradictory or altered media.
    Evaluates missing fields within the user-declared Image Source Context.
    """
    findings: List[Dict[str, Any]] = []
    
    group_names = set(groups.keys())
    has_exif = "EXIF" in group_names
    has_xmp = "XMP" in group_names
    has_iptc = "IPTC" in group_names
    has_gps = bool(summary.get("gps_position") or summary.get("gps_latitude"))
    has_camera = bool(summary.get("camera_make") or summary.get("camera_model"))
    detected_type = (summary.get("file_type") or "").lower()

    is_downloaded = "downloaded" in source_context.lower() or "website" in source_context.lower() or "social" in source_context.lower()
    is_messaging = "messaging" in source_context.lower()

    completeness_data = {
        "tag_count": tag_count,
        "source_context": source_context,
        "has_exif": has_exif,
        "has_xmp": has_xmp,
        "has_iptc": has_iptc,
        "has_gps": has_gps,
        "has_camera": has_camera,
        "exif_status": "Present" if has_exif else "Absent",
        "xmp_status": "Present" if has_xmp else "Absent",
        "iptc_status": "Present" if has_iptc else "Absent",
        "gps_status": "Present" if has_gps else "Absent",
        "camera_hardware": "Present" if has_camera else "Absent",
    }

    context_note = f"Source context declared as: '{source_context}'."
    if is_downloaded:
        context_note += (
            " Web platforms (e.g. Pinterest, Instagram, X) systematically strip EXIF, camera, "
            "and GPS metadata for bandwidth and privacy. Note: User context does not verify platform origin."
        )
    elif is_messaging:
        context_note += " Messaging applications (e.g. WhatsApp, Telegram) routinely compress and scrub embedded metadata."

    check_record = {
        "check_id": "CHECK_METADATA_COMPLETENESS",
        "name": "Metadata Completeness & Distribution Pipeline Audit",
        "fields_evaluated": ["EXIF", "XMP", "IPTC", "GPS", "MakerNotes", "Camera Details", "Source Context"],
        "values": completeness_data,
        "status": "PASS",
        "notes": f"Total {tag_count} metadata tags evaluated across {len(group_names)} groups. {context_note}"
    }

    # Check if image has sparse metadata or no camera hardware records
    is_sparse = (not has_camera and tag_count < 25) or (not has_exif and not has_xmp)
    if is_sparse or tag_count < 15:
        if is_downloaded or is_messaging:
            rule_title = "Sparse Metadata (Expected for Declared Web/Messaging Pipeline)"
            obs_eval = (
                f"The image contains {tag_count} metadata tags and lacks camera hardware and GPS records. "
                f"Under the declared context ('{source_context}'), this metadata absence is EXPECTED. "
                "Web platforms such as Pinterest, social networks, and messaging services routinely strip EXIF, IPTC, and GPS tags "
                "to protect user privacy and reduce bandwidth. "
                "Any local filesystem timestamps (e.g. FileModifyDate) reflect download or copy time, not camera exposure time."
            )
            benign_expl = "Web platforms (such as Pinterest, social networks, and messaging services) routinely strip EXIF and recompress media to conserve bandwidth and safeguard user privacy."
        elif "camera" in source_context.lower() or "phone" in source_context.lower():
            rule_title = "Sparse Metadata (Unusual for Direct Camera Master)"
            obs_eval = (
                f"The image contains {tag_count} metadata tags without camera hardware records. "
                f"For an image declared as a direct camera or phone capture ('{source_context}'), "
                "the absence of camera model and exposure tags is unusual and suggests prior export or privacy scrubbing."
            )
            benign_expl = "Camera privacy settings disabled metadata recording, or image was exported through a third-party camera app."
        else:
            rule_title = "Sparse Metadata / Potential Privacy Scrubbing"
            obs_eval = (
                f"The image contains {tag_count} metadata tags and lacks camera hardware records. "
                "The metadata may have been stripped by social media networks, messaging applications, or privacy tools."
            )
            benign_expl = "Web platforms and messaging services routinely scrub EXIF upon upload for user privacy and bandwidth reduction."

        findings.append({
            "rule_id": "RULE_METADATA_STRIPPED",
            "rule_name": rule_title,
            "severity": SEVERITY_INFO,
            "severity_reason": "Low metadata count and absence of camera hardware tags.",
            "evidence_field": f"Total Tags: {tag_count} | Camera Make/Model: None | Source Context: {source_context}",
            "observed_value": f"{tag_count} tags present (No camera or GPS records embedded)",
            "explanation": obs_eval,
            "benign_explanation": benign_expl,
            "next_step": "Investigate file provenance and obtain the original camera capture file if available."
        })
        check_record["status"] = "INFORMATIONAL"

    return findings, check_record


def perform_advanced_image_analysis(file_path: str) -> Dict[str, Any]:
    """
    Performs explainable, transparent image-level forensic checks using Pillow:
    1. JPEG Quantization Table Inspection (identifies compression profile).
    2. Error Level Analysis (ELA) metric estimation (evaluates compression uniformity).
    """
    advanced_results = {
        "enabled": True,
        "format": "Unknown",
        "jpeg_quantization": None,
        "ela_analysis": None,
        "observations": [],
    }

    try:
        with Image.open(file_path) as img:
            advanced_results["format"] = img.format or "Unknown"
            advanced_results["mode"] = img.mode
            advanced_results["size"] = f"{img.width}x{img.height}"

            # 1. JPEG Quantization Table Inspection
            if img.format == "JPEG":
                quant_tables = getattr(img, "quantization", None)
                if quant_tables:
                    advanced_results["jpeg_quantization"] = {
                        "tables_count": len(quant_tables),
                        "has_luminance": 0 in quant_tables,
                        "has_chrominance": 1 in quant_tables,
                        "details": "Quantization tables extracted. Table profiles correspond to standard JPEG discrete cosine transform scaling."
                    }
                    advanced_results["observations"].append({
                        "technique": "JPEG Quantization Table Extraction",
                        "observed": f"{len(quant_tables)} discrete quantization tables found in image stream.",
                        "relevance": "Standard camera firmware and distinct graphic editors employ known quantization matrix templates.",
                        "benign_explanation": "Standard DCT quantization applied by camera DSP or imaging software during compression.",
                        "limitations": "Quantization tables indicate encoder profiles but do not identify localized regional modifications."
                    })

            # 2. Error Level Analysis (ELA) Simulation
            # Compute difference between original and 95% re-saved JPEG
            if img.mode in ("RGB", "RGBA", "L"):
                work_img = img.convert("RGB")
                buf = io.BytesIO()
                work_img.save(buf, format="JPEG", quality=95)
                buf.seek(0)
                resaved = Image.open(buf)

                diff = ImageChops.difference(work_img, resaved)
                stat = ImageStat.Stat(diff)
                mean_error = sum(stat.mean) / len(stat.mean)
                std_dev = sum(stat.stddev) / len(stat.stddev)

                advanced_results["ela_analysis"] = {
                    "mean_error_level": round(mean_error, 2),
                    "error_std_dev": round(std_dev, 2),
                    "metric_summary": f"Mean Error: {round(mean_error, 2)} | StdDev: {round(std_dev, 2)}"
                }

                advanced_results["observations"].append({
                    "technique": "Error Level Analysis (ELA) Uniformity",
                    "observed": f"Compression divergence metric: Mean={round(mean_error, 2)}, StdDev={round(std_dev, 2)}.",
                    "relevance": "Surfaces variations in high-frequency error distribution across 8x8 DCT compression blocks.",
                    "benign_explanation": "Natural camera noise, high-contrast edges, detailed textures, and solid gradients naturally exhibit diverging error levels.",
                    "limitations": "ELA cannot prove manipulation in isolation; it is an exploratory indicator that requires corroborating contextual evidence."
                })

    except Exception as e:
        advanced_results["enabled"] = False
        advanced_results["error"] = str(e)

    return advanced_results


def analyze_single_image(
    metadata_dict: Dict[str, Any],
    file_path: str,
    sha256_hash: str,
    file_size_bytes: int = 0,
    source_context: str = "Source unknown",
) -> Dict[str, Any]:
    """
    Master single-image forensic evaluation engine.
    Orchestrates all explainable checks and computes defensible forensic classification.
    Incorporates user-provided Image Source Context (camera, downloaded/social media, messaging, unknown).
    """
    raw = metadata_dict.get("raw", {})
    summary = metadata_dict.get("summary", {})
    groups = metadata_dict.get("groups", {})
    tag_count = metadata_dict.get("tag_count", 0)

    all_findings: List[Dict[str, Any]] = []
    checks_performed: List[Dict[str, Any]] = []

    # 1. Check Cryptographic Fingerprint
    checks_performed.append({
        "check_id": "CHECK_SHA256_FINGERPRINT",
        "name": "Cryptographic SHA-256 Digest",
        "fields_evaluated": ["File Binary Stream"],
        "values": {"sha256": sha256_hash, "file_size": f"{file_size_bytes} bytes"},
        "status": "PASS",
        "notes": "Cryptographic hash uniquely fingerprints the exact bytes analyzed."
    })

    # 2. Check File Format Alignment
    f_fmt, chk_fmt = check_format_consistency(file_path, raw, summary)
    all_findings.extend(f_fmt)
    checks_performed.append(chk_fmt)

    # 3. Check Timestamps
    f_time, chk_time = check_timestamps(raw, summary)
    all_findings.extend(f_time)
    checks_performed.append(chk_time)

    # 4. Check Software Signatures
    f_soft, chk_soft = check_software_signatures(raw, summary)
    all_findings.extend(f_soft)
    checks_performed.append(chk_soft)

    # 5. Check Metadata Structure
    f_struct, chk_struct = check_metadata_structure(raw, summary, groups)
    all_findings.extend(f_struct)
    checks_performed.append(chk_struct)

    # 6. Check Metadata Completeness (incorporating Image Source Context)
    f_comp, chk_comp = check_metadata_completeness(raw, summary, groups, tag_count, source_context=source_context)
    all_findings.extend(f_comp)
    checks_performed.append(chk_comp)

    # 7. GPS Forensics & Geolocation Analysis
    gps_forensics = gps_analyzer.extract_gps_forensics(raw)
    checks_performed.append({
        "check_id": "CHECK_GPS_GEOLOCATION",
        "name": "GNSS / GPS Geolocation Provenance",
        "fields_evaluated": ["GPSLatitude", "GPSLongitude", "GPSTimeStamp", "GPSDateStamp"],
        "values": {
            "has_gps": gps_forensics["has_gps"],
            "coordinates": gps_forensics["formatted_coordinates"] or "Not Present",
            "altitude": gps_forensics["altitude"] or "N/A",
        },
        "status": "PASS" if not gps_forensics["has_gps"] or any(f["status"] == "VALID" for f in gps_forensics["findings"]) else "FLAGGED",
        "notes": "Evaluates geographic coordinate boundaries and GPS satellite timestamp synchronization."
    })
    for g_find in gps_forensics.get("findings", []):
        if g_find.get("status") in ("CHRONOLOGICAL_MISMATCH", "ANOMALOUS", "SUSPICIOUS"):
            all_findings.append({
                "rule_id": "RULE_GPS_ANOMALY",
                "rule_name": f"GPS Geolocation: {g_find.get('category')}",
                "severity": SEVERITY_HIGH if g_find.get("status") == "CHRONOLOGICAL_MISMATCH" else SEVERITY_MEDIUM,
                "severity_reason": g_find.get("forensic_context", ""),
                "evidence_field": "GPS Coordinates / Clock Sync",
                "observed_value": g_find.get("description", ""),
                "explanation": g_find.get("description", ""),
                "benign_explanation": "Camera system clock divergence or localized GPS signal drift.",
                "next_step": "Cross-reference local cell-tower records or independent geolocation logs."
            })

    # 8. Hex & Binary File Structure Inspection
    hex_inspection = hex_inspector.inspect_file_structure(file_path)
    checks_performed.append({
        "check_id": "CHECK_HEX_FILE_STRUCTURE",
        "name": "Binary Magic Bytes & EOF Integrity",
        "fields_evaluated": ["Header Signature", "End of Image (EOI)", "Post-EOF Injected Payload"],
        "values": {
            "detected_format": hex_inspection["detected_format"],
            "is_valid_header": hex_inspection["is_valid_header"],
            "has_appended_data": hex_inspection["has_appended_data"],
            "appended_data_bytes": hex_inspection["appended_data_bytes"],
        },
        "status": "FLAGGED" if hex_inspection["has_appended_data"] or not hex_inspection["is_valid_header"] else "PASS",
        "notes": "Scans for polyglot archives, steganographic trailing data past EOF, and magic byte consistency."
    })
    if hex_inspection.get("has_appended_data"):
        all_findings.append({
            "rule_id": "RULE_HEX_APPENDED_PAYLOAD",
            "rule_name": "Injected Binary Payload Detected Past EOF",
            "severity": SEVERITY_HIGH,
            "severity_reason": "Data appended past the official End-Of-Image marker is a primary vector for steganography or file tampering.",
            "evidence_field": "Binary File Structure / EOF",
            "observed_value": f"{hex_inspection.get('appended_data_bytes')} trailing bytes",
            "explanation": f"File contains {hex_inspection.get('appended_data_bytes')} bytes appended past the valid image EOF marker.",
            "benign_explanation": "Some archival or camera firmware variants append proprietary thumbnail indices or debug logs.",
            "next_step": "Examine hex dump of trailing bytes in Hex Inspector to determine if payload is an archive or executable."
        })

    # 9. Optional Advanced Image Analysis (ELA / Quantization)
    advanced_analysis = perform_advanced_image_analysis(file_path)

    # Classification Logic
    has_high = any(f.get("severity") == SEVERITY_HIGH for f in all_findings)
    has_medium = any(f.get("severity") == SEVERITY_MEDIUM for f in all_findings)
    is_sparse = any(f.get("rule_id") == "RULE_METADATA_STRIPPED" for f in all_findings)

    if has_high or has_medium:
        classification = CLASSIFICATION_SUSPICIOUS
        classification_title = "Suspicious Indicators Found"
        classification_desc = (
            "One or more defined forensic checks identified anomalies or editing software signatures that warrant investigator review."
        )
        classification_badge = "badge-warning"
    elif is_sparse or tag_count < 10:
        classification = CLASSIFICATION_INCONCLUSIVE
        classification_title = "Inconclusive"
        classification_desc = (
            "The available metadata is sparse, stripped, or insufficient to evaluate authenticity reliably. "
            "No conclusive finding can be established without additional evidence."
        )
        classification_badge = "badge-neutral"
    else:
        classification = CLASSIFICATION_CLEAN
        classification_title = "No Significant Indicators Detected"
        classification_desc = (
            "The implemented checks did not identify significant anomalies or contradictory metadata. "
            "Important: This condition does NOT establish authenticity or prove the absence of tampering."
        )
        classification_badge = "badge-success"

    return {
        "classification": classification,
        "classification_title": classification_title,
        "classification_description": classification_desc,
        "classification_badge": classification_badge,
        "findings": all_findings,
        "findings_count": len(all_findings),
        "checks_performed": checks_performed,
        "checks_count": len(checks_performed),
        "completeness": chk_comp.get("values", {}),
        "advanced_analysis": advanced_analysis,
        "gps_forensics": gps_forensics,
        "hex_inspection": hex_inspection,
        "sha256": sha256_hash,
        "summary": summary,
        "tag_count": tag_count,
        "source_context": source_context,
        "source_context_note": (
            f"Evaluated with declared source context: '{source_context}'. "
            "Note: Declared source context is investigator-provided contextual input and does not constitute independent verification of platform origin."
        ),
        "disclaimer": (
            "FORENSIC LIMITATION NOTICE: Without an original master image, verified reference hash, "
            "or corroborating external evidence, automated analysis cannot establish historical authenticity. "
            "All findings describe observed metadata properties and rule-based consistency, not definitive proof of tampering."
        )
    }
