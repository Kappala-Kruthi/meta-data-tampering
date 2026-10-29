"""
TRACE Digital Forensics Workbench - Metadata Sanitizer & Privacy Redactor.
Empowers investigators and users to safely sanitize or selectively scrub
sensitive EXIF, GNSS/GPS geolocation, serial numbers, and private device
fingerprints before publication, demonstrating forensic before-and-after differentials.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from core import exiftool_runner, hasher


def sanitize_media_file(
    input_path: str,
    output_dir: str,
    scrub_mode: str = "ALL",  # 'ALL' or 'GPS_ONLY'
) -> Dict[str, Any]:
    """
    Sanitizes media file by scrubbing metadata, and generates a differential audit log.
    Modes:
      - 'ALL': Strips all EXIF, GPS, IPTC, XMP, device serials, and thumbnail data.
      - 'GPS_ONLY': Strips only GNSS coordinates and location tags while preserving camera settings.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.basename(input_path)
    file_stem, ext = os.path.splitext(base_name)
    suffix = "_clean" if scrub_mode == "ALL" else "_nogps"
    output_filename = f"{file_stem}{suffix}{ext}"
    output_path = os.path.join(output_dir, output_filename)

    # 1. Compute original file metrics and metadata
    original_size = os.path.getsize(input_path)
    original_hash = hasher.calculate_sha256(input_path)
    original_meta = exiftool_runner.extract_metadata(input_path)

    # 2. Copy file to output destination
    shutil.copy2(input_path, output_path)

    # 3. Execute ExifTool redaction
    exiftool_bin = exiftool_runner.find_exiftool_binary()
    if scrub_mode == "GPS_ONLY":
        cmd = [
            exiftool_bin,
            "-gps:all=",
            "-overwrite_original",
            output_path,
        ]
    else:  # ALL
        cmd = [
            exiftool_bin,
            "-all=",
            "-tagsFromFile",
            "@",
            "-ColorSpaceTags",
            "-overwrite_original",
            output_path,
        ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"ExifTool sanitization failed: {proc.stderr}")
    except Exception as e:
        if os.path.exists(output_path):
            os.remove(output_path)
        raise RuntimeError(f"Error executing metadata sanitization: {str(e)}")

    # 4. Compute sanitized file metrics and metadata
    sanitized_size = os.path.getsize(output_path)
    sanitized_hash = hasher.calculate_sha256(output_path)
    sanitized_meta = exiftool_runner.extract_metadata(output_path)

    # 5. Calculate removed tags
    removed_tags = []
    ignored_dynamic_tags = {"SourceFile", "Directory", "FileAccessDate", "FileModifyDate", "FilePermissions"}

    for key, val in original_meta.items():
        if key not in ignored_dynamic_tags and key not in sanitized_meta:
            removed_tags.append({
                "tag": key,
                "original_value": str(val)[:120],
                "category": (
                    "GPS Geolocation" if key.startswith("GPS")
                    else "Camera Hardware" if key in ("Make", "Model", "LensModel", "SerialNumber")
                    else "Timestamps" if "Date" in key or "Time" in key
                    else "General EXIF"
                ),
            })

    # Sort removed tags alphabetically
    removed_tags.sort(key=lambda x: (x["category"], x["tag"]))

    bytes_saved = max(0, original_size - sanitized_size)
    percent_reduction = round((bytes_saved / original_size * 100), 2) if original_size > 0 else 0.0

    return {
        "success": True,
        "scrub_mode": scrub_mode,
        "original_filename": base_name,
        "sanitized_filename": output_filename,
        "sanitized_rel_path": os.path.relpath(output_path, output_dir),
        "sanitized_full_path": output_path,
        "original_size": original_size,
        "sanitized_size": sanitized_size,
        "bytes_reduced": bytes_saved,
        "percent_reduced": percent_reduction,
        "original_sha256": original_hash,
        "sanitized_sha256": sanitized_hash,
        "original_tag_count": len(original_meta),
        "sanitized_tag_count": len(sanitized_meta),
        "removed_tags": removed_tags,
        "removed_count": len(removed_tags),
    }
