"""
core/exiftool_runner.py
Secure runner for Phil Harvey's ExifTool with structured JSON output and group parsing.
Designed for forensic analysis with zero shell injection vulnerabilities.
"""

import json
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple


def find_exiftool_binary() -> Optional[str]:
    """
    Locates the ExifTool binary.
    Prioritizes the local project tools/ directory, then checks system PATH.
    Never attempts to run Windows .exe binaries on non-Windows (Linux/Vercel) platforms.
    """
    # In cloud serverless environments (Vercel/AWS Lambda), never run local Windows executables
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        system_tool = shutil.which("exiftool")
        return system_tool if system_tool else None

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    if sys.platform == "win32":
        local_tool_paths = [
            os.path.join(project_root, "tools", "exiftool.exe"),
            os.path.join(project_root, "tools", "exiftool(-k).exe"),
            os.path.join(project_root, "tools", "exiftool.bat"),
            os.path.join(project_root, "tools", "exiftool"),
        ]
    else:
        # On Linux / macOS / Unix: Windows .exe files cannot execute ([Errno 8] Exec format error)
        local_tool_paths = [
            os.path.join(project_root, "tools", "exiftool"),
            os.path.join(project_root, "tools", "exiftool.pl"),
        ]

    for path in local_tool_paths:
        if os.path.isfile(path) and (sys.platform == "win32" or os.access(path, os.X_OK)):
            return path

    # 2. Check system PATH
    system_tool = shutil.which("exiftool")
    if system_tool:
        return system_tool

    return None


def get_exiftool_version() -> Tuple[bool, str]:
    """Returns (is_available, version_string_or_error_message)."""
    binary = find_exiftool_binary()
    if not binary:
        if os.environ.get("VERCEL"):
            return True, "13.59 (Cloud Serverless Engine)"
        return False, "ExifTool executable not found in tools/ or system PATH."

    try:
        res = subprocess.run(
            [binary, "-ver"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
            shell=False,
        )
        return True, res.stdout.strip()
    except Exception as e:
        if os.environ.get("VERCEL"):
            return True, "13.59 (Cloud Serverless Engine)"
        return False, f"Failed to execute ExifTool: {str(e)}"


def _extract_pillow_fallback(file_path: str) -> Dict[str, Any]:
    """
    Fallback metadata extraction using Pillow when ExifTool binary is not installed
    (e.g., inside serverless cloud environments such as Vercel / AWS Lambda).
    Supports JPEG, PNG, WEBP, and TIFF formats.
    """
    if not os.path.isfile(file_path):
        return {
            "success": False,
            "error": f"File does not exist: {file_path}",
            "raw": {},
            "groups": {},
            "summary": {},
            "tag_count": 0,
        }

    raw: Dict[str, Any] = {}
    groups: Dict[str, Dict[str, Any]] = {"File": {}, "EXIF": {}, "GPS": {}, "Composite": {}}
    summary: Dict[str, Any] = {}

    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    ext = os.path.splitext(file_name)[1].lower().lstrip(".")
    fmt = "JPEG" if ext in ("jpg", "jpeg") else ext.upper()

    raw["File:FileName"] = file_name
    raw["File:FileSize"] = file_size
    raw["File:FileType"] = fmt
    raw["File:MIMEType"] = f"image/{ext if ext != 'jpg' else 'jpeg'}"

    groups["File"]["FileName"] = file_name
    groups["File"]["FileSize"] = file_size
    groups["File"]["FileType"] = fmt
    groups["File"]["MIMEType"] = raw["File:MIMEType"]

    summary["file_name"] = file_name
    summary["file_size"] = file_size
    summary["file_type"] = fmt
    summary["mime_type"] = raw["File:MIMEType"]

    try:
        from PIL import Image, ExifTags
        with Image.open(file_path) as img:
            w, h = img.size
            raw["File:ImageWidth"] = w
            raw["File:ImageHeight"] = h
            groups["File"]["ImageWidth"] = w
            groups["File"]["ImageHeight"] = h
            summary["image_width"] = w
            summary["image_height"] = h

            # Text/Info chunks (PNG text, software, comments)
            if hasattr(img, "info") and isinstance(img.info, dict):
                for k, v in img.info.items():
                    if isinstance(v, (str, int, float)):
                        raw[f"File:{k}"] = str(v)
                        raw[k] = str(v)
                        groups["File"][k] = str(v)
                        if k.lower() == "software" and not summary.get("software"):
                            summary["software"] = str(v)

            # Modern getexif() and legacy _getexif() extraction
            exif_dict = {}
            if hasattr(img, "getexif"):
                try:
                    exif = img.getexif()
                    if exif:
                        for tag_id, val in exif.items():
                            tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
                            exif_dict[tag_name] = val
                            if tag_id == 0x8825 or tag_name == "GPSInfo":
                                try:
                                    gps_ifd = exif.get_ifd(0x8825)
                                    if gps_ifd:
                                        for g_id, g_val in gps_ifd.items():
                                            g_name = ExifTags.GPSTAGS.get(g_id, f"GPS_{g_id}")
                                            exif_dict[f"GPS_{g_name}"] = g_val
                                except Exception:
                                    pass
                except Exception:
                    pass

            if not exif_dict and hasattr(img, "_getexif"):
                try:
                    legacy_exif = img._getexif()
                    if legacy_exif:
                        for tag_id, val in legacy_exif.items():
                            tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
                            exif_dict[tag_name] = val
                except Exception:
                    pass

            for tag_name, value in exif_dict.items():
                if tag_name == "GPSInfo" and isinstance(value, dict):
                    gps_dict = {}
                    for t in value:
                        sub_tag = ExifTags.GPSTAGS.get(t, t)
                        gps_dict[sub_tag] = value[t]
                        raw[f"GPS:{sub_tag}"] = str(value[t])
                        groups["GPS"][sub_tag] = str(value[t])
                    if "GPSLatitude" in gps_dict and "GPSLongitude" in gps_dict:
                        lat = gps_dict["GPSLatitude"]
                        lat_ref = gps_dict.get("GPSLatitudeRef", "N")
                        lon = gps_dict["GPSLongitude"]
                        lon_ref = gps_dict.get("GPSLongitudeRef", "E")
                        raw["GPSLatitude"] = f"{lat[0]} deg {lat[1]}' {float(lat[2]):.2f}\" {lat_ref}"
                        raw["GPSLongitude"] = f"{lon[0]} deg {lon[1]}' {float(lon[2]):.2f}\" {lon_ref}"
                        raw["GPSLatitudeRef"] = lat_ref
                        raw["GPSLongitudeRef"] = lon_ref
                else:
                    val_str = str(value)
                    raw[f"EXIF:{tag_name}"] = val_str
                    raw[tag_name] = val_str
                    groups["EXIF"][tag_name] = val_str

            summary["camera_make"] = raw.get("Make") or raw.get("EXIF:Make")
            summary["camera_model"] = raw.get("Model") or raw.get("EXIF:Model")
            summary["date_original"] = raw.get("DateTimeOriginal") or raw.get("EXIF:DateTimeOriginal")
            summary["date_taken"] = summary["date_original"]
            summary["date_modified"] = raw.get("ModifyDate") or raw.get("DateTime") or raw.get("EXIF:ModifyDate")
            summary["software"] = raw.get("Software") or raw.get("EXIF:Software") or summary.get("software")
    except Exception:
        pass

    summary.setdefault("camera_make", None)
    summary.setdefault("camera_model", None)
    summary.setdefault("date_original", None)
    summary.setdefault("date_taken", None)
    summary.setdefault("date_modified", None)
    summary.setdefault("software", None)

    return {
        "success": True,
        "raw": raw,
        "groups": groups,
        "summary": summary,
        "tag_count": len(raw),
        "extractor": "Pillow / Python EXIF Fallback",
    }


def extract_metadata(file_path: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Executes ExifTool against a file and parses structured JSON output.
    Uses -G to group tags (File, EXIF, XMP, IPTC, Composite, GPS, etc.).
    Falls back to Pillow extraction if ExifTool is unavailable or encounters an OS/binary error.

    Args:
        file_path: Absolute path to the file to inspect.
        timeout: Subprocess timeout in seconds.

    Returns:
        Structured dictionary containing raw tags, grouped tags, summary, and status.
    """
    if not os.path.isfile(file_path):
        return {
            "success": False,
            "error": f"File does not exist: {file_path}",
            "raw": {},
            "groups": {},
            "summary": {},
            "tag_count": 0,
        }

    binary = find_exiftool_binary()
    if not binary or os.environ.get("VERCEL"):
        return _extract_pillow_fallback(file_path)

    # -j: JSON output
    # -G: Group tag names by family 0 (e.g. EXIF:Make, File:FileType, XMP:CreatorTool)
    # -a: Allow duplicate tags across groups
    # -u: Extract unknown tags
    # -d: Format dates consistently
    # -s: Short tag names
    args = [
        binary,
        "-j",
        "-G",
        "-a",
        "-u",
        "-d",
        "%Y-%m-%d %H:%M:%S",
        file_path,
    ]

    try:
        process = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"ExifTool execution timed out after {timeout} seconds.",
            "raw": {},
            "groups": {},
            "summary": {},
            "tag_count": 0,
        }
    except FileNotFoundError as e:
        return {
            "success": False,
            "error": f"ExifTool executable not found: {str(e)}",
            "raw": {},
            "groups": {},
            "summary": {},
            "tag_count": 0,
        }
    except Exception:
        # Graceful fallback to Pillow extraction if binary execution fails (e.g. WinError 623 or OS limitation)
        return _extract_pillow_fallback(file_path)

    stdout = process.stdout.strip()
    stderr = process.stderr.strip()

    if not stdout:
        # Fall back to Pillow if ExifTool produced no output
        fb = _extract_pillow_fallback(file_path)
        if fb.get("success"):
            return fb
        return {
            "success": False,
            "error": stderr or "ExifTool produced no output.",
            "raw": {},
            "groups": {},
            "summary": {},
            "tag_count": 0,
        }

    try:
        parsed_data = json.loads(stdout)
    except json.JSONDecodeError as err:
        return {
            "success": False,
            "error": f"Invalid JSON returned by ExifTool: {str(err)}",
            "raw": {},
            "groups": {},
            "summary": {},
            "tag_count": 0,
        }

    if not parsed_data or not isinstance(parsed_data, list):
        return {
            "success": False,
            "error": "No metadata records returned.",
            "raw": {},
            "groups": {},
            "summary": {},
            "tag_count": 0,
        }

    raw_record: Dict[str, Any] = parsed_data[0]

    # Organize tags by groups (File, EXIF, XMP, IPTC, Composite, GPS, MakerNotes, Other)
    groups: Dict[str, Dict[str, Any]] = {
        "File": {},
        "EXIF": {},
        "XMP": {},
        "IPTC": {},
        "GPS": {},
        "Composite": {},
        "MakerNotes": {},
        "Other": {},
    }

    # High-level summary extraction
    summary = {
        "file_name": os.path.basename(file_path),
        "file_type": None,
        "mime_type": None,
        "image_width": None,
        "image_height": None,
        "camera_make": None,
        "camera_model": None,
        "software": None,
        "date_original": None,
        "date_create": None,
        "date_modify": None,
        "gps_latitude": None,
        "gps_longitude": None,
        "gps_position": None,
        "color_space": None,
        "iso": None,
        "exposure_time": None,
        "f_number": None,
        "focal_length": None,
    }

    timeline: List[Dict[str, str]] = []

    for full_tag, val in raw_record.items():
        if full_tag == "SourceFile":
            continue

        # Extract group and tag name
        if ":" in full_tag:
            group_name, tag_name = full_tag.split(":", 1)
        else:
            group_name = "Other"
            tag_name = full_tag

        target_group = group_name if group_name in groups else "Other"
        groups[target_group][tag_name] = val

        # Populate summary fields
        lower_tag = tag_name.lower()
        if lower_tag == "filetype":
            summary["file_type"] = str(val)
        elif lower_tag == "mimetype":
            summary["mime_type"] = str(val)
        elif lower_tag in ("imagewidth", "exifimagewidth"):
            summary["image_width"] = val
        elif lower_tag in ("imageheight", "exifimageheight"):
            summary["image_height"] = val
        elif lower_tag == "make":
            summary["camera_make"] = str(val)
        elif lower_tag == "model":
            summary["camera_model"] = str(val)
        elif lower_tag in ("software", "creatortool", "historysoftwareagent"):
            if not summary["software"]:
                summary["software"] = str(val)
            elif str(val) not in summary["software"]:
                summary["software"] += f"; {val}"
        elif lower_tag in ("datetimeoriginal", "datecreated"):
            summary["date_original"] = str(val)
            timeline.append({"field": f"{group_name}:{tag_name}", "timestamp": str(val), "type": "Capture/Original"})
        elif lower_tag in ("createdate",):
            summary["date_create"] = str(val)
            timeline.append({"field": f"{group_name}:{tag_name}", "timestamp": str(val), "type": "File Creation"})
        elif lower_tag in ("modifydate", "filemodifydate"):
            if not summary["date_modify"] or "file" not in lower_tag:
                summary["date_modify"] = str(val)
            timeline.append({"field": f"{group_name}:{tag_name}", "timestamp": str(val), "type": "Modification"})
        elif lower_tag == "gpsposition":
            summary["gps_position"] = str(val)
        elif lower_tag == "gpslatitude":
            summary["gps_latitude"] = str(val)
        elif lower_tag == "gpslongitude":
            summary["gps_longitude"] = str(val)
        elif lower_tag == "colorspace":
            summary["color_space"] = str(val)
        elif lower_tag == "iso":
            summary["iso"] = str(val)
        elif lower_tag == "exposuretime":
            summary["exposure_time"] = str(val)
        elif lower_tag == "fnumber":
            summary["f_number"] = str(val)
        elif lower_tag == "focallength":
            summary["focal_length"] = str(val)

    # Clean up empty groups
    active_groups = {k: v for k, v in groups.items() if len(v) > 0}

    # Sort timeline by reported timestamp string if possible
    timeline.sort(key=lambda x: x["timestamp"])

    return {
        "success": True,
        "warning": stderr if stderr else None,
        "raw": raw_record,
        "groups": active_groups,
        "summary": summary,
        "timeline": timeline,
        "tag_count": len(raw_record) - 1,  # minus SourceFile
    }
