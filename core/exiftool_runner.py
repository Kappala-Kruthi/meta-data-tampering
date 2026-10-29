"""
core/exiftool_runner.py
Secure runner for Phil Harvey's ExifTool with structured JSON output and group parsing.
Designed for forensic analysis with zero shell injection vulnerabilities.
"""

import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple


def find_exiftool_binary() -> Optional[str]:
    """
    Locates the ExifTool binary.
    Prioritizes the local project tools/ directory, then checks system PATH.
    """
    # 1. Check local project tools folder
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    local_tool_paths = [
        os.path.join(project_root, "tools", "exiftool.exe"),
        os.path.join(project_root, "tools", "exiftool"),
        os.path.join(project_root, "tools", "exiftool(-k).exe"),
    ]
    for path in local_tool_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
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
        return False, f"Failed to execute ExifTool: {str(e)}"


def extract_metadata(file_path: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Executes ExifTool against a file and parses structured JSON output.
    Uses -G to group tags (File, EXIF, XMP, IPTC, Composite, GPS, etc.).

    Args:
        file_path: Absolute path to the file to inspect.
        timeout: Subprocess timeout in seconds.

    Returns:
        Structured dictionary containing raw tags, grouped tags, summary, and status.
    """
    binary = find_exiftool_binary()
    if not binary:
        return {
            "success": False,
            "error": "ExifTool executable not found.",
            "raw": {},
            "groups": {},
            "summary": {},
            "tag_count": 0,
        }

    if not os.path.isfile(file_path):
        return {
            "success": False,
            "error": f"File does not exist: {file_path}",
            "raw": {},
            "groups": {},
            "summary": {},
            "tag_count": 0,
        }

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
    except Exception as e:
        return {
            "success": False,
            "error": f"Execution failed: {str(e)}",
            "raw": {},
            "groups": {},
            "summary": {},
            "tag_count": 0,
        }

    stdout = process.stdout.strip()
    stderr = process.stderr.strip()

    if not stdout:
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
