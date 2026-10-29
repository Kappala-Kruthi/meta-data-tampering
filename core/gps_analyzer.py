"""
TRACE Digital Forensics Workbench - GPS Forensics & Geolocation Module.
Parses ExifTool GPS metadata tags into decimal degrees, validates coordinate
boundaries, cross-references GPS timestamps with camera capture clocks,
and constructs embeddable map references.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Optional, Tuple


def _parse_dms_coordinate(coord_val: Any, ref: Optional[str] = None) -> Optional[float]:
    """
    Parses coordinate representation into signed decimal degrees.
    Handles numeric decimal degrees or DMS strings like '18 deg 48' 19.80\" N'.
    """
    if coord_val is None:
        return None

    if isinstance(coord_val, (int, float)):
        val = float(coord_val)
        if ref and ref.upper() in ("S", "W") and val > 0:
            val = -val
        return val

    s = str(coord_val).strip()
    try:
        val = float(s)
        if ref and ref.upper() in ("S", "W") and val > 0:
            val = -val
        return val
    except ValueError:
        pass

    pattern = r"(\d+(?:\.\d+)?)\s*(?:deg|°|:)?\s*(\d+(?:\.\d+)?)\s*(?:'|m|:)?\s*(\d+(?:\.\d+)?)\s*(?:\"|s)?"
    match = re.search(pattern, s, re.IGNORECASE)
    if match:
        deg = float(match.group(1))
        minute = float(match.group(2))
        sec = float(match.group(3))
        decimal = deg + (minute / 60.0) + (sec / 3600.0)

        ref_match = re.search(r"\b([NSEW])\b", s, re.IGNORECASE)
        resolved_ref = (ref_match.group(1) if ref_match else (ref or "")).upper()
        if resolved_ref in ("S", "W"):
            decimal = -decimal
        return decimal

    return None


def extract_gps_forensics(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes metadata dictionary for GPS coordinates, altitude, timestamp,
    and calculates forensic consistency indicators.
    """
    raw_lat = metadata.get("GPSLatitude")
    raw_lat_ref = metadata.get("GPSLatitudeRef")
    raw_lon = metadata.get("GPSLongitude")
    raw_lon_ref = metadata.get("GPSLongitudeRef")
    raw_alt = metadata.get("GPSAltitude")
    raw_alt_ref = metadata.get("GPSAltitudeRef")
    raw_gps_time = metadata.get("GPSTimeStamp")
    raw_gps_date = metadata.get("GPSDateStamp")
    raw_position = metadata.get("GPSPosition")

    lat = _parse_dms_coordinate(raw_lat, raw_lat_ref)
    lon = _parse_dms_coordinate(raw_lon, raw_lon_ref)

    has_gps = lat is not None and lon is not None

    result: Dict[str, Any] = {
        "has_gps": has_gps,
        "latitude": lat,
        "longitude": lon,
        "raw_latitude": raw_lat,
        "raw_longitude": raw_lon,
        "raw_position": raw_position,
        "altitude": str(raw_alt) if raw_alt is not None else None,
        "altitude_ref": str(raw_alt_ref) if raw_alt_ref is not None else None,
        "gps_time": str(raw_gps_time) if raw_gps_time is not None else None,
        "gps_date": str(raw_gps_date) if raw_gps_date is not None else None,
        "formatted_coordinates": None,
        "osm_embed_url": None,
        "osm_external_url": None,
        "google_maps_url": None,
        "timestamp_consistency": None,
        "findings": [],
    }

    if not has_gps:
        result["findings"].append({
            "category": "GPS Geolocation",
            "status": "NOT_PRESENT",
            "description": "No embedded GPS geolocation tags detected in file metadata.",
            "forensic_context": (
                "Absence of GPS tags is standard when location services are disabled, "
                "for standalone cameras without GNSS hardware, or when media is processed "
                "through privacy-stripping social media or messaging platforms."
            ),
        })
        return result

    lat_cardinal = "N" if lat >= 0 else "S"
    lon_cardinal = "E" if lon >= 0 else "W"
    result["formatted_coordinates"] = (
        f"{abs(lat):.6f}° {lat_cardinal}, {abs(lon):.6f}° {lon_cardinal}"
    )

    if not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
        result["findings"].append({
            "category": "GPS Validity",
            "status": "ANOMALOUS",
            "description": f"GPS coordinates ({lat}, {lon}) exceed physical Earth boundaries.",
            "forensic_context": "Coordinates outside [-90, 90] lat or [-180, 180] lon indicate corrupted metadata or synthetic injection.",
        })
    elif abs(lat) < 0.0001 and abs(lon) < 0.0001:
        result["findings"].append({
            "category": "GPS Null Island",
            "status": "SUSPICIOUS",
            "description": "GPS coordinates resolve to (0.0, 0.0) (Null Island off Gulf of Guinea).",
            "forensic_context": "Resolving to exactly (0,0) frequently indicates uninitialized GPS sensors or dummy test values.",
        })
    else:
        result["findings"].append({
            "category": "GPS Geolocation",
            "status": "VALID",
            "description": f"Valid geographic coordinates located at {result['formatted_coordinates']}.",
            "forensic_context": "GNSS location coordinates verified within standard terrestrial bounding limits.",
        })

    delta = 0.008
    bbox = f"{lon - delta:.6f}%2C{lat - delta:.6f}%2C{lon + delta:.6f}%2C{lat + delta:.6f}"
    result["osm_embed_url"] = (
        f"https://www.openstreetmap.org/export/embed.html?bbox={bbox}&layer=mapnik&marker={lat:.6f}%2C{lon:.6f}"
    )
    result["osm_external_url"] = (
        f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}"
    )
    result["google_maps_url"] = (
        f"https://www.google.com/maps/search/?api=1&query={lat:.6f},{lon:.6f}"
    )

    cam_dt_str = (
        metadata.get("DateTimeOriginal")
        or metadata.get("CreateDate")
        or metadata.get("ModifyDate")
    )

    if raw_gps_time and raw_gps_date and cam_dt_str:
        try:
            gps_dt_raw = f"{raw_gps_date} {raw_gps_time}".replace("Z", "").strip()
            gps_dt_clean = re.sub(r"(\d{4})[:\-](\d{2})[:\-](\d{2})", r"\1-\2-\3", gps_dt_raw)
            gps_dt_clean = gps_dt_clean.split(".")[0]
            gps_dt = datetime.strptime(gps_dt_clean, "%Y-%m-%d %H:%M:%S")

            cam_clean = re.sub(r"(\d{4})[:\-](\d{2})[:\-](\d{2})", r"\1-\2-\3", str(cam_dt_str).strip())
            cam_clean = cam_clean.split(".")[0]
            cam_dt = datetime.strptime(cam_clean, "%Y-%m-%d %H:%M:%S")

            diff_sec = abs((cam_dt - gps_dt).total_seconds())
            hours_diff = diff_sec / 3600.0

            result["timestamp_consistency"] = {
                "gps_datetime_utc": gps_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "camera_datetime": cam_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "absolute_difference_hours": round(hours_diff, 2),
            }

            if diff_sec > 86400 * 2:
                result["findings"].append({
                    "category": "Clock Synchronization",
                    "status": "CHRONOLOGICAL_MISMATCH",
                    "description": (
                        f"Discrepancy of {round(hours_diff / 24.0, 1)} days detected between GPS satellite time "
                        f"({gps_dt.strftime('%Y-%m-%d %H:%M:%S')}) and camera capture time ({cam_dt.strftime('%Y-%m-%d %H:%M:%S')})."
                    ),
                    "forensic_context": (
                        "Satellite GPS time is derived directly from atomic GNSS clocks. A major divergence indicates "
                        "either an incorrect camera system clock or retrospective coordinate injection / tampering."
                    ),
                })
            else:
                result["findings"].append({
                    "category": "Clock Synchronization",
                    "status": "CONSISTENT",
                    "description": (
                        f"GPS satellite clock ({gps_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC) and camera time "
                        f"({cam_dt.strftime('%Y-%m-%d %H:%M:%S')}) are chronologically aligned (within standard timezone offset)."
                    ),
                    "forensic_context": "Acceptable delta consistent with local timezone variations.",
                })
        except Exception:
            pass

    return result
