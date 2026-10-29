"""
TRACE Digital Forensics Workbench - Hex & Low-Level File Structure Inspector.
Performs magic byte signature verification, metadata segment / marker mapping,
appended steganography payload detection (post-EOF data injection), and
generates forensic hex dump representations.
"""

from __future__ import annotations

import os
import struct
from typing import Any, Dict, List, Optional, Tuple


MAGIC_SIGNATURES: Dict[str, Tuple[bytes, ...]] = {
    "JPEG": (b"\xFF\xD8\xFF",),
    "PNG": (b"\x89PNG\r\n\x1a\n",),
    "GIF": (b"GIF87a", b"GIF89a"),
    "TIFF_LE": (b"\x49\x49\x2A\x00",),
    "TIFF_BE": (b"\x4D\x4D\x00\x2A",),
    "WEBP": (b"RIFF",),  # RIFF....WEBP
    "BMP": (b"BM",),
    "PDF": (b"%PDF-",),
    "ZIP": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
}


def _format_hex_lines(data: bytes, base_offset: int = 0) -> List[Dict[str, str]]:
    """
    Formats byte buffer into standard 16-byte hex dump rows with ASCII representation.
    """
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        # Pad to fixed column width
        if len(chunk) < 16:
            hex_bytes = hex_bytes.ljust(47)

        ascii_repr = "".join((chr(b) if 32 <= b <= 126 else ".") for b in chunk)
        lines.append({
            "offset": f"{base_offset + i:08X}",
            "hex": hex_bytes,
            "ascii": ascii_repr,
        })
    return lines


def _analyze_jpeg_segments(data: bytes) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    """
    Parses JPEG markers to identify EXIF/XMP/Photoshop segments and the End of Image (EOI) offset.
    Returns (segments_list, eoi_offset).
    """
    segments = []
    eoi_offset = None
    idx = 2  # skip SOI (FF D8)
    data_len = len(data)

    marker_names = {
        0xE0: "APP0 (JFIF / Standard)",
        0xE1: "APP1 (EXIF / XMP / Extended Metadata)",
        0xE2: "APP2 (ICC Profile / FlashPix)",
        0xED: "APP13 (Photoshop IRB / IPTC)",
        0xEE: "APP14 (Adobe)",
        0xDB: "DQT (Quantization Table)",
        0xC0: "SOF0 (Baseline DCT Frame Header)",
        0xC2: "SOF2 (Progressive DCT Frame Header)",
        0xC4: "DHT (Huffman Table)",
        0xDA: "SOS (Start of Scan - Compressed Stream)",
        0xD9: "EOI (End of Image)",
        0xFE: "COM (Comment)",
    }

    # Record SOI
    segments.append({
        "offset": 0,
        "offset_hex": "0x00000000",
        "marker": "FF D8",
        "name": "SOI (Start of Image)",
        "length": 2,
    })

    while idx < data_len - 1:
        if data[idx] == 0xFF:
            marker = data[idx + 1]
            if marker in (0x00, 0xFF):  # byte stuffing or padding
                idx += 1
                continue

            marker_hex = f"FF {marker:02X}"
            marker_name = marker_names.get(marker, f"Marker 0x{marker:02X}")

            if marker == 0xD9:  # EOI
                eoi_offset = idx + 2
                segments.append({
                    "offset": idx,
                    "offset_hex": f"0x{idx:08X}",
                    "marker": marker_hex,
                    "name": marker_name,
                    "length": 2,
                })
                break
            elif marker == 0xDA:  # SOS
                # Marker has header length, followed by entropy-coded data
                if idx + 4 <= data_len:
                    seg_len = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
                    segments.append({
                        "offset": idx,
                        "offset_hex": f"0x{idx:08X}",
                        "marker": marker_hex,
                        "name": marker_name,
                        "length": seg_len + 2,
                    })
                    idx += 2 + seg_len
                    # Entropy scan until next 0xFF (not 0x00)
                    while idx < data_len - 1:
                        if data[idx] == 0xFF and data[idx + 1] not in (0x00, 0xFF):
                            break
                        idx += 1
                    continue
                else:
                    break
            elif marker in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0x01):  # Standalone markers without length
                segments.append({
                    "offset": idx,
                    "offset_hex": f"0x{idx:08X}",
                    "marker": marker_hex,
                    "name": marker_name,
                    "length": 2,
                })
                idx += 2
            else:
                # Segment with 2-byte length field
                if idx + 4 <= data_len:
                    seg_len = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
                    segments.append({
                        "offset": idx,
                        "offset_hex": f"0x{idx:08X}",
                        "marker": marker_hex,
                        "name": marker_name,
                        "length": seg_len + 2,
                    })
                    idx += 2 + seg_len
                else:
                    break
        else:
            idx += 1

    return segments, eoi_offset


def inspect_file_structure(file_path: str) -> Dict[str, Any]:
    """
    Performs deep binary analysis on file header, footer, segments,
    and detects steganographic appended bytes past EOF.
    """
    if not file_path or not os.path.exists(file_path):
        ext = os.path.splitext(file_path)[1].lower().lstrip(".") if file_path else ""
        return {
            "file_size": 0,
            "detected_format": "N/A",
            "is_valid_header": True,
            "extension": ext,
            "extension_match": True,
            "segments": [],
            "has_appended_data": False,
            "appended_data_bytes": 0,
            "appended_sample_hex": None,
            "findings": [],
            "header_hex_dump": [],
            "trailer_hex_dump": [],
        }

    file_size = os.path.getsize(file_path)

    # Read binary contents
    with open(file_path, "rb") as f:
        head_sample = f.read(512)
        f.seek(max(0, file_size - 512))
        tail_sample = f.read(512)

    # Detect Magic Signature
    detected_format = "Unknown / Non-Standard"
    is_valid_header = False

    for fmt, sigs in MAGIC_SIGNATURES.items():
        for sig in sigs:
            if head_sample.startswith(sig):
                if fmt == "WEBP" and len(head_sample) >= 12 and head_sample[8:12] != b"WEBP":
                    continue
                detected_format = fmt
                is_valid_header = True
                break
        if is_valid_header:
            break

    # Extension consistency check
    ext = os.path.splitext(file_path)[1].lower().lstrip(".")
    ext_norm = "JPEG" if ext in ("jpg", "jpeg", "jpe") else ext.upper()
    extension_match = (ext_norm == detected_format) or (ext_norm == "JPG" and detected_format == "JPEG")

    findings = []
    if not is_valid_header:
        findings.append({
            "category": "File Header",
            "status": "ANOMALOUS",
            "title": "Unrecognized Magic Bytes",
            "description": f"Initial bytes '{head_sample[:8].hex().upper()}' do not match standard image signatures.",
            "severity": "HIGH",
        })
    elif not extension_match and detected_format != "Unknown / Non-Standard":
        findings.append({
            "category": "Extension Mismatch",
            "status": "MISMATCH",
            "title": "Extension / Header Discrepancy",
            "description": f"File extension is '.{ext}', but internal magic signature is '{detected_format}'.",
            "severity": "MEDIUM",
        })
    else:
        findings.append({
            "category": "File Header",
            "status": "VALID",
            "title": "Header Signature Verified",
            "description": f"Magic bytes match official {detected_format} file format specification.",
            "severity": "INFO",
        })

    # Segment Mapping & EOF Steganography Check
    segments: List[Dict[str, Any]] = []
    appended_data_bytes = 0
    appended_data_detected = False
    appended_sample_hex = None

    if detected_format == "JPEG":
        with open(file_path, "rb") as f:
            full_data = f.read()
        segments, eoi_offset = _analyze_jpeg_segments(full_data)
        if eoi_offset is not None and file_size > eoi_offset:
            appended_data_bytes = file_size - eoi_offset
            if appended_data_bytes > 4:  # Allow minimal padding
                appended_data_detected = True
                appended_slice = full_data[eoi_offset : eoi_offset + 64]
                appended_sample_hex = appended_slice.hex()

                # Check if appended data looks like a ZIP or text file
                trailing_desc = f"{appended_data_bytes} bytes of extraneous data found appended past JPEG End-Of-Image marker (FF D9)."
                if appended_slice.startswith(b"PK"):
                    trailing_desc += " Trailing payload signature matches a ZIP/Office archive (Steganographic Polyglot)."

                findings.append({
                    "category": "Appended Payload",
                    "status": "SUSPICIOUS",
                    "title": "Post-EOF Injected Payload Detected",
                    "description": trailing_desc,
                    "severity": "HIGH",
                })
        elif eoi_offset is None:
            findings.append({
                "category": "Structural Integrity",
                "status": "CORRUPT",
                "title": "Missing JPEG End of Image (EOI)",
                "description": "File stream terminates prematurely without official FF D9 marker.",
                "severity": "HIGH",
            })
    elif detected_format == "PNG":
        with open(file_path, "rb") as f:
            full_data = f.read()
        # Find IEND chunk (49 45 4E 44) + 4-byte CRC
        iend_pos = full_data.find(b"IEND")
        if iend_pos != -1:
            png_end = iend_pos + 8  # 'IEND' + 4-byte CRC
            if file_size > png_end + 4:
                appended_data_bytes = file_size - png_end
                appended_data_detected = True
                findings.append({
                    "category": "Appended Payload",
                    "status": "SUSPICIOUS",
                    "title": "Post-IEND Injected Payload Detected",
                    "description": f"{appended_data_bytes} bytes discovered past PNG IEND terminal chunk.",
                    "severity": "HIGH",
                })

    # Prepare Hex Dump Previews (First 256 bytes & Last 128 bytes)
    header_dump = _format_hex_lines(head_sample[:256], base_offset=0)
    tail_dump_offset = max(0, file_size - 128)
    trailer_dump = _format_hex_lines(tail_sample[-128:], base_offset=tail_dump_offset)

    return {
        "file_size": file_size,
        "detected_format": detected_format,
        "is_valid_header": is_valid_header,
        "extension": ext,
        "extension_match": extension_match,
        "segments": segments,
        "has_appended_data": appended_data_detected,
        "appended_data_bytes": appended_data_bytes,
        "appended_sample_hex": appended_sample_hex,
        "findings": findings,
        "header_hex_dump": header_dump,
        "trailer_hex_dump": trailer_dump,
    }
