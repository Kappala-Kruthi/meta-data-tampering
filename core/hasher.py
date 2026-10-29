"""
core/hasher.py
Cryptographic hashing module for bit-for-bit forensic integrity verification.
Computes SHA-256 (primary standard) and MD5 (legacy reference).
"""

import hashlib
import os
from typing import Any, Dict


def format_file_size(num_bytes: int) -> str:
    """Returns human-readable file size string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def calculate_sha256(file_path: str) -> str:
    """Computes SHA-256 hex digest for a target file."""
    return compute_file_hashes(file_path)["sha256"]


def compute_file_hashes(file_path: str, chunk_size: int = 65536) -> Dict[str, Any]:
    """
    Computes cryptographic hashes for a file using streaming reads.
    
    Args:
        file_path: Path to the target file.
        chunk_size: Read buffer size in bytes (default: 64 KB).
        
    Returns:
        Dict containing SHA-256, SHA-1, MD5, file size in bytes, and human-readable size.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Target file does not exist: {file_path}")

    sha256_hasher = hashlib.sha256()
    sha1_hasher = hashlib.sha1()
    md5_hasher = hashlib.md5()
    total_bytes = 0

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256_hasher.update(chunk)
            sha1_hasher.update(chunk)
            md5_hasher.update(chunk)
            total_bytes += len(chunk)

    return {
        "file_name": os.path.basename(file_path),
        "file_size_bytes": total_bytes,
        "file_size_human": format_file_size(total_bytes),
        "sha256": sha256_hasher.hexdigest().lower(),
        "sha1": sha1_hasher.hexdigest().lower(),
        "md5": md5_hasher.hexdigest().lower(),
    }


def compare_file_hashes(file_path_a: str, file_path_b: str) -> Dict[str, Any]:
    """
    Compares cryptographic hashes of two files and provides an objective forensic statement.
    """
    hashes_a = compute_file_hashes(file_path_a)
    hashes_b = compute_file_hashes(file_path_b)

    sha256_match = hashes_a["sha256"] == hashes_b["sha256"]
    size_match = hashes_a["file_size_bytes"] == hashes_b["file_size_bytes"]

    if sha256_match:
        integrity_status = "IDENTICAL_BYTES"
        summary = (
            "Cryptographic SHA-256 hashes are identical. "
            "Both files are bit-for-bit byte duplicates with near-absolute mathematical certainty."
        )
    else:
        integrity_status = "DIFFERENT_BYTES"
        summary = (
            "Cryptographic SHA-256 hashes differ. "
            "The binary contents of the two files are not identical. "
            "Note: Differing hashes indicate modified bytes (which can result from re-compression, "
            "metadata changes, editing, or format conversion), but do not on their own prove malicious manipulation."
        )

    return {
        "file_a": hashes_a,
        "file_b": hashes_b,
        "sha256_match": sha256_match,
        "size_match": size_match,
        "status": integrity_status,
        "summary": summary,
    }
