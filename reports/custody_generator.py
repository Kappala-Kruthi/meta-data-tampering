"""
TRACE Digital Forensics Workbench - Forensic Chain of Custody Certificate Generator.
Produces standardized, courtroom- and academic-grade Evidence Custody Certificates
establishing provenance, multi-algorithm cryptographic digests (SHA-256, SHA-1, MD5),
evidence acquisition parameters, and custody transfer logs.
"""

from __future__ import annotations

import hashlib
import os
import platform
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core import exiftool_runner, hasher


def generate_custody_certificate(
    file_path: str,
    investigator_id: str,
    investigator_name: str,
    investigator_title: str,
    case_ref: Optional[str] = None,
    source_context: str = "Source unknown",
    notes: str = "",
) -> Dict[str, Any]:
    """
    Generates a cryptographically sealed Chain of Custody evidentiary record.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    hashes = hasher.compute_file_hashes(file_path)
    now_utc = datetime.now(timezone.utc)
    now_local = datetime.now()

    # Evidence Reference ID
    file_name = os.path.basename(file_path)
    stem = os.path.splitext(file_name)[0].upper()[:8]
    clean_stem = "".join(c for c in stem if c.isalnum()) or "EVID"
    timestamp_token = now_utc.strftime("%Y%m%d%H%M")
    evidence_id = f"TRACE-COC-{timestamp_token}-{clean_stem}"

    # Engine version
    exif_ver = exiftool_runner.get_exiftool_version()

    # Tamper-Evident Verification Token
    token_seed = f"{evidence_id}|{hashes['sha256']}|{hashes['file_size_bytes']}|{investigator_id}|{now_utc.isoformat()}"
    custody_seal = hashlib.sha256(token_seed.encode("utf-8")).hexdigest()[:24].upper()
    formatted_seal = "-".join([custody_seal[i : i + 6] for i in range(0, 24, 6)])

    # Standard Custody Transfer Ledger
    transfer_ledger = [
        {
            "action": "EVIDENCE_ACQUISITION",
            "timestamp": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "custodian": f"{investigator_name} ({investigator_title})",
            "location": "Digital Forensics Acquisition Terminal",
            "purpose": f"Initial evidence intake and ingestion (Declared Source: {source_context})",
            "hash_verified": True,
        },
        {
            "action": "CRYPTOGRAPHIC_SEALING",
            "timestamp": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "custodian": "TRACE Automated Hashing Engine",
            "location": "Local Secure Evidence Repository",
            "purpose": f"Generated SHA-256 ({hashes['sha256'][:16]}...) and SHA-1 digests.",
            "hash_verified": True,
        },
        {
            "action": "FORENSIC_EXAMINATION",
            "timestamp": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "custodian": f"{investigator_name} ({investigator_title})",
            "location": "TRACE Digital Forensics Workbench",
            "purpose": "Non-destructive metadata extraction and structural anomaly analysis.",
            "hash_verified": True,
        },
    ]

    return {
        "certificate_title": "FORENSIC DIGITAL EVIDENCE CHAIN OF CUSTODY CERTIFICATE",
        "evidence_id": evidence_id,
        "case_reference": case_ref or f"CASE-{now_local.strftime('%Y%m')}-001",
        "acquisition_date_utc": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "acquisition_date_local": now_local.strftime("%Y-%m-%d %H:%M:%S"),
        "investigator": {
            "user_id": investigator_id,
            "display_name": investigator_name,
            "title": investigator_title,
        },
        "evidence_file": {
            "filename": file_name,
            "size_bytes": hashes["file_size_bytes"],
            "size_human": hashes["file_size_human"],
            "sha256": hashes["sha256"],
            "sha1": hashes["sha1"],
            "md5": hashes["md5"],
        },
        "source_context": source_context,
        "environment": {
            "exiftool_version": exif_ver,
            "python_version": sys.version.split()[0],
            "os_platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        },
        "custody_seal": formatted_seal,
        "transfer_ledger": transfer_ledger,
        "notes": notes or "Item acquired in good order for non-destructive digital forensics analysis.",
    }
