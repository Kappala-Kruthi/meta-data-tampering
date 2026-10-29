# TRACE: Digital Forensics Workbench
## Metadata Tampering Detection in Media Files Using ExifTool

An applied digital forensics application engineered to analyze, inspect, and detect metadata tampering in media files using Phil Harvey's ExifTool, cryptographic SHA-256 hashing, and rule-based heuristic anomaly detection.

---

## Project Overview

Digital media files (JPEG, PNG, TIFF, WebP, HEIC) embed structured metadata tags (EXIF, XMP, IPTC) recording camera hardware configurations, exposure settings, GPS geolocation coordinates, capture timestamps, and software modification trails.

This system provides:
1. Public Landing Page: Educational overview of digital forensics, metadata analysis, workflow, and technical methodology.
2. Secure Authentication: Session-based authentication protecting the forensic workspace.
3. Single Image Authenticity Analysis: Independent analysis of a solitary image for metadata inconsistencies, chronological inversions, editor software signatures, cross-namespace conflicts, and completeness without requiring a reference original copy.
4. Single-File Forensic Inspection: Comprehensive tag extraction grouped by family (File, EXIF, XMP, IPTC, GPS, Composite) with search filtering and chronological timelines.
5. Two-File Differential Workspace: Differential comparison between reference (File A) and suspected (File B) media files to identify matching, modified, added, and stripped tags.
6. Cryptographic Integrity Verification: Bit-for-bit file verification using SHA-256 and legacy MD5 hashing.
7. Rule-Based Anomaly Indicators: Transparent detection of editing software signatures (Photoshop, GIMP, Canva), chronological contradictions, and stripped geotags without unverified AI probabilities.
8. Local Case Management: Local SQLite persistence storing case summaries and an application-generated chain of custody audit log.
9. Multi-Format Report Generation: Standalone printable HTML evidence reports, CSV differential matrices, and structured JSON data.

---

## System Requirements

- Operating System: Windows 10 or Windows 11 (64-bit)
- Python: Version 3.10 or newer (tested with Python 3.13)
- ExifTool: Standalone Windows 64-bit executable (included locally in `tools/exiftool.exe`)

---

## Windows Quick Start Guide

### 1. Open Terminal in Project Folder
Open PowerShell or Command Prompt in the project directory:
```powershell
cd "c:\Users\K.BHUVANA KRUTHI\Downloads\meta-data-tampering"
```

### 2. Activate Virtual Environment
```powershell
.\.venv\Scripts\Activate.ps1
```
*(If execution policy prevents activation, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` or invoke `.\.venv\Scripts\python.exe` directly).*

### 3. Install Dependencies
```powershell
.\.venv\Scripts\pip.exe install -r requirements.txt
```

### 4. Verify ExifTool Executable
```powershell
.\tools\exiftool.exe -ver
```
Expected output: `13.59` (or newer).

### 5. Launch Web Application
```powershell
.\.venv\Scripts\python.exe app.py
```
Open your web browser and navigate to: **`http://127.0.0.1:5000`**

---

## Authentication and Demonstration Credentials

The application includes an authentication layer protecting the forensic analysis workspace.

### Demo Evaluation Credentials
- **User ID**: `Bhuvana@123`
- **Password**: `123`

### Security and Configuration Notice
The demo credentials above are provided strictly for local offline academic evaluation and viva demonstration. Never deploy this application to a public network with default credentials.

You can customize credentials and session secrets using Windows environment variables:
```powershell
$env:FORENSIC_USER_ID = "CustomAnalystID"
$env:FORENSIC_PASSWORD = "StrongSecurePassword"
$env:FLASK_SECRET_KEY = "RandomHexKeyForProduction"
```

---

## Running the Automated Test Suite
 
Execute the full suite of 32 automated unit, integration, and security tests:
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

All tests execute against local binaries and genuine test images in `tests/samples/`.
Specific tests for single-image authenticity analysis can be executed via:
```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_single_analysis.py -v
```

---

## Forensic Principles and Limitations

1. Cryptographic Hashes: Matching SHA-256 hashes establish bit-for-bit byte equality with near-absolute mathematical confidence. However, a differing hash only indicates that the binary bytes differ; it does not by itself prove malicious tampering. Lossy compression, rotation, and benign format re-encoding also change hashes.
2. Absence of Metadata: Social media platforms and messaging services routinely scrub EXIF metadata for user privacy and bandwidth efficiency. Lack of metadata is not definitive proof of tampering.
3. Device Clocks: EXIF timestamps reflect internal camera clock settings at capture time, which may be uncalibrated, unset, or offset by timezones.
4. Chain of Custody: Application-generated logs are local software audit records and should be corroborated with visual examination and independent evidence in forensic workflows.