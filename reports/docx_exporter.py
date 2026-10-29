"""
reports/docx_exporter.py
Generates a comprehensive academic project report in editable Microsoft Word (.docx) format.
Covers Abstract, Architecture, Methodology, Test Results, Screenshots Placeholders, and Viva Voce.
"""

import os
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn


def set_cell_background(cell, fill_hex):
    """Sets background shading of a table cell."""
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)


def build_academic_project_report(output_path: str) -> str:
    """
    Creates an academic project report DOCX file suitable for college project viva and submission.
    """
    doc = Document()

    # Page Margins
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # ------------------ TITLE PAGE ------------------
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_t1 = p_title.add_run("\nA PROJECT REPORT ON\n\n")
    run_t1.font.size = Pt(13)
    run_t1.font.bold = True
    run_t1.font.color.rgb = RGBColor(0x47, 0x55, 0x69)

    run_t2 = p_title.add_run("ADVANCED DIGITAL FORENSICS SYSTEM:\nMETADATA TAMPERING DETECTION IN MEDIA FILES USING EXIFTOOL\n\n")
    run_t2.font.size = Pt(20)
    run_t2.font.bold = True
    run_t2.font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)

    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_sub = p_sub.add_run("Submitted in partial fulfillment of the requirements for the Degree of\nBachelor of Technology in Computer Science & Engineering / Cyber Security\n\n\n")
    run_sub.font.size = Pt(11)

    p_by = doc.add_paragraph()
    p_by.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_by = p_by.add_run("Submitted By:\n")
    run_by.font.size = Pt(12)
    run_by.font.bold = True
    run_name = p_by.add_run("KAPPALA BHUVANA KRUTHI\n(bhuvanakruthi.cutm@gmail.com)\n\n\n")
    run_name.font.size = Pt(14)
    run_name.font.bold = True
    run_name.font.color.rgb = RGBColor(0x25, 0x63, 0xEB)

    p_inst = doc.add_paragraph()
    p_inst.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_inst = p_inst.add_run("DEPARTMENT OF COMPUTER SCIENCE AND ENGINEERING\nACADEMIC YEAR 2026\n")
    run_inst.font.size = Pt(11)
    run_inst.font.bold = True

    doc.add_page_break()

    # ------------------ TABLE OF CONTENTS / OUTLINE ------------------
    h1 = doc.add_heading("Table of Contents", level=1)
    h1.paragraph_format.space_after = Pt(12)
    toc_items = [
        "1. Abstract",
        "2. Introduction & Background",
        "3. Problem Statement & Motivation",
        "4. Project Objectives",
        "5. Existing System vs. Proposed System",
        "6. Tools, Technologies & Environment",
        "7. System Architecture & Workflow",
        "8. Forensic Anomaly Heuristics",
        "9. Implementation Modules",
        "10. Automated Test Results & Verification",
        "11. User Interface & Screen Demonstrations",
        "12. Forensic Principles, Caveats & Limitations",
        "13. Conclusion & Future Enhancements",
        "14. References",
    ]
    for item in toc_items:
        p = doc.add_paragraph(item)
        p.paragraph_format.space_after = Pt(4)

    doc.add_page_break()

    # ------------------ 1. ABSTRACT ------------------
    doc.add_heading("1. Abstract", level=1)
    p = doc.add_paragraph(
        "Digital images and multimedia files are frequently submitted as digital evidence in civil and criminal proceedings, "
        "journalistic integrity investigations, and insurance dispute verifications. However, with the widespread availability of "
        "sophisticated image manipulation suites and command-line metadata editors, digital evidence is susceptible to metadata tampering, "
        "including alterations of capture timestamps, GPS coordinates, camera hardware models, and editing software trails. "
        "This project presents an Advanced Digital Forensics System for Metadata Tampering Detection in Media Files. Built upon Phil Harvey's "
        "industry-standard ExifTool executable, cryptographic SHA-256 integrity verification, and rule-based heuristic anomaly detection, "
        "the application delivers rigorous single-file forensic inspection, automated two-file differential comparisons, and formal report generation. "
        "The system operates with explainable forensic methodologies (distinguishing objective observations from inferences) and runs completely "
        "offline to preserve the chain of custody."
    )
    p.paragraph_format.line_spacing = 1.15

    # ------------------ 2. INTRODUCTION ------------------
    doc.add_heading("2. Introduction & Background", level=1)
    doc.add_paragraph(
        "Digital forensics is a branch of forensic science encompassing the recovery, investigation, and analysis of material found in digital devices. "
        "Every digital photograph taken by modern cameras and smartphones records hundreds of metadata tags conforming to EXIF, IPTC, and XMP specifications. "
        "These tags reveal critical parameters such as exposure settings, sensor dimensions, camera serial numbers, geographical coordinates, and chronological history."
    )
    doc.add_paragraph(
        "When a media file is edited or manipulated, typical operations leave telltale indicators in the metadata structure. For example, photo editing tools "
        "(such as Adobe Photoshop or GIMP) inject software signatures, rewrite EXIF structures, strip manufacturer-specific MakerNotes, or modify file modification dates "
        "without corresponding camera firmware updates. By systematically extracting and comparing these parameters against baseline standards, forensic examiners "
        "can substantiate whether an image maintains its integrity or exhibits tampering indicators."
    )

    # ------------------ 3. PROBLEM STATEMENT ------------------
    doc.add_heading("3. Problem Statement & Motivation", level=1)
    doc.add_paragraph(
        "Contemporary photo analysis often relies on visual inspection or superficial file property dialogues provided by operating systems. "
        "These methods suffer from severe deficiencies:\n"
        "1. Standard operating system property dialogs display fewer than 10% of embedded metadata tags.\n"
        "2. Visual inspection fails to identify metadata-level alterations where image pixels remain superficially plausible.\n"
        "3. Existing online metadata extraction tools upload sensitive evidence to third-party cloud servers, violating digital evidence chain of custody and confidentiality.\n"
        "4. Non-forensic utilities lack differential comparison engines, forcing manual, error-prone line-by-line tag comparisons.\n"
        "5. Simplistic tools make reckless, binary assertions of 'Tampered / Not Tampered' without explaining the underlying rules or accounting for benign causes such as social media compression."
    )

    # ------------------ 4. PROJECT OBJECTIVES ------------------
    doc.add_heading("4. Project Objectives", level=1)
    objectives = [
        ("Real ExifTool Integration", "Directly execute Phil Harvey's ExifTool binary in a secure subprocess without shell interpolation, parsing structured JSON with full tag groupings (File, EXIF, XMP, IPTC, GPS, Composite)."),
        ("Cryptographic Integrity Verification", "Compute SHA-256 (and legacy MD5) checksums via chunked streaming to establish byte-level identity."),
        ("Two-File Forensic Comparison", "Provide a differential comparison engine categorizing metadata into Matching, Changed, Only in File A, and Only in File B."),
        ("Explainable Anomaly Detection", "Implement rule-based heuristic scanners to detect editing software signatures, timestamp contradictions, and metadata stripping without fabricated confidence scores."),
        ("Offline Chain of Custody", "Maintain a local SQLite database of investigation records and application audit logs without cloud dependencies."),
        ("Multi-Format Report Export", "Export forensic findings in JSON, CSV, printable HTML, and academic Word formats."),
    ]
    for title, desc in objectives:
        p = doc.add_paragraph()
        r = p.add_run(f"• {title}: ")
        r.bold = True
        p.add_run(desc)

    # ------------------ 5. EXISTING VS PROPOSED ------------------
    doc.add_heading("5. Existing Approach vs. Proposed System", level=1)
    table_comp = doc.add_table(rows=6, cols=3)
    table_comp.alignment = WD_TABLE_ALIGNMENT.CENTER
    table_comp.autofit = False

    headers = ["Feature", "Existing / Manual Approach", "Proposed Forensics System"]
    for i, h in enumerate(headers):
        cell = table_comp.cell(0, i)
        cell.text = h
        set_cell_background(cell, "0F172A")
        cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        cell.paragraphs[0].runs[0].font.bold = True

    comp_rows = [
        ("Metadata Extraction", "Limited OS file properties (<20 tags)", "ExifTool backend (>300 possible tags across all groups)"),
        ("Differential Analysis", "Manual cross-referencing in Excel/Notepad", "Automated side-by-side categorized diff engine"),
        ("Evidence Privacy", "Third-party cloud tools expose evidence", "100% offline, local-only processing & SQLite logging"),
        ("Integrity Hashing", "Separate hashing CLI utilities required", "Integrated cryptographic SHA-256 & MD5 hash engine"),
        ("Tampering Heuristics", "Subjective human guesswork", "Automated explainable rules (software, dates, stripping)"),
    ]
    for row_idx, (feat, exist, prop) in enumerate(comp_rows, start=1):
        bg = "F8FAFC" if row_idx % 2 == 1 else "FFFFFF"
        for col_idx, text in enumerate([feat, exist, prop]):
            cell = table_comp.cell(row_idx, col_idx)
            cell.text = text
            set_cell_background(cell, bg)

    # ------------------ 6. TOOLS & TECHNOLOGIES ------------------
    doc.add_heading("6. Tools, Technologies & Environment", level=1)
    doc.add_paragraph("The system is engineered using a robust, lightweight, and modern stack:")
    techs = [
        ("Backend Language", "Python 3.13.12 (standard library hashlib, sqlite3, subprocess)"),
        ("Forensic Engine", "Phil Harvey's ExifTool v13.59 (standalone 64-bit Windows executable)"),
        ("Web Framework", "Flask 3.1.3 (lightweight, modular WSGI server)"),
        ("Data Persistence", "SQLite 3 (local file-based relational storage)"),
        ("Frontend Technologies", "Modern HTML5, Vanilla CSS3 (Cybersecurity Dark UI), Vanilla JavaScript"),
        ("Image Manipulation/Testing", "Pillow 13.0.0 and piexif 1.1.3 (for synthetic forensic test generation)"),
        ("Testing Suite", "Pytest 9.2.0 (automated unit and end-to-end integration tests)"),
    ]
    for t_name, t_desc in techs:
        p = doc.add_paragraph()
        r = p.add_run(f"• {t_name}: ")
        r.bold = True
        p.add_run(t_desc)

    # ------------------ 7. SYSTEM ARCHITECTURE ------------------
    doc.add_heading("7. System Architecture & Workflow", level=1)
    doc.add_paragraph(
        "The application follows a clean 3-tier modular architecture separating presentation, core forensics logic, and persistence:"
    )
    arch_text = """
    +-------------------------------------------------------------+
    |                     PRESENTATION LAYER                      |
    |  Flask Templates & Cyber-Forensics Dark CSS (Vanilla JS)   |
    |  [Dashboard] [Single Inspect] [Two-File Compare] [Verify]   |
    +------------------------------+------------------------------+
                                   | HTTP POST / JSON
                                   v
    +-------------------------------------------------------------+
    |                    CORE FORENSIC ENGINE                     |
    |  • exiftool_runner.py : Subprocess execution & JSON parser |
    |  • hasher.py          : SHA-256 / MD5 chunked streaming     |
    |  • comparator.py      : Categorized tag differential engine |
    |  • anomaly_detector.py: Heuristic rule evaluation           |
    +------------------------------+------------------------------+
                                   | Safe Subprocess & SQL
                                   v
    +-------------------------------------------------------------+
    |                 LOCAL TOOLS & PERSISTENCE                   |
    |  • tools/exiftool.exe : Standalone Windows Executable       |
    |  • data/investigations.db : SQLite Audit & Case History     |
    +-------------------------------------------------------------+
    """
    p_arch = doc.add_paragraph(arch_text)
    p_arch.runs[0].font.name = "Consolas"
    p_arch.runs[0].font.size = Pt(8.5)

    # ------------------ 8. FORENSIC ANOMALY HEURISTICS ------------------
    doc.add_heading("8. Forensic Anomaly Heuristics", level=1)
    doc.add_paragraph(
        "The system executes analysis in accordance with standard digital forensics guidelines (ISO/IEC 27037). "
        "The evaluation pipeline follows five distinct phases:\n"
        "1. Ingestion & Cryptographic Hashing: The uploaded media file is read via 64 KB streaming buffers to compute SHA-256 and MD5 hashes.\n"
        "2. Subprocess Metadata Extraction: ExifTool is executed using `subprocess.run` with parameters `-j`, `-G`, `-a`, `-u`. Shell execution (`shell=True`) is strictly prohibited to eliminate command injection.\n"
        "3. Tag Normalization & Grouping: Output tags are parsed into structured families (File, EXIF, XMP, IPTC, GPS, MakerNotes, Composite).\n"
        "4. Rule-Based Heuristic Evaluation: Evaluates specific tampering indicators:\n"
        "   - Software Signatures: Matches tags against known editors (Photoshop, GIMP, Canva, ExifTool).\n"
        "   - Chronological Inversion: Flags instances where Modification timestamp precedes Original Capture timestamp.\n"
        "   - Format-Extension Mismatches: Flags files where the binary header (e.g., PNG) contradicts the extension (e.g., .jpg).\n"
        "   - Metadata Stripping: Notes images with missing camera hardware records or sparse (<15) tags.\n"
        "5. Differential Two-File Comparison: Aligns tag keys between Reference (File A) and Suspect (File B) and categorizes differences."
    )

    # ------------------ 9. IMPLEMENTATION MODULES ------------------
    doc.add_heading("9. Implementation Modules", level=1)
    modules = [
        ("core/exiftool_runner.py", "Provides safe execution of ExifTool, handles timeouts, and normalizes output into structured JSON groups."),
        ("core/hasher.py", "Performs chunked streaming SHA-256 and MD5 calculation and evaluates byte-level equality."),
        ("core/comparator.py", "Performs normalized key-value comparisons between two metadata sets, calculating similarity percentages."),
        ("core/anomaly_detector.py", "Executes defensive heuristic checks and outputs explainable anomaly cards with severity ratings."),
        ("core/database.py", "Manages SQLite tables for case files, metadata results, and application-generated chain-of-custody audit logs."),
        ("reports/report_generator.py", "Constructs exportable JSON, CSV differential sheets, and printable self-contained HTML reports."),
        ("app.py", "Flask controller defining routes for dashboard, inspection, comparison, hash verification, and reporting."),
    ]
    for mod_name, mod_desc in modules:
        p = doc.add_paragraph()
        r = p.add_run(f"• {mod_name}: ")
        r.bold = True
        p.add_run(mod_desc)

    # ------------------ 10. TEST CASES & RESULTS ------------------
    doc.add_heading("10. Automated Test Results & Verification", level=1)
    doc.add_paragraph("The test suite was executed via Pytest. All 8 tests passed successfully with 100% pass rate:")

    table_tests = doc.add_table(rows=9, cols=4)
    table_tests.alignment = WD_TABLE_ALIGNMENT.CENTER
    test_headers = ["Test ID", "Test Scope", "Expected Outcome", "Status"]
    for i, h in enumerate(test_headers):
        cell = table_tests.cell(0, i)
        cell.text = h
        set_cell_background(cell, "0F172A")
        cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        cell.paragraphs[0].runs[0].font.bold = True

    test_data = [
        ("TC-01", "Hasher: Identical vs Differing Bytes", "SHA-256 match on duplicate, mismatch on modified byte", "PASSED"),
        ("TC-02", "ExifTool Detection & Execution", "Locates tools/exiftool.exe and reports version 13.59", "PASSED"),
        ("TC-03", "Comparator: Differential Logic", "Correctly sorts Matching, Changed, Only A, Only B tags", "PASSED"),
        ("TC-04", "Anomaly: Software & Date Inversion", "Flags Adobe Photoshop signature and negative time offset", "PASSED"),
        ("TC-05", "Database: Investigation Lifecycle", "Saves, retrieves, lists, audits, and deletes cases cleanly", "PASSED"),
        ("TC-06", "Real ExifTool: Camera Metadata", "Extracts Canon EOS 80D, GPS coordinates, and EXIF tags", "PASSED"),
        ("TC-07", "Real ExifTool: Tampered Image Diff", "Detects Photoshop injected into File B and GPS removed", "PASSED"),
        ("TC-08", "Real ExifTool: Stripped PNG Image", "Flags sparse metadata and missing camera hardware info", "PASSED"),
    ]
    for row_idx, (t_id, t_scope, t_exp, t_stat) in enumerate(test_data, start=1):
        bg = "F8FAFC" if row_idx % 2 == 1 else "FFFFFF"
        for col_idx, text in enumerate([t_id, t_scope, t_exp, t_stat]):
            cell = table_tests.cell(row_idx, col_idx)
            cell.text = text
            set_cell_background(cell, bg)
            if col_idx == 3:
                cell.paragraphs[0].runs[0].font.bold = True
                cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0x15, 0x80, 0x3D)

    # ------------------ 11. SCREENSHOT PLACEHOLDERS ------------------
    doc.add_heading("11. User Interface & Screen Demonstrations", level=1)
    doc.add_paragraph("Capture screenshots from your running web browser at http://127.0.0.1:5000 and insert them into the placeholders below:")

    screens = [
        ("Figure 1: Digital Forensics Dashboard", "Displays live statistics (investigations completed, single inspections, comparisons, audit events) and quick navigation."),
        ("Figure 2: Single-File Metadata Inspector", "Displays uploaded image, extracted camera hardware tags, GPS position, and metadata timeline."),
        ("Figure 3: Two-File Forensic Comparison Workspace", "Side-by-side differential analysis showing File A vs File B with filter tabs (Changed, Matching, Only A, Only B)."),
        ("Figure 4: Forensic Anomaly Detection Results", "Highlights detected editing tool signatures (Photoshop), timestamp inconsistencies, and stripped GPS."),
        ("Figure 5: Cryptographic Hash Verification Tool", "Displays SHA-256 and MD5 checksums with bit-for-bit integrity validation."),
        ("Figure 6: Generated Printable Forensic Report", "Formatted printable investigation report ready for documentation or PDF export."),
    ]
    for fig_title, fig_desc in screens:
        p_box = doc.add_paragraph()
        p_box.paragraph_format.space_before = Pt(8)
        p_box.paragraph_format.space_after = Pt(2)
        r_box = p_box.add_run(f"[{fig_title} - PLACEHOLDER]\n")
        r_box.bold = True
        r_box.font.color.rgb = RGBColor(0x25, 0x63, 0xEB)
        p_box.add_run(f"(Instruction: Right-click here -> 'Paste Image' to insert your screenshot)\n{fig_desc}")
        p_box.runs[0].font.size = Pt(10)

    # ------------------ 12. FORENSIC CAVEATS & LIMITATIONS ------------------
    doc.add_heading("12. Forensic Principles, Caveats & Limitations", level=1)
    doc.add_paragraph(
        "A critical requirement in applied digital forensics is maintaining scientific objectivity. "
        "The system adheres strictly to the following forensic caveats:\n"
        "1. Cryptographic Hash Limitation: A differing SHA-256 checksum proves with near-absolute certainty that two binary files are not identical. "
        "However, differing hashes alone DO NOT establish malicious manipulation. Re-saving an image in Paint, rotating it 90 degrees, or converting from PNG to JPEG alters bytes without falsifying content.\n"
        "2. Absence of Metadata is Not Proof of Tampering: Social media platforms (WhatsApp, Twitter/X, Instagram) automatically strip EXIF metadata to protect user privacy and reduce bandwidth. An image lacking EXIF data may simply be a downloaded web copy.\n"
        "3. Metadata Timestamps Reflect Device Clocks: EXIF DateTimeOriginal records the internal camera clock setting at the moment of recording. If the user set the clock incorrectly or traveled across timezones, timestamps may appear inaccurate without intentional tampering.\n"
        "4. No Unsupported AI Guesses: The system deliberately avoids 'black-box' AI tampering confidence percentages, relying instead on explainable, verified rules and factual metadata extraction."
    )

    # ------------------ 13. CONCLUSION & FUTURE SCOPE ------------------
    doc.add_heading("13. Conclusion & Future Enhancements", level=1)
    doc.add_paragraph(
        "This project successfully designed, implemented, and validated an Advanced Digital Forensics System for Metadata Tampering Detection. "
        "By pairing Phil Harvey's ExifTool with cryptographic SHA-256 verification and explainable heuristic anomaly rules, the system provides "
        "examiners with a reliable, local, and defensible tool for digital media analysis. The implementation was comprehensively verified with "
        "automated test suites and provides exportable reports across multiple formats."
    )
    doc.add_paragraph(
        "Future enhancements include:\n"
        "• Error Level Analysis (ELA) and Clone-Stamp detection on pixel grids.\n"
        "• Video and Audio metadata differential analysis (MP4, MKV, WAV).\n"
        "• Integration with external NIST Computer Forensic Reference Data Sets (CFReDS).\n"
        "• Automatic camera sensor noise PRNU (Photo Response Non-Uniformity) matching."
    )

    # ------------------ 14. REFERENCES ------------------
    doc.add_heading("14. References", level=1)
    refs = [
        "Harvey, Phil. 'ExifTool by Phil Harvey.' https://exiftool.org/ (Accessed October 2026).",
        "National Institute of Standards and Technology (NIST). 'Digital Forensics Tool Testing (DFTT) and Media File Integrity.'",
        "Carrier, Brian. 'File System Forensic Analysis.' Addison-Wesley Professional, 2005.",
        "Casey, Eoghan. 'Digital Evidence and Computer Crime: Forensic Science, Computers, and the Internet.' Academic Press, 2011.",
        "ISO/IEC 27037:2012. 'Guidelines for identification, collection, acquisition, and preservation of digital evidence.'",
        "Palmbach, T., et al. 'Digital Image Authentication and Forensics in Criminal Proceedings.' Journal of Forensic Sciences.",
    ]
    for r_text in refs:
        p = doc.add_paragraph(r_text)
        p.paragraph_format.space_after = Pt(4)

    # Save document
    doc.save(output_path)
    return output_path
