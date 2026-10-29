"""
reports/report_generator.py
Generates downloadable investigation reports:
1. Structured JSON report
2. Comparison CSV export
3. Standalone, printable, human-readable forensic HTML report
"""

import csv
import io
import json
from typing import Any, Dict, List


def export_as_json(investigation_data: Dict[str, Any]) -> str:
    """Serializes the investigation into a formatted JSON string."""
    return json.dumps(investigation_data, indent=2, default=str)


def export_comparison_as_csv(comparison_data: Dict[str, Any]) -> str:
    """Exports comparison results (matching, changed, only_a, only_b) into CSV format."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Write CSV Header
    writer.writerow(["Category", "Group", "Tag Name", "Full Tag", "Value in File A", "Value in File B"])

    # Changed tags
    for item in comparison_data.get("changed", []):
        writer.writerow([
            "CHANGED",
            item.get("group", ""),
            item.get("tag", ""),
            item.get("full_tag", ""),
            item.get("value_a", ""),
            item.get("value_b", ""),
        ])

    # Only in File A
    for item in comparison_data.get("only_a", []):
        writer.writerow([
            "ONLY_IN_FILE_A",
            item.get("group", ""),
            item.get("tag", ""),
            item.get("full_tag", ""),
            item.get("value_a", ""),
            "N/A",
        ])

    # Only in File B
    for item in comparison_data.get("only_b", []):
        writer.writerow([
            "ONLY_IN_FILE_B",
            item.get("group", ""),
            item.get("tag", ""),
            item.get("full_tag", ""),
            "N/A",
            item.get("value_b", ""),
        ])

    # Matching tags
    for item in comparison_data.get("matching", []):
        writer.writerow([
            "MATCHING",
            item.get("group", ""),
            item.get("tag", ""),
            item.get("full_tag", ""),
            item.get("value_a", ""),
            item.get("value_b", ""),
        ])

    return output.getvalue()


def generate_printable_html_report(investigation_data: Dict[str, Any]) -> str:
    """
    Builds a standalone, beautifully styled, printable forensic HTML report.
    Self-contained with inline CSS for offline printing and saving as PDF.
    """
    inv_id = investigation_data.get("id", "N/A")
    title = investigation_data.get("case_title", "Forensic Investigation Report")
    created_at = investigation_data.get("created_at", "N/A")
    analysis_type = investigation_data.get("analysis_type", "N/A").upper()
    notes = investigation_data.get("notes") or "No additional investigator notes provided."
    results = investigation_data.get("results", {})

    anomalies = results.get("anomalies", [])
    file_a = results.get("file_a", {})
    file_b = results.get("file_b", {})
    comp = results.get("comparison", {})
    metrics = comp.get("metrics", {})

    # Build anomalies table HTML
    anomalies_rows = ""
    if anomalies:
        for a in anomalies:
            severity = a.get("severity", "INFORMATIONAL")
            color = "#ef4444" if severity == "SIGNIFICANT_DIFFERENCE" else ("#f59e0b" if severity == "REVIEW_RECOMMENDED" else "#3b82f6")
            anomalies_rows += f"""
            <tr>
                <td><span style="display:inline-block; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px; background:{color}22; color:{color}; border:1px solid {color}55;">{severity}</span></td>
                <td><strong>{a.get('title')}</strong><br><small style="color:#555;">{a.get('rule_id')}</small></td>
                <td>{a.get('description')}<br><code style="background:#f1f5f9; padding:2px 4px; font-size:11px;">{a.get('evidence', '')}</code></td>
                <td><small style="color:#666;">{a.get('mitigating_factors', 'None')}</small></td>
            </tr>
            """
    else:
        anomalies_rows = "<tr><td colspan='4' style='text-align:center; color:#10b981; padding:15px;'>No forensic anomalies or tampering indicators detected based on active heuristics.</td></tr>"

    # Build changed metadata rows HTML
    changed_rows = ""
    for ch in comp.get("changed", []):
        changed_rows += f"""
        <tr>
            <td><code>{ch.get('group')}:{ch.get('tag')}</code></td>
            <td style="color:#b91c1c;">{ch.get('value_a')}</td>
            <td style="color:#15803d; font-weight:bold;">{ch.get('value_b')}</td>
        </tr>
        """
    if not changed_rows:
        changed_rows = "<tr><td colspan='3' style='text-align:center; color:#666; padding:10px;'>No changed metadata tags found.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Report - {inv_id}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #1e293b; background: #fff; margin: 0; padding: 25px; }}
    @media print {{ body {{ padding: 0; }} .no-print {{ display: none; }} }}
    .header {{ border-bottom: 2px solid #0f172a; padding-bottom: 15px; margin-bottom: 20px; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; background: #e2e8f0; color: #334155; }}
    .meta-box {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 15px; margin-bottom: 20px; }}
    h1 {{ font-size: 22px; color: #0f172a; margin: 0 0 5px 0; }}
    h2 {{ font-size: 15px; color: #1e293b; border-bottom: 1px solid #cbd5e1; padding-bottom: 5px; margin-top: 25px; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 15px; font-size: 12px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 7px 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; font-weight: 600; color: #334155; }}
    code {{ font-family: Consolas, monospace; font-size: 11px; }}
    .btn-print {{ background: #0f172a; color: #fff; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 600; margin-bottom: 15px; }}
    .btn-print:hover {{ background: #334155; }}
    .callout {{ background: #eff6ff; border-left: 4px solid #3b82f6; padding: 10px 15px; font-size: 12px; color: #1e3a8a; margin-bottom: 20px; }}
    .disclaimer {{ background: #fef2f2; border-left: 4px solid #ef4444; padding: 10px 15px; font-size: 11px; color: #991b1b; margin-top: 30px; }}
</style>
</head>
<body>
<div class="no-print" style="text-align: right;">
    <button class="btn-print" onclick="window.print()">Print or Save as PDF</button>
</div>

<div class="header">
    <div style="display:flex; justify-content:space-between; align-items:flex-start;">
        <div>
            <h1>TRACE Digital Forensics Investigation Report</h1>
            <div style="color:#64748b; font-size:13px;">TRACE Digital Forensics Workbench | Tool: Phil Harvey's ExifTool</div>
        </div>
        <div style="text-align:right;">
            <span class="badge">CASE ID: {inv_id}</span>
            <div style="font-size:12px; color:#64748b; margin-top:5px;">Analysis Date: {created_at}</div>
        </div>
    </div>
</div>

<div class="meta-box">
    <div>
        <strong>Case Title:</strong> {title}<br>
        <strong>Investigation Type:</strong> {analysis_type}<br>
        <strong>Investigator Notes:</strong> {notes}
    </div>
    <div>
        <strong>Tool Engine:</strong> ExifTool (Stand-alone Windows 64-bit)<br>
        <strong>Integrity Algorithm:</strong> Cryptographic SHA-256 (64-character hash)<br>
        <strong>Chain of Custody:</strong> Local Application Audit Log
    </div>
</div>

<h2>1. Cryptographic File Integrity Analysis</h2>
<table>
    <thead>
        <tr>
            <th>Role</th>
            <th>Filename</th>
            <th>File Size</th>
            <th>SHA-256 Hash</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td><strong>File A (Reference)</strong></td>
            <td>{file_a.get('file_name', investigation_data.get('file_a_name', 'N/A'))}</td>
            <td>{file_a.get('file_size_human', 'N/A')}</td>
            <td><code>{file_a.get('sha256', investigation_data.get('file_a_hash', 'N/A'))}</code></td>
        </tr>
        {'<tr><td><strong>File B (Suspected)</strong></td><td>' + str(file_b.get('file_name', investigation_data.get('file_b_name', 'N/A'))) + '</td><td>' + str(file_b.get('file_size_human', 'N/A')) + '</td><td><code>' + str(file_b.get('sha256', investigation_data.get('file_b_hash', 'N/A'))) + '</code></td></tr>' if file_b.get('file_name') or investigation_data.get('file_b_name') else ''}
    </tbody>
</table>

{'<div class="callout"><strong>Forensic Integrity Status:</strong> ' + comp.get('observation', 'Single-file inspection.') + '</div>' if comp.get('observation') else ''}

<h2>2. Forensic Anomaly & Heuristic Detection</h2>
<table>
    <thead>
        <tr>
            <th style="width:15%;">Severity</th>
            <th style="width:25%;">Anomaly / Rule</th>
            <th style="width:35%;">Description & Evidence</th>
            <th style="width:25%;">Mitigating Explanations</th>
        </tr>
    </thead>
    <tbody>
        {anomalies_rows}
    </tbody>
</table>

{f'''
<h2>3. Metadata Differential Summary (File A vs File B)</h2>
<div style="display:grid; grid-template-columns:repeat(4, 1fr); gap:10px; margin-bottom:15px; text-align:center;">
    <div style="background:#f1f5f9; padding:10px; border-radius:4px;"><strong>{metrics.get('matching_count', 0)}</strong><br><small>Matching Tags</small></div>
    <div style="background:#fee2e2; padding:10px; border-radius:4px; color:#b91c1c;"><strong>{metrics.get('changed_count', 0)}</strong><br><small>Modified Tags</small></div>
    <div style="background:#fef3c7; padding:10px; border-radius:4px; color:#b45309;"><strong>{metrics.get('only_a_count', 0)}</strong><br><small>Only in File A</small></div>
    <div style="background:#e0e7ff; padding:10px; border-radius:4px; color:#4338ca;"><strong>{metrics.get('only_b_count', 0)}</strong><br><small>Only in File B</small></div>
</div>

<table>
    <thead>
        <tr>
            <th style="width:30%;">Metadata Tag</th>
            <th style="width:35%;">File A (Reference) Value</th>
            <th style="width:35%;">File B (Suspected) Value</th>
        </tr>
    </thead>
    <tbody>
        {changed_rows}
    </tbody>
</table>
''' if analysis_type == "COMPARE" or comp.get("changed") else ''}

<div class="disclaimer">
    <strong>Forensic Caveat & Legal Notice:</strong><br>
    This automated report documents extracted metadata tags and cryptographic checksums using Phil Harvey's ExifTool and SHA-256. 
    A differing hash indicates modified binary bytes but does not alone prove malicious intent; differences can occur through image re-compression, rotation, or social media privacy stripping. 
    Findings should be correlated with visual forensic inspection and independent corroborating evidence.
</div>

</body>
</html>
    """
    return html


def generate_single_analysis_report(investigation_data: Dict[str, Any]) -> str:
    """
    Builds a standalone, printable evidence report specifically designed for
    Single Image Metadata Authenticity Analysis.
    Adheres strictly to objective reporting, uncertainty disclosure, and verifiable evidence.
    """
    inv_id = investigation_data.get("id", "N/A")
    title = investigation_data.get("case_title", "Single Image Forensic Authenticity Analysis")
    created_at = investigation_data.get("created_at", "N/A")
    notes = investigation_data.get("notes") or "None specified."
    results = investigation_data.get("results", {})

    single_res = results.get("single_analysis", {})
    classification = single_res.get("classification_title", "Inconclusive")
    classification_desc = single_res.get("classification_description", "")
    findings = single_res.get("findings", [])
    checks = single_res.get("checks_performed", [])
    completeness = single_res.get("completeness", {})
    advanced = single_res.get("advanced_analysis", {})
    raw_metadata = results.get("raw_metadata", {})

    filename = investigation_data.get("file_a_name", "Unknown File")
    file_hash = investigation_data.get("file_a_hash", "N/A")
    file_size_human = results.get("file_size_human", "N/A")
    detected_format = results.get("detected_format", "N/A")
    source_context = single_res.get("source_context") or results.get("source_context") or "Source unknown"

    # Classification badge color
    badge_bg = "#fef3c7" if "Suspicious" in classification else ("#dbeafe" if "Inconclusive" in classification else "#dcfce7")
    badge_color = "#92400e" if "Suspicious" in classification else ("#1e40af" if "Inconclusive" in classification else "#166534")

    # Findings Rows
    findings_rows = ""
    if findings:
        for f in findings:
            sev = f.get("severity", "INFORMATIONAL")
            sev_color = "#b91c1c" if sev == "HIGH" else ("#b45309" if sev == "MEDIUM" else "#2563eb")
            findings_rows += f"""
            <tr>
                <td><span style="display:inline-block; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px; background:{sev_color}18; color:{sev_color}; border:1px solid {sev_color}44;">{sev}</span><br><small style="color:#64748b;">{f.get('severity_reason', '')}</small></td>
                <td><strong>{f.get('rule_name')}</strong><br><code>{f.get('rule_id')}</code></td>
                <td>
                    <strong>Observed Evidence:</strong><br>
                    <code style="background:#f1f5f9; padding:2px 4px; font-size:11px; display:inline-block; margin-bottom:4px;">{f.get('evidence_field', '')}</code><br>
                    {f.get('observed_value', '')}<br><br>
                    <strong>Forensic Explanation:</strong><br>{f.get('explanation', '')}
                </td>
                <td>
                    <strong>Benign Possibility:</strong><br>{f.get('benign_explanation', '')}<br><br>
                    <strong>Recommended Next Step:</strong><br><span style="color:#0f172a; font-weight:500;">{f.get('next_step', '')}</span>
                </td>
            </tr>
            """
    else:
        findings_rows = "<tr><td colspan='4' style='text-align:center; color:#15803d; padding:16px;'>No suspicious metadata indicators or chronological contradictions detected under the active evaluation rules.</td></tr>"

    # Checks Performed Rows
    checks_rows = ""
    for chk in checks:
        status = chk.get("status", "PASS")
        st_color = "#b45309" if status == "FLAGGED" else ("#15803d" if status == "PASS" else "#475569")
        checks_rows += f"""
        <tr>
            <td><strong>{chk.get('name')}</strong><br><code>{chk.get('check_id')}</code></td>
            <td><span style="font-weight:bold; color:{st_color};">{status}</span></td>
            <td><small>{', '.join(chk.get('fields_evaluated', []))}</small></td>
            <td><small style="color:#475569;">{chk.get('notes', '')}</small></td>
        </tr>
        """

    # Appendix: Raw metadata sample (up to 40 primary tags)
    raw_rows = ""
    for idx, (k, v) in enumerate(list(raw_metadata.items())[:50]):
        raw_rows += f"<tr><td><code>{k}</code></td><td>{v}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>TRACE Single Image Forensic Report - {inv_id}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #1e293b; background: #fff; margin: 0; padding: 25px; }}
    @media print {{ body {{ padding: 0; }} .no-print {{ display: none; }} }}
    .header {{ border-bottom: 2px solid #0f172a; padding-bottom: 15px; margin-bottom: 20px; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
    .classification-box {{ background: {badge_bg}; color: {badge_color}; border: 1px solid {badge_color}55; border-radius: 6px; padding: 14px 18px; margin-bottom: 20px; }}
    .meta-box {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 15px; margin-bottom: 20px; }}
    h1 {{ font-size: 22px; color: #0f172a; margin: 0 0 5px 0; }}
    h2 {{ font-size: 14px; color: #0f172a; border-bottom: 1px solid #cbd5e1; padding-bottom: 5px; margin-top: 25px; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 15px; font-size: 12px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; font-weight: 600; color: #334155; }}
    code {{ font-family: Consolas, monospace; font-size: 11px; }}
    .btn-print {{ background: #0f172a; color: #fff; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 600; margin-bottom: 15px; }}
    .btn-print:hover {{ background: #334155; }}
    .disclaimer {{ background: #f8fafc; border-left: 4px solid #64748b; padding: 12px 16px; font-size: 11px; color: #334155; margin-top: 25px; line-height: 1.6; }}
</style>
</head>
<body>
<div class="no-print" style="text-align: right;">
    <button class="btn-print" onclick="window.print()">Print or Save as PDF</button>
</div>

<div class="header">
    <div style="display:flex; justify-content:space-between; align-items:flex-start;">
        <div>
            <h1>TRACE: Single Image Metadata Authenticity Report</h1>
            <div style="color:#64748b; font-size:13px;">Digital Forensics Workbench | Analysis Engine: Phil Harvey's ExifTool & SHA-256</div>
        </div>
        <div style="text-align:right;">
            <span class="badge" style="background:#e2e8f0; color:#0f172a;">CASE REF: {inv_id}</span>
            <div style="font-size:12px; color:#64748b; margin-top:5px;">Analysis Timestamp: {created_at}</div>
        </div>
    </div>
</div>

<!-- Overall Classification -->
<div class="classification-box">
    <div style="font-size:11px; font-weight:bold; text-transform:uppercase; letter-spacing:0.8px; margin-bottom:3px;">Forensic Classification (Standalone Single-File Evaluation)</div>
    <div style="font-size:18px; font-weight:bold; margin-bottom:4px;">{classification}</div>
    <div style="font-size:13px;">{classification_desc}</div>
</div>

<div class="meta-box">
    <div>
        <strong>Evidence Filename:</strong> {filename}<br>
        <strong>File Size:</strong> {file_size_human}<br>
        <strong>Detected File Format:</strong> {detected_format}<br>
        <strong>Declared Source Context:</strong> <span style="color:#0f172a; font-weight:600;">{source_context}</span><br>
        <strong>Investigator Notes:</strong> {notes}
    </div>
    <div>
        <strong>Cryptographic SHA-256 Digest:</strong><br>
        <code style="word-break:break-all;">{file_hash}</code><br><br>
        <strong>Total Tags Extracted:</strong> {completeness.get('tag_count', 0)} tags<br>
        <strong>Hardware Tags:</strong> {completeness.get('camera_hardware', 'Absent')} | <strong>EXIF:</strong> {completeness.get('exif_status', 'Absent')} | <strong>GPS:</strong> {completeness.get('gps_status', 'Absent')}
    </div>
</div>

<h2>1. Explainable Forensic Findings</h2>
<table>
    <thead>
        <tr>
            <th style="width:18%;">Severity &amp; Rationale</th>
            <th style="width:22%;">Rule &amp; Identifier</th>
            <th style="width:30%;">Observed Evidence &amp; Explanation</th>
            <th style="width:30%;">Benign Explanations &amp; Recommended Steps</th>
        </tr>
    </thead>
    <tbody>
        {findings_rows}
    </tbody>
</table>

<h2>2. Checks Performed Matrix</h2>
<table>
    <thead>
        <tr>
            <th style="width:30%;">Check Name</th>
            <th style="width:15%;">Evaluation Status</th>
            <th style="width:25%;">Fields Evaluated</th>
            <th style="width:30%;">Investigative Observations</th>
        </tr>
    </thead>
    <tbody>
        {checks_rows}
    </tbody>
</table>

<h2>3. Image-Level Advanced Indicators</h2>
<table>
    <thead>
        <tr>
            <th style="width:25%;">Technique</th>
            <th style="width:25%;">Observed Metrics</th>
            <th style="width:25%;">Relevance &amp; Benign Factors</th>
            <th style="width:25%;">Methodological Limitations</th>
        </tr>
    </thead>
    <tbody>
        {"".join([f"<tr><td><strong>{obs.get('technique')}</strong></td><td>{obs.get('observed')}</td><td>{obs.get('relevance')}<br><small style='color:#64748b;'>Benign: {obs.get('benign_explanation')}</small></td><td><small>{obs.get('limitations')}</small></td></tr>" for obs in advanced.get("observations", [])]) or "<tr><td colspan='4' style='text-align:center; color:#64748b;'>Image-level advanced analysis not available for this container type.</td></tr>"}
    </tbody>
</table>

<h2>4. Extracted Metadata Sample Appendix (First 50 Tags)</h2>
<table>
    <thead>
        <tr>
            <th style="width:35%;">Tag Name (Namespace:Tag)</th>
            <th style="width:65%;">Extracted Recorded Value</th>
        </tr>
    </thead>
    <tbody>
        {raw_rows or "<tr><td colspan='2' style='text-align:center; color:#64748b;'>No raw metadata tags extracted.</td></tr>"}
    </tbody>
</table>

<div class="disclaimer">
    <strong>Forensic Transparency &amp; Uncertainty Disclosure:</strong><br>
    This automated analysis was performed without a verified original master image or authoritative external reference hash. 
    Consequently, this system evaluates internal consistency, chronological ordering, and recorded tag signatures only. 
    The absence of suspicious indicators does NOT establish authenticity or prove that an image is unaltered, as metadata can be freely stripped, forged, or edited. 
    Conversely, the presence of software tags or differing timestamps does not prove malicious intent, as normal export, cropping, and routine format conversions legitimately introduce software tags. 
    All conclusions must be verified through independent corroborating evidence, physical hardware inspection, and forensic chain of custody.
</div>

</body>
</html>
    """
    return html

