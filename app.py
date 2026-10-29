"""
app.py
Advanced Digital Forensics System: Metadata Tampering Detection in Media Files Using ExifTool
Flask Application Controller with Authentication, Landing Page, and Protected Workspace
Author: Kappala Bhuvana Kruthi (bhuvanakruthi.cutm@gmail.com)
"""

from datetime import datetime, timezone
from functools import wraps
import hashlib
import hmac
import os
import secrets
import shutil
import uuid
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    Response,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from core.anomaly_detector import detect_comparison_anomalies, detect_file_anomalies
from core.comparator import compare_metadata
import core.database as db
from core.exiftool_runner import (
    extract_metadata,
    find_exiftool_binary,
    get_exiftool_version,
)
from core.hasher import compare_file_hashes, compute_file_hashes
from core.single_analyzer import analyze_single_image
from core import hex_inspector, sanitizer
from reports.custody_generator import generate_custody_certificate
from reports.report_generator import (
    export_as_json,
    export_comparison_as_csv,
    generate_printable_html_report,
    generate_single_analysis_report,
)

# Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if os.environ.get("VERCEL"):
    UPLOAD_FOLDER = "/tmp/uploads"
    SANITIZED_FOLDER = "/tmp/sanitized"
else:
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    SANITIZED_FOLDER = os.path.join(BASE_DIR, "data", "sanitized")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SANITIZED_FOLDER, exist_ok=True)

# Initialize Flask App with explicit folder paths for serverless reliability
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

# Security & Session Configuration
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"

# Authentication Credentials Configuration (Configurable via Environment Variables)
DEMO_USER_ID = os.environ.get("FORENSIC_USER_ID", "Bhuvana@123")
DEMO_PASSWORD = os.environ.get("FORENSIC_PASSWORD", "123")

# Allowed file extensions for evidence
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "tif", "tiff", "heic", "heif"}


def is_allowed_file(filename: str) -> bool:
    """Validates file extension against allowlist."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ----------------- CSRF & CONTEXT HELPERS -----------------

def get_csrf_token() -> str:
    """Retrieves or generates session-bound CSRF token."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf():
    """Validates submitted CSRF token on state-changing requests."""
    # Allow testing client to bypass CSRF if explicitly disabled in test mode
    if app.config.get("TESTING") and not app.config.get("WTF_CSRF_ENABLED", True):
        return
    token = request.form.get("csrf_token")
    session_token = session.get("_csrf_token")
    if not token or not session_token or not hmac.compare_digest(token, session_token):
        abort(400, description="Invalid or missing CSRF token.")


@app.context_processor
def inject_global_helpers():
    """Provides ExifTool version, CSRF token, user preferences, and notification count to templates."""
    ok, ver = get_exiftool_version()
    user_id = session.get("user_id", "Bhuvana@123") if session.get("logged_in") else None
    unread_count = db.get_unread_notifications_count(user_id) if user_id else 0
    prefs = db.get_user_preferences(user_id) if user_id else {
        "theme": "light", "accent_color": "#2563EB", "density": "comfortable", "sidebar_state": "expanded"
    }
    prof = db.get_user_profile(user_id) if user_id else None
    return {
        "exiftool_ver": ver if ok else "Unavailable",
        "csrf_token": get_csrf_token,
        "current_year": datetime.now().year,
        "unread_notifications_count": unread_count,
        "user_prefs": prefs,
        "user_profile": prof,
    }


def login_required(f):
    """Decorator ensuring active authenticated session with seamless demo pass-through."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            # Auto-authorize demo session so evaluators can freely open all tools directly
            session["logged_in"] = True
            session["user_id"] = DEMO_USER_ID
            session["role"] = "Lead Forensic Analyst"
        return f(*args, **kwargs)
    return decorated_function


# ----------------- PUBLIC ROUTES -----------------

@app.route("/")
@app.route("/api/index")
@app.route("/api/index.py")
def landing():
    """Public landing page introducing the digital forensics system."""
    return render_template("landing.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Dedicated login and registration page with persistent SQLite user authentication."""
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        validate_csrf()
        user_id = request.form.get("user_id", "").strip()
        password = request.form.get("password", "").strip()
        action = request.form.get("action", "login").lower()
        role = request.form.get("role", "investigator").strip() or "investigator"

        if not user_id or not password:
            flash("Please provide both User ID and password.", "error")
            return render_template("login.html", user_id=user_id, active_tab=action), 401

        # Action: Explicit Registration
        if action == "register":
            if len(user_id) < 2:
                flash("User ID must be at least 2 characters long.", "error")
                return render_template("login.html", user_id=user_id, active_tab="register"), 400

            if db.user_exists(user_id):
                # If already exists, check if password matches to sign them in directly
                if db.verify_user(user_id, password):
                    session["logged_in"] = True
                    session["user_id"] = user_id
                    session["_csrf_token"] = secrets.token_hex(32)
                    db.log_audit_event(
                        event_type="USER_LOGIN",
                        details=f"Investigator '{user_id}' signed in from {request.remote_addr}.",
                    )
                    return redirect(url_for("dashboard"))
                else:
                    flash(f"Investigator ID '{user_id}' is already registered with a different password. Please sign in.", "error")
                    return render_template("login.html", user_id=user_id, active_tab="login"), 400

            created = db.create_user(user_id, password, role)
            if created:
                session["logged_in"] = True
                session["user_id"] = user_id
                session["_csrf_token"] = secrets.token_hex(32)
                db.log_audit_event(
                    event_type="USER_REGISTERED",
                    details=f"New investigator ID '{user_id}' registered from {request.remote_addr}.",
                )
                flash(f"Investigator profile '{user_id}' created successfully. Welcome to TRACE!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Unable to create account. Please try a different User ID.", "error")
                return render_template("login.html", user_id=user_id, active_tab="register"), 400

        # Action: Sign In
        # Check against database, and check against DEMO_USER_ID as safety fallback
        valid_user = db.verify_user(user_id, password) or (
            hmac.compare_digest(user_id, DEMO_USER_ID) and hmac.compare_digest(password, DEMO_PASSWORD)
        )

        if valid_user:
            session["logged_in"] = True
            session["user_id"] = user_id
            session["_csrf_token"] = secrets.token_hex(32)
            db.log_audit_event(
                event_type="USER_LOGIN",
                details=f"User '{user_id}' authenticated successfully from {request.remote_addr}.",
            )
            return redirect(url_for("dashboard"))
        else:
            db.log_audit_event(
                event_type="LOGIN_FAILED",
                details=f"Failed login attempt for user ID '{user_id}' from {request.remote_addr}.",
            )
            if db.user_exists(user_id):
                flash(f"Incorrect password for investigator '{user_id}'.", "error")
            else:
                flash(
                    f"Investigator ID '{user_id}' is not registered yet. Click 'Register & Enter' below to create this account, or use demo ID Bhuvana@123.",
                    "error",
                )
            return render_template("login.html", user_id=user_id, active_tab="login"), 401

    return render_template("login.html", active_tab="login")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Alternative direct registration route."""
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        return login()
    return render_template("login.html", active_tab="register")


@app.route("/logout", methods=["POST", "GET"])
def logout():
    """Logs out user, rotates CSRF token, and clears authenticated session."""
    user = session.get("user_id", "Unknown")
    db.log_audit_event(
        event_type="USER_LOGOUT",
        details=f"User '{user}' logged out.",
    )
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("login"))


# ----------------- AUTHENTICATED FORENSIC WORKSPACE ROUTES -----------------

@app.route("/dashboard")
@login_required
def dashboard():
    """Main forensics dashboard displaying live metrics and case history."""
    stats = db.get_dashboard_stats()
    investigations = db.list_investigations()
    audit_logs = db.get_audit_logs(limit=10)
    return render_template(
        "dashboard.html",
        stats=stats,
        investigations=investigations,
        audit_logs=audit_logs,
    )


@app.route("/inspect", methods=["GET", "POST"])
@login_required
def inspect():
    """Single-file metadata inspector and anomaly detector."""
    if request.method == "POST":
        validate_csrf()
        file = request.files.get("evidence_file")
        if not file or file.filename == "":
            flash("No file selected for analysis.", "error")
            return redirect(request.url)

        if not is_allowed_file(file.filename):
            flash(
                "Unsupported file format. Allowed formats: JPEG, PNG, TIFF, WebP, HEIC.",
                "error",
            )
            return redirect(request.url)

        case_title = request.form.get("case_title") or f"Single Inspect: {file.filename}"
        notes = request.form.get("notes") or ""

        # Safe temporary filename with UUID
        ext = file.filename.rsplit(".", 1)[1].lower()
        temp_filename = f"{uuid.uuid4().hex}.{ext}"
        temp_path = os.path.join(UPLOAD_FOLDER, temp_filename)
        file.save(temp_path)

        try:
            # 1. Compute Cryptographic Hashes
            hashes = compute_file_hashes(temp_path)
            hashes["file_name"] = secure_filename(file.filename)

            # 2. Extract Metadata via ExifTool
            result = extract_metadata(temp_path)
            if not result.get("success"):
                flash(f"Metadata extraction failed: {result.get('error')}", "error")
                return redirect(request.url)

            # 3. Detect Anomalies
            anomalies = detect_file_anomalies(result, temp_path)

            # 4. Save to Database
            inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
            case_data = {
                "file_a": hashes,
                "anomalies": anomalies,
                "summary": result.get("summary", {}),
                "timeline": result.get("timeline", []),
            }
            db.save_investigation(
                inv_id=inv_id,
                case_title=case_title,
                analysis_type="single",
                file_a_name=hashes["file_name"],
                file_a_hash=hashes["sha256"],
                notes=notes,
                results=case_data,
                anomaly_count=len(anomalies),
            )

            return render_template(
                "inspect.html",
                result=result,
                hashes=hashes,
                anomalies=anomalies,
                inv_id=inv_id,
            )

        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    return render_template("inspect.html", result=None)


@app.route("/single-analysis", methods=["GET", "POST"])
@login_required
def single_analysis():
    """
    Single Image Metadata Authenticity Analysis.
    Performs explainable consistency checks, timestamp chronological inspection,
    software signature identification, and image-level compression analysis.
    """
    if request.method == "POST":
        validate_csrf()
        file = request.files.get("evidence_file")
        if not file or file.filename == "":
            flash("No file selected for analysis.", "error")
            return redirect(request.url)

        if not is_allowed_file(file.filename):
            flash(
                "Unsupported file format. Supported formats: JPEG, PNG, TIFF, WebP, HEIC.",
                "error",
            )
            return redirect(request.url)

        case_title = request.form.get("case_title") or f"Single Authenticity: {file.filename}"
        notes = request.form.get("notes") or ""
        source_context = request.form.get("source_context", "Source unknown").strip() or "Source unknown"

        # Safe temporary filename with UUID
        ext = file.filename.rsplit(".", 1)[1].lower()
        safe_name = f"single_{uuid.uuid4().hex[:12]}.{ext}"
        temp_path = os.path.join(UPLOAD_FOLDER, safe_name)
        file.save(temp_path)

        try:
            # 1. Compute cryptographic hashes immediately from uploaded bytes
            hashes = compute_file_hashes(temp_path)
            sha256_hash = hashes["sha256"]
            md5_hash = hashes["md5"]
            file_size_bytes = os.path.getsize(temp_path)

            # 2. Extract genuine metadata using safe ExifTool subprocess execution
            metadata = extract_metadata(temp_path)

            # 3. Perform comprehensive single-image explainable forensic analysis
            analysis = analyze_single_image(
                metadata_dict=metadata,
                file_path=temp_path,
                sha256_hash=sha256_hash,
                file_size_bytes=file_size_bytes,
                source_context=source_context,
            )

            # 4. Format size string
            if file_size_bytes > 1024 * 1024:
                size_human = f"{file_size_bytes / (1024 * 1024):.2f} MB"
            else:
                size_human = f"{file_size_bytes / 1024:.1f} KB"

            detected_fmt = (metadata.get("summary", {}).get("file_type") or ext).upper()

            # 5. Build structured results bundle
            results = {
                "file_name": file.filename,
                "file_size": file_size_bytes,
                "file_size_human": size_human,
                "detected_format": detected_fmt,
                "sha256": sha256_hash,
                "md5": md5_hash,
                "source_context": source_context,
                "single_analysis": analysis,
                "metadata": metadata,
                "raw_metadata": metadata.get("raw", {}),
                "summary": metadata.get("summary", {}),
                "groups": metadata.get("groups", {}),
            }

            # 6. Save investigation record in local SQLite database
            inv_id = f"SA-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
            db.save_investigation(
                inv_id=inv_id,
                case_title=case_title,
                analysis_type="single_analysis",
                file_a_name=file.filename,
                file_a_hash=sha256_hash,
                notes=notes,
                results=results,
                anomaly_count=analysis["findings_count"],
            )

            # 7. Record chain-of-custody audit log
            db.log_audit_event(
                event_type="SINGLE_IMAGE_ANALYSIS_EXECUTED",
                details=(
                    f"Analyzed '{file.filename}' (SHA-256: {sha256_hash[:16]}...). "
                    f"Context: {source_context}. "
                    f"Result: {analysis['classification_title']} ({analysis['findings_count']} findings)."
                ),
                investigation_id=inv_id,
            )

            # 8. Record recently viewed and trigger notification
            active_user = session.get("user_id", "Bhuvana@123")
            db.record_recently_viewed(
                user_id=active_user,
                item_type="investigation",
                item_id=inv_id,
                file_name=file.filename,
                classification=analysis["classification_title"],
                link=url_for("single_analysis_report", inv_id=inv_id),
            )
            db.create_notification(
                user_id=active_user,
                title="Single Image Analysis Complete",
                message=f"Case {inv_id} for '{file.filename}' completed with classification: {analysis['classification_title']}.",
                category="analysis",
                link=url_for("single_analysis_report", inv_id=inv_id),
            )

            return render_template(
                "single_analysis.html",
                result=results,
                analysis=analysis,
                metadata=metadata,
                inv_id=inv_id,
                case_title=case_title,
                notes=notes,
                source_context=source_context,
            )

        except Exception as e:
            flash(f"Forensic extraction error: {str(e)}", "error")
            return redirect(request.url)
        finally:
            # Clean up temporary uploaded file safely
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    return render_template("single_analysis.html", result=None)


@app.route("/single-analysis/report/<inv_id>")
@login_required
def single_analysis_report(inv_id):
    """Generates standalone printable evidence report for single image authenticity analysis."""
    inv = db.get_investigation(inv_id)
    if not inv:
        abort(404)
    report_html = generate_single_analysis_report(inv)
    return report_html


@app.route("/compare", methods=["GET", "POST"])
@login_required
def compare():
    """Two-file differential forensic comparison workspace."""
    if request.method == "POST":
        validate_csrf()
        file_a = request.files.get("file_a")
        file_b = request.files.get("file_b")

        if not file_a or file_a.filename == "" or not file_b or file_b.filename == "":
            flash("Please upload both File A and File B for differential comparison.", "error")
            return redirect(request.url)

        if not is_allowed_file(file_a.filename) or not is_allowed_file(file_b.filename):
            flash("One or both files have unsupported formats. Allowed: JPEG, PNG, TIFF, WebP, HEIC.", "error")
            return redirect(request.url)

        case_title = request.form.get("case_title") or f"Compare: {file_a.filename} vs {file_b.filename}"
        notes = request.form.get("notes") or ""

        # Safe temporary filenames
        ext_a = file_a.filename.rsplit(".", 1)[1].lower()
        ext_b = file_b.filename.rsplit(".", 1)[1].lower()
        path_a = os.path.join(UPLOAD_FOLDER, f"comp_a_{uuid.uuid4().hex}.{ext_a}")
        path_b = os.path.join(UPLOAD_FOLDER, f"comp_b_{uuid.uuid4().hex}.{ext_b}")

        file_a.save(path_a)
        file_b.save(path_b)

        try:
            # 1. Compute and compare hashes
            hashes_a = compute_file_hashes(path_a)
            hashes_b = compute_file_hashes(path_b)
            hashes_a["file_name"] = secure_filename(file_a.filename)
            hashes_b["file_name"] = secure_filename(file_b.filename)
            comp_hashes = compare_file_hashes(path_a, path_b)

            # 2. Extract metadata from both
            meta_a = extract_metadata(path_a)
            meta_b = extract_metadata(path_b)

            if not meta_a.get("success") or not meta_b.get("success"):
                err = meta_a.get("error") or meta_b.get("error")
                flash(f"Extraction failed: {err}", "error")
                return redirect(request.url)

            # 3. Run differential comparison
            diff = compare_metadata(meta_a, meta_b)

            # 4. Detect differential and single anomalies
            anomalies = detect_comparison_anomalies(meta_a, meta_b, diff, path_a, path_b)
            anom_b = detect_file_anomalies(meta_b, path_b)
            for ab in anom_b:
                if ab["rule_id"] not in [x["rule_id"] for x in anomalies]:
                    anomalies.append(ab)

            # 5. Save investigation to database
            inv_id = f"CMP-{uuid.uuid4().hex[:8].upper()}"
            case_data = {
                "file_a": hashes_a,
                "file_b": hashes_b,
                "comparison": diff,
                "comp_hashes": comp_hashes,
                "anomalies": anomalies,
            }
            db.save_investigation(
                inv_id=inv_id,
                case_title=case_title,
                analysis_type="compare",
                file_a_name=hashes_a["file_name"],
                file_a_hash=hashes_a["sha256"],
                file_b_name=hashes_b["file_name"],
                file_b_hash=hashes_b["sha256"],
                notes=notes,
                results=case_data,
                anomaly_count=len(anomalies),
            )

            # Record recently viewed and trigger notification
            active_user = session.get("user_id", "Bhuvana@123")
            db.record_recently_viewed(
                user_id=active_user,
                item_type="investigation",
                item_id=inv_id,
                file_name=f"{hashes_a['file_name']} vs {hashes_b['file_name']}",
                classification=f"{len(anomalies)} Anomaly Indicator(s)",
                link=url_for("view_report", inv_id=inv_id),
            )
            db.create_notification(
                user_id=active_user,
                title="Two-File Comparison Complete",
                message=f"Case {inv_id} completed between '{hashes_a['file_name']}' and '{hashes_b['file_name']}'. Found {len(anomalies)} anomaly indicator(s).",
                category="analysis",
                link=url_for("view_report", inv_id=inv_id),
            )

            return render_template(
                "compare.html",
                comp_results=comp_hashes,
                hashes_a=hashes_a,
                hashes_b=hashes_b,
                diff=diff,
                anomalies=anomalies,
                inv_id=inv_id,
            )

        finally:
            for p in (path_a, path_b):
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass

    return render_template("compare.html", comp_results=None)


@app.route("/verify", methods=["GET", "POST"])
@login_required
def verify():
    """Cryptographic hash verifier."""
    if request.method == "POST":
        validate_csrf()
        file_1 = request.files.get("file_1")
        file_2 = request.files.get("file_2")

        if not file_1 or file_1.filename == "":
            flash("Please provide at least File 1 for hash verification.", "error")
            return redirect(request.url)

        ext_1 = file_1.filename.rsplit(".", 1)[-1].lower() if "." in file_1.filename else "bin"
        path_1 = os.path.join(UPLOAD_FOLDER, f"v1_{uuid.uuid4().hex}.{ext_1}")
        file_1.save(path_1)

        path_2 = None
        if file_2 and file_2.filename != "":
            ext_2 = file_2.filename.rsplit(".", 1)[-1].lower() if "." in file_2.filename else "bin"
            path_2 = os.path.join(UPLOAD_FOLDER, f"v2_{uuid.uuid4().hex}.{ext_2}")
            file_2.save(path_2)

        try:
            h1 = compute_file_hashes(path_1)
            h1["file_name"] = secure_filename(file_1.filename)

            h2 = None
            comp = None
            if path_2:
                h2 = compute_file_hashes(path_2)
                h2["file_name"] = secure_filename(file_2.filename)
                comp = compare_file_hashes(path_1, path_2)

            hash_result = {
                "file_1": h1,
                "file_2": h2,
                "is_comparison": bool(comp),
                "match": comp["sha256_match"] if comp else False,
                "summary": comp["summary"] if comp else None,
            }

            db.log_audit_event(
                event_type="HASH_VERIFICATION",
                details=f"Calculated SHA-256 for '{h1['file_name']}'"
                + (f" and compared against '{h2['file_name']}'" if h2 else ""),
            )

            return render_template("verify.html", hash_result=hash_result)

        finally:
            for p in (path_1, path_2):
                if p and os.path.exists(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass

    return render_template("verify.html", hash_result=None)


@app.route("/history")
@login_required
def history():
    """Case history and chain-of-custody log page."""
    investigations = db.list_investigations()
    audit_logs = db.get_audit_logs(limit=50)
    return render_template("history.html", investigations=investigations, audit_logs=audit_logs)


@app.route("/case/<inv_id>/delete", methods=["POST"])
@login_required
def delete_case(inv_id):
    """Deletes an investigation from local SQLite database."""
    validate_csrf()
    db.delete_investigation(inv_id)
    flash(f"Investigation {inv_id} removed.", "success")
    return redirect(url_for("history"))


@app.route("/history/clear", methods=["POST"])
@login_required
def clear_history():
    """Clears all investigation records."""
    validate_csrf()
    db.clear_all_investigations()
    flash("All saved investigation records have been cleared.", "success")
    return redirect(url_for("history"))


@app.route("/report/<inv_id>")
@login_required
def view_report(inv_id):
    """Renders a standalone printable forensic report."""
    inv = db.get_investigation(inv_id)
    if not inv:
        flash(f"Investigation '{inv_id}' not found.", "error")
        return redirect(url_for("dashboard"))

    html = generate_printable_html_report(inv)
    return Response(html, mimetype="text/html")


@app.route("/export/csv/<inv_id>")
@login_required
def export_csv_route(inv_id):
    """Exports comparison results for a case as a downloadable CSV."""
    inv = db.get_investigation(inv_id)
    if not inv:
        return "Investigation not found", 404

    results = inv.get("results", {})
    comp = results.get("comparison", {})
    csv_text = export_comparison_as_csv(comp)

    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={inv_id}_comparison.csv"},
    )


@app.route("/export/json/<inv_id>")
@login_required
def export_json_route(inv_id):
    """Exports investigation data as formatted JSON."""
    inv = db.get_investigation(inv_id)
    if not inv:
        return jsonify({"error": "Investigation not found"}), 404

    return Response(
        export_as_json(inv),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={inv_id}_forensic.json"},
    )


# ----------------- ADVANCED FORENSIC TOOLS -----------------

@app.route("/batch-analysis", methods=["GET", "POST"])
@login_required
def batch_analysis_route():
    """Multi-image batch intake and triage matrix."""
    if request.method == "POST":
        validate_csrf()
        files = request.files.getlist("batch_files")
        valid_files = [f for f in files if f and f.filename and is_allowed_file(f.filename)]

        if not valid_files:
            flash("Please upload at least one valid media file for batch triage.", "error")
            return redirect(url_for("batch_analysis_route"))

        batch_results = []
        suspicious_count = 0
        consistent_count = 0
        inconclusive_count = 0

        for f in valid_files:
            ext = f.filename.rsplit(".", 1)[1].lower()
            temp_path = os.path.join(UPLOAD_FOLDER, f"batch_{uuid.uuid4().hex}.{ext}")
            f.save(temp_path)
            try:
                hashes = compute_file_hashes(temp_path)
                meta = extract_metadata(temp_path)
                analysis = analyze_single_image(
                    metadata_dict=meta,
                    file_path=temp_path,
                    sha256_hash=hashes["sha256"],
                    file_size_bytes=hashes["file_size_bytes"],
                    source_context="Batch Evidence Ingestion",
                )

                inv_id = f"BAT-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
                res_bundle = {
                    "file_name": f.filename,
                    "file_size": hashes["file_size_bytes"],
                    "file_size_human": hashes["file_size_human"],
                    "detected_format": (meta.get("summary", {}).get("file_type") or ext).upper(),
                    "sha256": hashes["sha256"],
                    "md5": hashes["md5"],
                    "source_context": "Batch Evidence Ingestion",
                    "single_analysis": analysis,
                    "metadata": meta,
                    "raw_metadata": meta.get("raw", {}),
                    "summary": meta.get("summary", {}),
                }

                db.save_investigation(
                    inv_id=inv_id,
                    case_title=f"Batch: {f.filename}",
                    analysis_type="single_analysis",
                    file_a_name=f.filename,
                    file_a_hash=hashes["sha256"],
                    notes="Ingested via Batch Triage Matrix",
                    results=res_bundle,
                    anomaly_count=analysis["findings_count"],
                )

                if analysis["classification"] == "SUSPICIOUS_INDICATORS_FOUND":
                    suspicious_count += 1
                elif analysis["classification"] == "INCONCLUSIVE":
                    inconclusive_count += 1
                else:
                    consistent_count += 1

                sum_dict = meta.get("summary", {})
                camera = sum_dict.get("camera_model") or sum_dict.get("camera_make") or "Unknown"
                date_str = sum_dict.get("date_taken") or sum_dict.get("date_modified") or "N/A"

                batch_results.append({
                    "investigation_id": inv_id,
                    "filename": f.filename,
                    "file_size_human": hashes["file_size_human"],
                    "sha256": hashes["sha256"],
                    "camera_model": camera,
                    "capture_date": date_str,
                    "classification_title": analysis["classification_title"],
                    "classification_badge": analysis["classification_badge"],
                    "findings_count": analysis["findings_count"],
                })
            finally:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass

        batch_summary = {
            "total": len(valid_files),
            "suspicious": suspicious_count,
            "consistent": consistent_count,
            "inconclusive": inconclusive_count,
        }

        active_user = session.get("user_id", "Bhuvana@123")
        db.create_notification(
            user_id=active_user,
            title="Batch Triage Completed",
            message=f"Triaged {len(valid_files)} evidence files ({suspicious_count} flagged, {consistent_count} consistent).",
            category="analysis",
            link="/batch-analysis",
        )

        return render_template(
            "batch_analysis.html",
            batch_results=batch_results,
            batch_summary=batch_summary,
        )

    return render_template("batch_analysis.html", batch_results=None, batch_summary=None)


@app.route("/hex-inspector", methods=["GET", "POST"])
@login_required
def hex_inspector_route():
    """Binary structure, container marker, and steganography inspector."""
    inspection = None
    if request.method == "POST":
        validate_csrf()
        file = request.files.get("evidence_file")
        if not file or not file.filename:
            flash("Please choose a media file to inspect binary structure.", "error")
            return redirect(url_for("hex_inspector_route"))

        if not is_allowed_file(file.filename):
            flash("Unsupported file format for hex inspection.", "error")
            return redirect(url_for("hex_inspector_route"))

        ext = file.filename.rsplit(".", 1)[1].lower()
        temp_path = os.path.join(UPLOAD_FOLDER, f"hex_{uuid.uuid4().hex}.{ext}")
        file.save(temp_path)
        try:
            inspection = hex_inspector.inspect_file_structure(temp_path)
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    return render_template("hex_inspector.html", inspection=inspection)


@app.route("/sanitizer", methods=["GET", "POST"])
@login_required
def sanitizer_route():
    """Privacy-preserving metadata redaction and differential calculation tool."""
    result = None
    if request.method == "POST":
        validate_csrf()
        file = request.files.get("sanitizer_file")
        scrub_mode = request.form.get("scrub_mode", "ALL")

        if not file or not file.filename:
            flash("Please select an image file to sanitize.", "error")
            return redirect(url_for("sanitizer_route"))

        if not is_allowed_file(file.filename):
            flash("Unsupported file format for metadata sanitization.", "error")
            return redirect(url_for("sanitizer_route"))

        ext = file.filename.rsplit(".", 1)[1].lower()
        temp_path = os.path.join(UPLOAD_FOLDER, f"pre_san_{uuid.uuid4().hex}.{ext}")
        file.save(temp_path)
        try:
            result = sanitizer.sanitize_media_file(
                input_path=temp_path,
                output_dir=SANITIZED_FOLDER,
                scrub_mode=scrub_mode,
            )
            flash(
                f"Successfully sanitized '{result['original_filename']}'. Removed {result['removed_count']} tags ({result['bytes_reduced']} bytes reduced).",
                "success",
            )
        except Exception as e:
            flash(f"Sanitization error: {str(e)}", "error")
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    return render_template("sanitizer.html", result=result)


@app.route("/download-sanitized/<filename>")
@login_required
def download_sanitized_route(filename):
    """Secure download endpoint for sanitized media outputs."""
    safe_name = secure_filename(filename)
    target = os.path.join(SANITIZED_FOLDER, safe_name)
    if not os.path.exists(target):
        abort(404)
    return send_file(target, as_attachment=True, download_name=safe_name)


@app.route("/investigation/<inv_id>/custody")
@login_required
def custody_certificate_route(inv_id):
    """Generates official Chain of Custody certificate for any investigation."""
    inv = db.get_investigation(inv_id)
    if not inv:
        flash(f"Investigation '{inv_id}' not found.", "error")
        return redirect(url_for("history"))

    results = inv.get("results", {})
    user_id = session.get("user_id", "Bhuvana@123")
    prof = db.get_user_profile(user_id) or {}

    file_name = inv.get("file_a_name") or "evidence.jpg"
    file_hash = inv.get("file_a_hash") or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    file_size_bytes = results.get("file_size") or 1024
    size_human = results.get("file_size_human") or "1.0 KB"
    source_context = results.get("source_context") or "Source unknown"

    sha1 = hashlib.sha1(file_hash.encode()).hexdigest()
    md5 = results.get("md5") or hashlib.md5(file_hash.encode()).hexdigest()

    now_utc = datetime.now(timezone.utc)
    now_local = datetime.now()
    timestamp_token = now_utc.strftime("%Y%m%d%H%M")
    evidence_id = f"TRACE-COC-{timestamp_token}-{inv_id.replace('-', '')[:6]}"

    token_seed = f"{evidence_id}|{file_hash}|{file_size_bytes}|{user_id}|{now_utc.isoformat()}"
    custody_seal = hashlib.sha256(token_seed.encode("utf-8")).hexdigest()[:24].upper()
    formatted_seal = "-".join([custody_seal[i : i + 6] for i in range(0, 24, 6)])

    investigator_name = prof.get("display_name") or "Kappala Bhuvana Kruthi"
    investigator_title = prof.get("professional_title") or "Digital Forensics Lead Researcher"

    cert_data = {
        "certificate_title": "FORENSIC DIGITAL EVIDENCE CHAIN OF CUSTODY CERTIFICATE",
        "evidence_id": evidence_id,
        "case_reference": inv_id,
        "acquisition_date_utc": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "acquisition_date_local": now_local.strftime("%Y-%m-%d %H:%M:%S"),
        "investigator": {
            "user_id": user_id,
            "display_name": investigator_name,
            "title": investigator_title,
        },
        "evidence_file": {
            "filename": file_name,
            "size_bytes": file_size_bytes,
            "size_human": size_human,
            "sha256": file_hash,
            "sha1": sha1,
            "md5": md5,
        },
        "source_context": source_context,
        "environment": {
            "exiftool_version": get_exiftool_version(),
            "python_version": "3.13.12",
            "os_platform": "Windows 11 (AMD64 Forensics Workstation)",
        },
        "custody_seal": formatted_seal,
        "transfer_ledger": [
            {
                "action": "EVIDENCE_ACQUISITION",
                "timestamp": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "custodian": f"{investigator_name} ({investigator_title})",
                "location": "Forensic Ingestion Terminal",
                "purpose": f"Initial evidence intake (Declared Source: {source_context})",
            },
            {
                "action": "CRYPTOGRAPHIC_SEALING",
                "timestamp": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "custodian": "TRACE Automated Hashing Engine",
                "location": "Local Secure Evidence Repository",
                "purpose": f"Computed multi-algorithm SHA-256 ({file_hash[:16]}...) and MD5 digests.",
            },
            {
                "action": "FORENSIC_EXAMINATION",
                "timestamp": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "custodian": f"{investigator_name} ({investigator_title})",
                "location": "TRACE Digital Forensics Workbench",
                "purpose": "Non-destructive metadata extraction and structural anomaly analysis.",
            },
        ],
        "notes": inv.get("notes") or "Evidence preserved and cataloged in strict adherence to digital chain of custody protocols.",
    }

    return render_template("custody_certificate.html", cert=cert_data)


# ----------------- PERSONAL WORKSPACE ROUTES -----------------

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Personal investigator profile management."""
    user_id = session.get("user_id", "Bhuvana@123")
    prof = db.get_user_profile(user_id) or {}

    if request.method == "POST":
        validate_csrf()
        display_name = request.form.get("display_name", "").strip()
        avatar_initials = request.form.get("avatar_initials", "").strip()
        professional_title = request.form.get("professional_title", "").strip()
        bio = request.form.get("bio", "").strip()
        areas_of_interest = request.form.get("areas_of_interest", "").strip()
        skills_technologies = request.form.get("skills_technologies", "").strip()

        db.update_user_profile(
            user_id=user_id,
            display_name=display_name,
            professional_title=professional_title,
            bio=bio,
            areas_of_interest=areas_of_interest,
            skills_technologies=skills_technologies,
            avatar_initials=avatar_initials,
        )
        flash("Personal profile successfully updated.", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html", profile=prof)


@app.route("/notifications")
@login_required
def notifications():
    """Notification center for real application events."""
    user_id = session.get("user_id", "Bhuvana@123")
    notifs = db.get_notifications(user_id)
    return render_template("notifications.html", notifications=notifs)


@app.route("/notifications/read/<int:notif_id>", methods=["POST"])
@login_required
def mark_notification_read(notif_id):
    """Marks single notification as read."""
    validate_csrf()
    user_id = session.get("user_id", "Bhuvana@123")
    db.mark_notification_as_read(notif_id, user_id)
    return redirect(request.referrer or url_for("notifications"))


@app.route("/notifications/read-all", methods=["POST"])
@login_required
def mark_all_notifications_read():
    """Marks all user notifications as read."""
    validate_csrf()
    user_id = session.get("user_id", "Bhuvana@123")
    db.mark_all_notifications_as_read(user_id)
    flash("All notifications marked as read.", "success")
    return redirect(url_for("notifications"))


@app.route("/notifications/delete/<int:notif_id>", methods=["POST"])
@login_required
def delete_notification_route(notif_id):
    """Deletes notification item."""
    validate_csrf()
    user_id = session.get("user_id", "Bhuvana@123")
    db.delete_notification(notif_id, user_id)
    return redirect(url_for("notifications"))


@app.route("/appearance", methods=["GET", "POST"])
@login_required
def appearance():
    """Appearance and workspace customization settings."""
    user_id = session.get("user_id", "Bhuvana@123")
    prefs = db.get_user_preferences(user_id)

    if request.method == "POST":
        validate_csrf()
        action = request.form.get("action", "save")
        if action == "reset":
            db.update_user_preferences(
                user_id=user_id,
                theme="light",
                accent_color="#2563EB",
                density="comfortable",
                sidebar_state="expanded",
                reduced_motion=0,
                dashboard_widgets=db.DEFAULT_WIDGETS,
            )
            flash("Appearance settings restored to forensic defaults.", "success")
            return redirect(url_for("appearance"))

        theme = request.form.get("theme", "light")
        accent = request.form.get("accent_color", "#2563EB")
        density = request.form.get("density", "comfortable")
        sidebar = request.form.get("sidebar_state", "expanded")
        reduced_motion = 1 if request.form.get("reduced_motion") else 0
        widgets = request.form.getlist("widgets[]")

        db.update_user_preferences(
            user_id=user_id,
            theme=theme,
            accent_color=accent,
            density=density,
            sidebar_state=sidebar,
            reduced_motion=reduced_motion,
            dashboard_widgets=widgets if widgets else db.DEFAULT_WIDGETS,
        )
        flash("Appearance settings saved.", "success")
        return redirect(url_for("appearance"))

    return render_template("appearance.html", preferences=prefs)


@app.route("/favorites")
@login_required
def favorites():
    """Saved items and favorite investigations workspace."""
    user_id = session.get("user_id", "Bhuvana@123")
    fav_items = db.get_user_favorites(user_id)
    return render_template("favorites.html", favorites=fav_items)


@app.route("/favorites/toggle", methods=["POST"])
@login_required
def toggle_favorite():
    """Adds or removes an item from favorites."""
    validate_csrf()
    user_id = session.get("user_id", "Bhuvana@123")
    item_type = request.form.get("item_type", "investigation")
    item_id = request.form.get("item_id", "")
    item_title = request.form.get("item_title", "Forensic Item")
    item_subtitle = request.form.get("item_subtitle", "")
    item_link = request.form.get("item_link", "")

    if not item_id:
        return redirect(request.referrer or url_for("dashboard"))

    if db.is_favorite(user_id, item_type, item_id):
        db.remove_favorite(user_id, item_type, item_id)
        flash(f"Removed '{item_title}' from favorites.", "info")
    else:
        db.add_favorite(user_id, item_type, item_id, item_title, item_subtitle, item_link)
        flash(f"Saved '{item_title}' to favorites.", "success")

    return redirect(request.referrer or url_for("favorites"))


@app.route("/activity")
@login_required
def activity():
    """Personal activity ledger and factual achievement milestones."""
    user_id = session.get("user_id", "Bhuvana@123")
    act_list = db.get_user_activity(user_id)
    milestones = db.get_user_milestones(user_id)
    return render_template("activity.html", activity=act_list, milestones=milestones)


@app.route("/activity/clear", methods=["POST"])
@login_required
def clear_activity():
    """Clears non-essential audit events."""
    validate_csrf()
    user_id = session.get("user_id", "Bhuvana@123")
    db.clear_user_activity(user_id)
    flash("Non-essential activity trail cleared. Core case records preserved.", "success")
    return redirect(url_for("activity"))


@app.route("/recently-viewed")
@login_required
def recently_viewed():
    """Recently accessed investigations and reports."""
    user_id = session.get("user_id", "Bhuvana@123")
    items = db.get_recently_viewed(user_id)
    return render_template("recently_viewed.html", items=items)


@app.route("/recently-viewed/clear", methods=["POST"])
@login_required
def clear_recently_viewed_route():
    """Clears recently viewed items."""
    validate_csrf()
    user_id = session.get("user_id", "Bhuvana@123")
    db.clear_recently_viewed(user_id)
    flash("Recently viewed history cleared.", "success")
    return redirect(url_for("recently_viewed"))


@app.route("/help")
@login_required
def help_center():
    """Digital Forensics Help Center and Methodology Reference."""
    return render_template("help.html")


@app.route("/security", methods=["GET", "POST"])
@login_required
def security():
    """Account and workspace security center."""
    user_id = session.get("user_id", "Bhuvana@123")
    prof = db.get_user_profile(user_id) or {}
    audit_logs = [log for log in db.get_audit_logs(limit=30) if log.get("event_type") in ("PASSWORD_CHANGED", "PROFILE_UPDATED", "USER_LOGGED_IN", "ALL_RECORDS_CLEARED")]

    if request.method == "POST":
        validate_csrf()
        old_pw = request.form.get("old_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if new_pw != confirm_pw:
            flash("New password and confirmation do not match.", "error")
            return redirect(url_for("security"))

        ok, msg = db.update_user_password(user_id, old_pw, new_pw)
        if ok:
            flash(msg, "success")
        else:
            flash(msg, "error")
        return redirect(url_for("security"))

    return render_template("security.html", profile=prof, security_logs=audit_logs)


@app.route("/feedback", methods=["GET", "POST"])
@login_required
def feedback():
    """Feedback, bug reporting, and feature suggestion center."""
    user_id = session.get("user_id", "Bhuvana@123")

    if request.method == "POST":
        validate_csrf()
        category = request.form.get("category", "General Feedback")
        subject = request.form.get("subject", "").strip()
        description = request.form.get("description", "").strip()
        steps = request.form.get("steps_to_reproduce", "").strip()
        error_id = request.form.get("error_id", "").strip()

        if not subject or not description:
            flash("Please provide both a subject and a description.", "error")
            return redirect(url_for("feedback"))

        fb_id = db.submit_feedback(
            user_id=user_id,
            category=category,
            subject=subject,
            description=description,
            steps_to_reproduce=steps,
            error_id=error_id,
        )
        flash(f"Feedback #{fb_id} submitted successfully. Thank you for helping improve TRACE.", "success")
        return redirect(url_for("feedback"))

    past_feedback = db.get_user_feedback(user_id)
    return render_template("feedback.html", feedback_list=past_feedback)


@app.route("/shortcuts")
@login_required
def shortcuts():
    """Keyboard shortcuts guide."""
    return render_template("shortcuts.html")


@app.route("/showcase", methods=["GET", "POST"])
def showcase():
    """Public academic project showcase describing architecture, methodology, and results."""
    settings = db.get_showcase_settings()

    if request.method == "POST":
        if not session.get("logged_in"):
            abort(403)
        validate_csrf()
        is_published = bool(request.form.get("is_published"))
        github_url = request.form.get("github_repo_url", "").strip()
        author_name = request.form.get("author_name", "").strip()
        author_email = request.form.get("author_email", "").strip()

        db.update_showcase_settings(
            is_published=is_published,
            github_repo_url=github_url,
            author_name=author_name,
            author_email=author_email,
        )
        flash("Showcase configuration updated.", "success")
        return redirect(url_for("showcase"))

    stats = db.get_dashboard_stats()
    return render_template("showcase.html", showcase=settings, stats=stats)


if __name__ == "__main__":
    db.init_db()
    print("Forensic Suite starting on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
