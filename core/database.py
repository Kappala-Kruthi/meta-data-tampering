"""
core/database.py
Lightweight SQLite local persistence for forensic investigations and chain-of-custody audit logs.
Does not transmit data externally; operates entirely offline on the local system.
"""

from datetime import datetime
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional
from werkzeug.security import check_password_hash, generate_password_hash

if os.environ.get("VERCEL"):
    DB_DIR = "/tmp/data"
else:
    DB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
DB_PATH = os.path.join(DB_DIR, "investigations.db")


def get_connection() -> sqlite3.Connection:
    """Creates a connection with row factory enabled."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initializes tables if they do not exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Investigations Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                case_title TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                file_a_name TEXT,
                file_a_hash TEXT,
                file_b_name TEXT,
                file_b_hash TEXT,
                notes TEXT,
                results_json TEXT,
                anomaly_count INTEGER DEFAULT 0
            )
        """)

        # Chain of Custody Audit Log Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL,
                investigation_id TEXT,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE SET NULL
            )
        """)

        # Forensic Investigators (Users) Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'investigator',
                created_at TEXT NOT NULL,
                display_name TEXT,
                professional_title TEXT,
                bio TEXT,
                areas_of_interest TEXT,
                skills_technologies TEXT,
                portfolio_links TEXT,
                avatar_initials TEXT
            )
        """)

        # Safe column migrations for existing users table
        existing_cols = [c[1] for c in cursor.execute("PRAGMA table_info(users)").fetchall()]
        new_cols = [
            ("display_name", "TEXT"),
            ("professional_title", "TEXT"),
            ("bio", "TEXT"),
            ("areas_of_interest", "TEXT"),
            ("skills_technologies", "TEXT"),
            ("portfolio_links", "TEXT"),
            ("avatar_initials", "TEXT"),
        ]
        for col_name, col_type in new_cols:
            if col_name not in existing_cols:
                try:
                    cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
                except Exception:
                    pass

        # User Appearance & Workspace Preferences Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_preferences (
                user_id TEXT PRIMARY KEY,
                theme TEXT DEFAULT 'light',
                accent_color TEXT DEFAULT '#2563EB',
                density TEXT DEFAULT 'comfortable',
                sidebar_state TEXT DEFAULT 'expanded',
                reduced_motion INTEGER DEFAULT 0,
                dashboard_widgets_json TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)

        # Notification Center Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                category TEXT NOT NULL,
                link TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)

        # Feedback & Bug Reports Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                category TEXT NOT NULL,
                subject TEXT NOT NULL,
                description TEXT NOT NULL,
                steps_to_reproduce TEXT,
                error_id TEXT,
                status TEXT DEFAULT 'Under Review',
                created_at TEXT NOT NULL
            )
        """)

        # Favorites & Bookmarked Items Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS favorites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                item_type TEXT NOT NULL,
                item_id TEXT NOT NULL,
                item_title TEXT NOT NULL,
                item_subtitle TEXT,
                item_link TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, item_type, item_id)
            )
        """)

        # Recently Viewed Items Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recently_viewed (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                item_type TEXT NOT NULL,
                item_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                classification TEXT,
                link TEXT NOT NULL,
                viewed_at TEXT NOT NULL
            )
        """)

        # Public Project Showcase Settings Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS showcase_settings (
                id INTEGER PRIMARY KEY,
                is_published INTEGER DEFAULT 1,
                github_repo_url TEXT,
                author_name TEXT,
                author_email TEXT,
                updated_at TEXT
            )
        """)

        # Pre-seed default demonstration user if not already registered
        cursor.execute("SELECT 1 FROM users WHERE user_id = ?", ("Bhuvana@123",))
        if not cursor.fetchone():
            default_links = json.dumps([
                {"title": "Project Repository", "url": "https://github.com/Kappala-Kruthi/meta-data-tampering"},
                {"title": "Centurion University", "url": "https://cutm.ac.in"},
            ])
            cursor.execute(
                """
                INSERT INTO users (
                    user_id, password_hash, role, created_at,
                    display_name, professional_title, bio,
                    areas_of_interest, skills_technologies, portfolio_links, avatar_initials
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "Bhuvana@123",
                    generate_password_hash("123"),
                    "lead_investigator",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "Kappala Bhuvana Kruthi",
                    "Digital Forensics Researcher & Lead Analyst",
                    "Undergraduate digital forensics researcher at Centurion University of Technology and Management (CUTM). Specializing in metadata integrity, ExifTool automation, and forensic anomaly detection.",
                    "Digital Media Forensics, Metadata Inconsistency Detection, Cryptographic Hashing, Timestamp Verification",
                    "Python, ExifTool, Flask, Pillow, SQLite, Cryptography, Linux/Windows Forensics",
                    default_links,
                    "KB",
                ),
            )
        else:
            # Update default demonstration user profile if not yet populated
            cursor.execute("SELECT display_name FROM users WHERE user_id = ?", ("Bhuvana@123",))
            row = cursor.fetchone()
            if row and not row["display_name"]:
                default_links = json.dumps([
                    {"title": "Project Repository", "url": "https://github.com/Kappala-Kruthi/meta-data-tampering"},
                    {"title": "Centurion University", "url": "https://cutm.ac.in"},
                ])
                cursor.execute(
                    """
                    UPDATE users SET
                        display_name = ?,
                        professional_title = ?,
                        bio = ?,
                        areas_of_interest = ?,
                        skills_technologies = ?,
                        portfolio_links = ?,
                        avatar_initials = ?
                    WHERE user_id = ?
                    """,
                    (
                        "Kappala Bhuvana Kruthi",
                        "Digital Forensics Researcher & Lead Analyst",
                        "Undergraduate digital forensics researcher at Centurion University of Technology and Management (CUTM). Specializing in metadata integrity, ExifTool automation, and forensic anomaly detection.",
                        "Digital Media Forensics, Metadata Inconsistency Detection, Cryptographic Hashing, Timestamp Verification",
                        "Python, ExifTool, Flask, Pillow, SQLite, Cryptography, Linux/Windows Forensics",
                        default_links,
                        "KB",
                        "Bhuvana@123",
                    ),
                )

        # Pre-seed default showcase settings if empty
        cursor.execute("SELECT 1 FROM showcase_settings WHERE id = 1")
        if not cursor.fetchone():
            cursor.execute(
                """
                INSERT INTO showcase_settings (id, is_published, github_repo_url, author_name, author_email, updated_at)
                VALUES (1, 1, 'https://github.com/Kappala-Kruthi/meta-data-tampering', 'Kappala Bhuvana Kruthi', 'bhuvanakruthi.cutm@gmail.com', ?)
                """,
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
            )

        conn.commit()


def create_user(user_id: str, password: str, role: str = "investigator") -> bool:
    """Registers a new investigator account with a secure password hash."""
    init_db()
    clean_user = user_id.strip()
    if not clean_user or not password:
        return False
    pw_hash = generate_password_hash(password)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (user_id, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (clean_user, pw_hash, role, now_str),
            )
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False


def verify_user(user_id: str, password: str) -> bool:
    """Verifies investigator credentials against the SQLite database."""
    init_db()
    clean_user = user_id.strip()
    if not clean_user or not password:
        return False
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE user_id = ?", (clean_user,))
        row = cursor.fetchone()
        if row and check_password_hash(row["password_hash"], password):
            return True
    return False


def user_exists(user_id: str) -> bool:
    """Checks whether an investigator user ID is registered in the database."""
    init_db()
    clean_user = user_id.strip()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE user_id = ?", (clean_user,))
        return cursor.fetchone() is not None


def list_users() -> List[Dict[str, Any]]:
    """Retrieves all registered forensic investigators."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, user_id, role, created_at FROM users ORDER BY id ASC")
        return [dict(row) for row in cursor.fetchall()]


def log_audit_event(event_type: str, details: str, investigation_id: Optional[str] = None) -> None:
    """Records an application-level chain-of-custody event."""
    init_db()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO audit_logs (timestamp, event_type, details, investigation_id) VALUES (?, ?, ?, ?)",
            (now_str, event_type, details, investigation_id),
        )
        conn.commit()


def save_investigation(
    inv_id: str,
    case_title: str,
    analysis_type: str,
    file_a_name: Optional[str],
    file_a_hash: Optional[str],
    file_b_name: Optional[str] = None,
    file_b_hash: Optional[str] = None,
    notes: str = "",
    results: Optional[Dict[str, Any]] = None,
    anomaly_count: int = 0,
) -> str:
    """Saves an investigation record and logs the event."""
    init_db()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results_str = json.dumps(results or {})

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO investigations (
                id, case_title, analysis_type, created_at,
                file_a_name, file_a_hash, file_b_name, file_b_hash,
                notes, results_json, anomaly_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                inv_id, case_title, analysis_type, now_str,
                file_a_name, file_a_hash, file_b_name, file_b_hash,
                notes, results_str, anomaly_count,
            ),
        )
        conn.commit()

    log_audit_event(
        event_type="INVESTIGATION_CREATED",
        details=f"Created {analysis_type} investigation: '{case_title}' (ID: {inv_id})",
        investigation_id=inv_id,
    )
    return inv_id


def list_investigations() -> List[Dict[str, Any]]:
    """Returns all investigations ordered by creation date descending."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, case_title, analysis_type, created_at, file_a_name, file_a_hash, file_b_name, file_b_hash, notes, anomaly_count FROM investigations ORDER BY created_at DESC"
        )
        rows = cursor.fetchall()
        return [dict(r) for r in rows]


def get_investigation(inv_id: str) -> Optional[Dict[str, Any]]:
    """Fetches a single investigation with full parsed results."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,))
        row = cursor.fetchone()
        if not row:
            return None
        data = dict(row)
        try:
            data["results"] = json.loads(data.get("results_json") or "{}")
        except json.JSONDecodeError:
            data["results"] = {}
        return data


def delete_investigation(inv_id: str) -> bool:
    """Deletes an investigation and logs the deletion."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))
        deleted = cursor.rowcount > 0
        conn.commit()

    if deleted:
        log_audit_event(
            event_type="INVESTIGATION_DELETED",
            details=f"Deleted investigation record ID: {inv_id}",
            investigation_id=None,
        )
    return deleted


def clear_all_investigations() -> None:
    """Clears all records."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM investigations")
        conn.commit()
    log_audit_event(event_type="ALL_RECORDS_CLEARED", details="All saved investigation records were cleared by user.")


def get_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetches recent audit log entries."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, timestamp, event_type, details, investigation_id FROM audit_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_dashboard_stats() -> Dict[str, int]:
    """Computes genuine, non-fabricated metrics from saved records."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM investigations")
        total_inv = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM investigations WHERE analysis_type = 'single'")
        single_inv = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM investigations WHERE analysis_type = 'compare'")
        compare_inv = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM investigations WHERE analysis_type = 'verify'")
        verify_inv = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM audit_logs")
        total_logs = cursor.fetchone()[0]

        return {
            "total_investigations": total_inv,
            "single_inspections": single_inv,
            "two_file_comparisons": compare_inv,
            "hash_verifications": verify_inv,
            "total_audit_events": total_logs,
        }


# ----------------- USER PROFILE & SECURITY -----------------

def get_user_profile(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full profile for an investigator."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        data = dict(row)
        try:
            data["portfolio_links"] = json.loads(data.get("portfolio_links") or "[]")
        except json.JSONDecodeError:
            data["portfolio_links"] = []
        return data


def update_user_profile(
    user_id: str,
    display_name: str,
    professional_title: str,
    bio: str,
    areas_of_interest: str,
    skills_technologies: str,
    portfolio_links: Any = None,
    avatar_initials: Optional[str] = None,
) -> bool:
    """Updates investigator profile fields and persists to database."""
    init_db()
    clean_name = display_name.strip()
    if avatar_initials and avatar_initials.strip():
        initials = avatar_initials.strip().upper()[:4]
    else:
        initials = "".join([part[0].upper() for part in clean_name.split()[:2]]) if clean_name else "IN"
    links_str = "[]" if portfolio_links is None else (json.dumps(portfolio_links) if not isinstance(portfolio_links, str) else portfolio_links)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users SET
                display_name = ?,
                professional_title = ?,
                bio = ?,
                areas_of_interest = ?,
                skills_technologies = ?,
                portfolio_links = ?,
                avatar_initials = ?
            WHERE user_id = ?
            """,
            (
                clean_name,
                professional_title.strip(),
                bio.strip(),
                areas_of_interest.strip(),
                skills_technologies.strip(),
                links_str,
                initials,
                user_id,
            ),
        )
        updated = cursor.rowcount > 0
        conn.commit()

    if updated:
        log_audit_event(
            event_type="PROFILE_UPDATED",
            details=f"Investigator '{user_id}' updated personal profile details.",
        )
    return updated


def update_user_password(user_id: str, old_password: str, new_password: str) -> tuple[bool, str]:
    """Validates old password and sets new PBKDF2-hashed password."""
    init_db()
    if not new_password or len(new_password) < 3:
        return False, "New password must be at least 3 characters long."

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if not row or not check_password_hash(row["password_hash"], old_password):
            return False, "Current password verification failed."

        new_hash = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (new_hash, user_id))
        conn.commit()

    log_audit_event(
        event_type="PASSWORD_CHANGED",
        details=f"Investigator '{user_id}' changed account password.",
    )
    create_notification(
        user_id=user_id,
        title="Password Changed",
        message="Your account password was successfully updated.",
        category="security",
        link="/security",
    )
    return True, "Password successfully updated."


# ----------------- USER PREFERENCES -----------------

DEFAULT_WIDGETS = [
    "summary_stats",
    "quick_actions",
    "recent_investigations",
    "recent_reports",
    "favorites",
    "activity_timeline",
    "help_shortcuts",
]

def get_user_preferences(user_id: str) -> Dict[str, Any]:
    """Retrieves UI and workspace preferences for user."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_preferences WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return {
                "user_id": user_id,
                "theme": "light",
                "accent_color": "#2563EB",
                "density": "comfortable",
                "sidebar_state": "expanded",
                "reduced_motion": 0,
                "dashboard_widgets": DEFAULT_WIDGETS,
            }
        data = dict(row)
        try:
            data["dashboard_widgets"] = json.loads(data.get("dashboard_widgets_json") or "[]") or DEFAULT_WIDGETS
        except json.JSONDecodeError:
            data["dashboard_widgets"] = DEFAULT_WIDGETS
        return data


def update_user_preferences(
    user_id: str,
    theme: str = "light",
    accent_color: str = "#2563EB",
    density: str = "comfortable",
    sidebar_state: str = "expanded",
    reduced_motion: int = 0,
    dashboard_widgets: Optional[List[str]] = None,
) -> bool:
    """Saves user appearance and workspace settings."""
    init_db()
    valid_themes = {"light", "dark", "system"}
    clean_theme = theme if theme in valid_themes else "light"
    clean_accent = accent_color if accent_color.startswith("#") and len(accent_color) in (4, 7) else "#2563EB"
    clean_density = density if density in ("comfortable", "compact") else "comfortable"
    clean_sidebar = sidebar_state if sidebar_state in ("expanded", "collapsed") else "expanded"
    widgets_json = json.dumps(dashboard_widgets or DEFAULT_WIDGETS)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO user_preferences (user_id, theme, accent_color, density, sidebar_state, reduced_motion, dashboard_widgets_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                theme = excluded.theme,
                accent_color = excluded.accent_color,
                density = excluded.density,
                sidebar_state = excluded.sidebar_state,
                reduced_motion = excluded.reduced_motion,
                dashboard_widgets_json = excluded.dashboard_widgets_json
            """,
            (user_id, clean_theme, clean_accent, clean_density, clean_sidebar, int(bool(reduced_motion)), widgets_json),
        )
        conn.commit()
    return True


# ----------------- NOTIFICATIONS -----------------

def create_notification(
    user_id: str,
    title: str,
    message: str,
    category: str = "system",
    link: Optional[str] = None,
) -> int:
    """Inserts an application event notification."""
    init_db()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO notifications (user_id, title, message, category, link, is_read, created_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (user_id, title, message, category, link, now_str),
        )
        conn.commit()
        return cursor.lastrowid


def get_notifications(user_id: str, limit: int = 40) -> List[Dict[str, Any]]:
    """Retrieves notifications for an investigator."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_unread_notifications_count(user_id: str) -> int:
    """Counts unread notifications."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0", (user_id,))
        return cursor.fetchone()[0]


def mark_notification_as_read(notif_id: int, user_id: str) -> bool:
    """Marks a single notification as read."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?", (notif_id, user_id))
        conn.commit()
        return cursor.rowcount > 0


def mark_all_notifications_as_read(user_id: str) -> bool:
    """Marks all user notifications as read."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user_id,))
        conn.commit()
        return True


def delete_notification(notif_id: int, user_id: str) -> bool:
    """Removes a notification."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM notifications WHERE id = ? AND user_id = ?", (notif_id, user_id))
        conn.commit()
        return cursor.rowcount > 0


# ----------------- FEEDBACK & BUG REPORTING -----------------

def submit_feedback(
    user_id: str,
    category: str,
    subject: str,
    description: str,
    steps_to_reproduce: str = "",
    error_id: str = "",
) -> int:
    """Stores user feedback or bug report."""
    init_db()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO feedback (user_id, category, subject, description, steps_to_reproduce, error_id, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'Under Review', ?)
            """,
            (user_id, category, subject.strip(), description.strip(), steps_to_reproduce.strip(), error_id.strip(), now_str),
        )
        conn.commit()
        feedback_id = cursor.lastrowid

    log_audit_event(
        event_type="FEEDBACK_SUBMITTED",
        details=f"Investigator '{user_id}' submitted {category}: '{subject[:30]}...' (ID: #{feedback_id})",
    )
    create_notification(
        user_id=user_id,
        title="Feedback Received",
        message=f"Thank you. Your {category.lower()} submission (#{feedback_id}) has been recorded.",
        category="feedback",
        link="/feedback",
    )
    return feedback_id


def get_user_feedback(user_id: str) -> List[Dict[str, Any]]:
    """Retrieves all feedback submitted by the current user."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM feedback WHERE user_id = ? ORDER BY id DESC", (user_id,))
        return [dict(r) for r in cursor.fetchall()]


# ----------------- FAVORITES & SAVED ITEMS -----------------

def add_favorite(
    user_id: str,
    item_type: str,
    item_id: str,
    item_title: str,
    item_subtitle: str = "",
    item_link: str = "",
) -> bool:
    """Adds an item to investigator favorites."""
    init_db()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO favorites (user_id, item_type, item_id, item_title, item_subtitle, item_link, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, item_type, item_id, item_title, item_subtitle, item_link, now_str),
            )
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False


def remove_favorite(user_id: str, item_type: str, item_id: str) -> bool:
    """Removes an item from favorites."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM favorites WHERE user_id = ? AND item_type = ? AND item_id = ?",
            (user_id, item_type, item_id),
        )
        conn.commit()
        return cursor.rowcount > 0


def is_favorite(user_id: str, item_type: str, item_id: str) -> bool:
    """Checks if an item is currently favorited."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM favorites WHERE user_id = ? AND item_type = ? AND item_id = ?",
            (user_id, item_type, item_id),
        )
        return cursor.fetchone() is not None


def get_user_favorites(user_id: str) -> List[Dict[str, Any]]:
    """Lists all favorited items for investigator."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM favorites WHERE user_id = ? ORDER BY id DESC", (user_id,))
        return [dict(r) for r in cursor.fetchall()]


# ----------------- RECENTLY VIEWED ITEMS -----------------

def record_recently_viewed(
    user_id: str,
    item_type: str,
    item_id: str,
    file_name: str,
    classification: str = "",
    link: str = "",
) -> None:
    """Tracks viewed investigations and reports without storing raw media."""
    init_db()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM recently_viewed WHERE user_id = ? AND item_type = ? AND item_id = ?",
            (user_id, item_type, item_id),
        )
        cursor.execute(
            """
            INSERT INTO recently_viewed (user_id, item_type, item_id, file_name, classification, link, viewed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, item_type, item_id, file_name, classification, link, now_str),
        )
        conn.commit()


def get_recently_viewed(user_id: str, limit: int = 15) -> List[Dict[str, Any]]:
    """Returns recently accessed cases and reports."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM recently_viewed WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        )
        return [dict(r) for r in cursor.fetchall()]


def clear_recently_viewed(user_id: str) -> bool:
    """Clears investigator's recently viewed list."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM recently_viewed WHERE user_id = ?", (user_id,))
        conn.commit()
        return True


# ----------------- ACTIVITY TIMELINE & MILESTONES -----------------

def get_user_activity(user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Combines investigations, favorites, and audit records into an activity ledger."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp AS activity_time, event_type AS action_type, details, investigation_id
            FROM audit_logs
            ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_user_milestones(user_id: str) -> Dict[str, Any]:
    """Calculates factual achievement milestones based on verified database records."""
    stats = get_dashboard_stats()
    favs = len(get_user_favorites(user_id))
    unreads = get_unread_notifications_count(user_id)
    
    milestones = [
        {
            "id": "MS-01",
            "title": "First Step in Forensic Analysis",
            "description": "Executed your first single-image metadata authenticity inspection.",
            "completed": stats["single_inspections"] > 0,
            "metric": f"{stats['single_inspections']} completed",
        },
        {
            "id": "MS-02",
            "title": "Differential Analyst",
            "description": "Conducted a two-image differential comparison to isolate modified and stripped tags.",
            "completed": stats["two_file_comparisons"] > 0,
            "metric": f"{stats['two_file_comparisons']} completed",
        },
        {
            "id": "MS-03",
            "title": "Cryptographic Integrity Guardian",
            "description": "Computed bit-for-bit SHA-256 digests to verify file integrity.",
            "completed": stats["hash_verifications"] > 0 or stats["total_investigations"] > 0,
            "metric": f"{stats['hash_verifications'] + stats['total_investigations']} verified",
        },
        {
            "id": "MS-04",
            "title": "Chain of Custody Custodian",
            "description": "Logged 10 or more application audit trail events in the local SQLite database.",
            "completed": stats["total_audit_events"] >= 10,
            "metric": f"{stats['total_audit_events']} / 10 events",
        },
        {
            "id": "MS-05",
            "title": "Case Archive Curator",
            "description": "Saved 5 or more investigations and reports in your personal evidence repository.",
            "completed": stats["total_investigations"] >= 5,
            "metric": f"{stats['total_investigations']} / 5 cases",
        },
    ]

    return {
        "stats": stats,
        "favorites_count": favs,
        "unread_notifications": unreads,
        "milestones": milestones,
        "completed_count": sum(1 for m in milestones if m["completed"]),
        "total_milestones": len(milestones),
    }


def clear_user_activity(user_id: str) -> bool:
    """Clears non-essential audit logs."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM audit_logs WHERE event_type NOT IN ('INVESTIGATION_CREATED', 'INVESTIGATION_DELETED')")
        conn.commit()
    return True


# ----------------- SHOWCASE SETTINGS -----------------

def get_showcase_settings() -> Dict[str, Any]:
    """Retrieves showcase publication settings."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM showcase_settings WHERE id = 1")
        row = cursor.fetchone()
        if not row:
            return {
                "id": 1,
                "is_published": 1,
                "github_repo_url": "https://github.com/Kappala-Kruthi/meta-data-tampering",
                "author_name": "Kappala Bhuvana Kruthi",
                "author_email": "bhuvanakruthi.cutm@gmail.com",
            }
        return dict(row)


def update_showcase_settings(is_published: bool, github_repo_url: str, author_name: str, author_email: str) -> bool:
    """Updates showcase configuration."""
    init_db()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE showcase_settings SET
                is_published = ?,
                github_repo_url = ?,
                author_name = ?,
                author_email = ?,
                updated_at = ?
            WHERE id = 1
            """,
            (int(bool(is_published)), github_repo_url.strip(), author_name.strip(), author_email.strip(), now_str),
        )
        conn.commit()
    return True
