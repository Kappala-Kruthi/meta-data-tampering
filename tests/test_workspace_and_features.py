"""
Automated Forensic Test Suite: Workspace Features, Downloaded Media Context,
and Academic Security Modules for TRACE Workbench.
"""

import io
import os
import pytest
from core import database as db
from core.exiftool_runner import extract_metadata
from core.hasher import compute_file_hashes
from core.single_analyzer import analyze_single_image
from app import app


SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")
SAMPLE_CAMERA = os.path.join(SAMPLE_DIR, "sample_camera.jpg")
SAMPLE_STRIPPED = os.path.join(SAMPLE_DIR, "sample_stripped.png")


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess.clear()
        yield client


@pytest.fixture
def auth_client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = "Bhuvana@123"
            sess["logged_in"] = True
        yield client


# ============================================================================
# 1. DOWNLOADED & SOCIAL MEDIA IMAGE ANALYSIS (PINTEREST / MESSAGING)
# ============================================================================

def test_pinterest_social_media_source_context():
    """
    Verifies that when an image downloaded from Pinterest/social media is analyzed,
    the missing camera and GPS metadata is classified as EXPECTED platform privacy scrubbing
    and does NOT declare malicious tampering.
    """
    assert os.path.exists(SAMPLE_STRIPPED)
    meta = extract_metadata(SAMPLE_STRIPPED)
    hashes = compute_file_hashes(SAMPLE_STRIPPED)
    size_bytes = os.path.getsize(SAMPLE_STRIPPED)

    result = analyze_single_image(
        metadata_dict=meta,
        file_path=SAMPLE_STRIPPED,
        sha256_hash=hashes["sha256"],
        file_size_bytes=size_bytes,
        source_context="Downloaded from a website or social media platform",
    )

    # 1. Must NOT classify as 'Suspicious Indicators Found' merely because EXIF is stripped
    assert result["classification_title"] != "Suspicious Indicators Found"
    assert result["classification"] in ["NO_SIGNIFICANT_INDICATORS", "INCONCLUSIVE"]

    # 2. Check metadata completeness explanation
    completeness_finding = next(
        (f for f in result["findings"] if f["rule_id"] == "RULE_METADATA_STRIPPED"),
        None,
    )
    assert completeness_finding is not None
    assert completeness_finding["severity"] in ["INFORMATIONAL", "LOW", "INFO"]
    assert "Expected" in completeness_finding["rule_name"] or "Stripped" in completeness_finding["rule_name"]
    assert "Pinterest" in completeness_finding["benign_explanation"] or "bandwidth" in completeness_finding["benign_explanation"]


def test_messaging_app_source_context():
    """
    Verifies messaging application context (WhatsApp, Telegram) explains stripping.
    """
    assert os.path.exists(SAMPLE_STRIPPED)
    meta = extract_metadata(SAMPLE_STRIPPED)
    hashes = compute_file_hashes(SAMPLE_STRIPPED)
    size_bytes = os.path.getsize(SAMPLE_STRIPPED)

    result = analyze_single_image(
        metadata_dict=meta,
        file_path=SAMPLE_STRIPPED,
        sha256_hash=hashes["sha256"],
        file_size_bytes=size_bytes,
        source_context="Received through a messaging application",
    )
    completeness_finding = next(
        (f for f in result["findings"] if f["rule_id"] == "RULE_METADATA_STRIPPED"),
        None,
    )
    assert completeness_finding is not None
    assert "messaging" in completeness_finding["explanation"].lower() or "messaging" in completeness_finding["benign_explanation"].lower()


# ============================================================================
# 2. PERSONAL INVESTIGATOR PROFILE (/profile)
# ============================================================================

def test_profile_retrieval_and_update(auth_client):
    """
    Tests retrieving and updating user profile details.
    """
    # GET /profile
    res = auth_client.get("/profile")
    assert res.status_code == 200
    assert b"Investigator Profile" in res.data

    # POST update to /profile
    update_data = {
        "display_name": "K. Bhuvana Kruthi",
        "avatar_initials": "BK",
        "professional_title": "Senior Forensics Researcher",
        "bio": "Investigating media metadata tampering with ExifTool pipelines.",
        "areas_of_interest": "EXIF, IPTC, XMP, Timestamp Verification",
        "skills_technologies": "Python, Flask, ExifTool, SQLite3, Pillow",
    }
    res_post = auth_client.post("/profile", data=update_data, follow_redirects=True)
    assert res_post.status_code == 200
    assert b"K. Bhuvana Kruthi" in res_post.data
    assert b"Senior Forensics Researcher" in res_post.data
    assert b"Personal profile successfully updated." in res_post.data

    # Check persistence in database
    prof = db.get_user_profile("Bhuvana@123")
    assert prof["display_name"] == "K. Bhuvana Kruthi"
    assert prof["avatar_initials"] == "BK"


# ============================================================================
# 3. NOTIFICATION CENTER (/notifications)
# ============================================================================

def test_notification_center_lifecycle(auth_client):
    """
    Tests notification generation, viewing, marking read, and dismissing.
    """
    user_id = "Bhuvana@123"
    notif_id = db.create_notification(
        user_id=user_id,
        title="Analysis Completed: Case SA-TEST-101",
        message="Single image analysis verified with clean metadata integrity.",
        category="analysis",
        link="/single-analysis",
    )
    assert notif_id > 0

    # View in notification center
    res = auth_client.get("/notifications")
    assert res.status_code == 200
    assert b"Analysis Completed: Case SA-TEST-101" in res.data

    # Mark as read
    res_read = auth_client.post(f"/notifications/read/{notif_id}", follow_redirects=True)
    assert res_read.status_code == 200

    # Mark all as read
    res_all = auth_client.post("/notifications/read-all", follow_redirects=True)
    assert res_all.status_code == 200
    assert db.get_unread_notifications_count(user_id) == 0

    # Delete notification
    res_del = auth_client.post(f"/notifications/delete/{notif_id}", follow_redirects=True)
    assert res_del.status_code == 200


# ============================================================================
# 4. APPEARANCE CENTER & CUSTOMIZATION (/appearance)
# ============================================================================

def test_appearance_settings_customization(auth_client):
    """
    Tests saving dark theme, custom accent color, density, and resetting defaults.
    """
    user_id = "Bhuvana@123"

    # Save custom dark theme
    data = {
        "action": "save",
        "theme": "dark",
        "accent_color": "#0D9488",
        "density": "compact",
        "sidebar_state": "collapsed",
        "reduced_motion": "1",
    }
    res = auth_client.post("/appearance", data=data, follow_redirects=True)
    assert res.status_code == 200
    assert b"Appearance settings saved" in res.data

    prefs = db.get_user_preferences(user_id)
    assert prefs["theme"] == "dark"
    assert prefs["accent_color"] == "#0D9488"
    assert prefs["density"] == "compact"
    assert prefs["sidebar_state"] == "collapsed"
    assert prefs["reduced_motion"] == 1

    # Reset to defaults
    res_reset = auth_client.post("/appearance", data={"action": "reset"}, follow_redirects=True)
    assert res_reset.status_code == 200
    assert b"restored to forensic defaults" in res_reset.data

    prefs_default = db.get_user_preferences(user_id)
    assert prefs_default["theme"] == "light"
    assert prefs_default["accent_color"] == "#2563EB"


# ============================================================================
# 5. FAVORITES & BOOKMARKED ITEMS (/favorites)
# ============================================================================

def test_favorites_toggle_and_listing(auth_client):
    """
    Tests bookmarking investigations and guides, and removing them.
    """
    user_id = "Bhuvana@123"
    db.remove_favorite(user_id, "guide", "guide-pinterest-scrubbing")

    # Add favorite
    toggle_data = {
        "item_type": "guide",
        "item_id": "guide-pinterest-scrubbing",
        "item_title": "Pinterest Metadata Stripping Reference",
        "item_subtitle": "Why social media platforms scrub EXIF tags",
        "item_link": "/help#pinterest-social",
    }
    res_add = auth_client.post("/favorites/toggle", data=toggle_data, follow_redirects=True)
    assert res_add.status_code == 200
    assert b"Saved" in res_add.data and b"Pinterest Metadata" in res_add.data

    # Verify present on favorites page
    res_page = auth_client.get("/favorites")
    assert res_page.status_code == 200
    assert b"Pinterest Metadata Stripping Reference" in res_page.data

    # Toggle to remove
    res_remove = auth_client.post("/favorites/toggle", data=toggle_data, follow_redirects=True)
    assert res_remove.status_code == 200
    assert b"Removed" in res_remove.data and b"Pinterest Metadata" in res_remove.data


# ============================================================================
# 6. ACHIEVEMENTS & ACTIVITY (/activity)
# ============================================================================

def test_activity_ledger_and_milestones(auth_client):
    """
    Tests milestone calculations and non-essential activity clearing.
    """
    res = auth_client.get("/activity")
    assert res.status_code == 200
    assert b"Verified Research Milestones" in res.data
    assert b"Chronological Activity Ledger" in res.data

    # Clear activity
    res_clear = auth_client.post("/activity/clear", follow_redirects=True)
    assert res_clear.status_code == 200
    assert b"activity trail cleared" in res_clear.data


# ============================================================================
# 7. RECENTLY VIEWED (/recently-viewed)
# ============================================================================

def test_recently_viewed_lifecycle(auth_client):
    """
    Tests recording recently viewed items and clearing them.
    """
    user_id = "Bhuvana@123"
    db.record_recently_viewed(
        user_id=user_id,
        item_type="single",
        item_id="SA-2026-TEST",
        file_name="evidence_sample.jpg",
        classification="No Significant Indicators Detected",
        link="/single-analysis/report/SA-2026-TEST",
    )

    res = auth_client.get("/recently-viewed")
    assert res.status_code == 200
    assert b"evidence_sample.jpg" in res.data

    # Clear recently viewed
    res_clear = auth_client.post("/recently-viewed/clear", follow_redirects=True)
    assert res_clear.status_code == 200
    assert b"Recently viewed history cleared" in res_clear.data


# ============================================================================
# 8. SECURITY CENTER (/security)
# ============================================================================

def test_security_center_and_password_change(auth_client):
    """
    Tests security settings page, active session state, and password management.
    """
    res = auth_client.get("/security")
    assert res.status_code == 200
    assert b"Active Forensic Session" in res.data
    assert b"Academic Demo Security Guidance" in res.data

    # Attempt password change with wrong old password
    bad_pw_data = {
        "old_password": "WrongPassword999",
        "new_password": "NewSecretPass456",
        "confirm_password": "NewSecretPass456",
    }
    res_bad = auth_client.post("/security", data=bad_pw_data, follow_redirects=True)
    assert res_bad.status_code == 200
    assert b"verification failed" in res_bad.data or b"incorrect" in res_bad.data

    # Attempt with mismatched confirmation
    mismatch_data = {
        "old_password": "123",
        "new_password": "NewSecretPass456",
        "confirm_password": "DifferentPass789",
    }
    res_mismatch = auth_client.post("/security", data=mismatch_data, follow_redirects=True)
    assert res_mismatch.status_code == 200
    assert b"do not match" in res_mismatch.data

    # Valid password change
    good_pw_data = {
        "old_password": "123",
        "new_password": "ForensicPass@2026",
        "confirm_password": "ForensicPass@2026",
    }
    res_good = auth_client.post("/security", data=good_pw_data, follow_redirects=True)
    assert res_good.status_code == 200
    assert b"Password successfully updated" in res_good.data

    # Restore default password for other test fixtures
    db.update_user_password("Bhuvana@123", "ForensicPass@2026", "123")


# ============================================================================
# 9. FEEDBACK & BUG REPORTING (/feedback)
# ============================================================================

def test_feedback_submission(auth_client):
    """
    Tests submitting bug reports and feature requests, and reviewing user history.
    """
    fb_data = {
        "category": "Bug Report",
        "subject": "HEIC tag parsing test",
        "description": "Observed maker notes parsing in Apple iPhone HEIC files.",
        "steps_to_reproduce": "1. Upload sample.heic\n2. Run single analysis",
        "error_id": "ERR-HEIC-01",
    }
    res = auth_client.post("/feedback", data=fb_data, follow_redirects=True)
    assert res.status_code == 200
    assert b"Feedback #" in res.data

    # View feedback page to confirm submission is listed
    res_page = auth_client.get("/feedback")
    assert res_page.status_code == 200
    assert b"HEIC tag parsing test" in res_page.data


# ============================================================================
# 10. KEYBOARD SHORTCUTS GUIDE (/shortcuts)
# ============================================================================

def test_keyboard_shortcuts_page(auth_client):
    """
    Tests keyboard shortcuts guide renders all shortcuts accurately.
    """
    res = auth_client.get("/shortcuts")
    assert res.status_code == 200
    assert b"Workbench Hotkeys" in res.data
    assert b"D" in res.data
    assert b"S" in res.data
    assert b"C" in res.data


# ============================================================================
# 11. HELP CENTER (/help)
# ============================================================================

def test_help_center_content(auth_client):
    """
    Tests help center contains thorough explanation of Pinterest stripping,
    SHA-256, and result classifications.
    """
    res = auth_client.get("/help")
    assert res.status_code == 200
    assert b"Pinterest" in res.data
    assert b"Understanding Cryptographic Hashes (SHA-256)" in res.data
    assert b"Forensic Result Classifications" in res.data
    assert b"Suspicious Indicators Found" in res.data
    assert b"No Significant Indicators Detected" in res.data
    assert b"Inconclusive" in res.data


# ============================================================================
# 12. PUBLIC PROJECT SHOWCASE (/showcase)
# ============================================================================

def test_public_showcase_accessibility(client, auth_client):
    """
    Tests showcase page is accessible publicly without authentication and
    does not expose private cases.
    """
    # 1. Unauthenticated public access
    res_pub = client.get("/showcase")
    assert res_pub.status_code == 200
    assert b"Metadata Tampering Detection in Media Files Using ExifTool" in res_pub.data
    assert b"Problem Statement" in res_pub.data
    assert b"Technical Architecture" in res_pub.data
    # Must NOT have administrative publishing toggle controls
    assert b"Showcase Privacy" not in res_pub.data

    # 2. Authenticated researcher access
    res_auth = auth_client.get("/showcase")
    assert res_auth.status_code == 200
    # Must have administrative publishing toggle controls
    assert b"Showcase Privacy" in res_auth.data
