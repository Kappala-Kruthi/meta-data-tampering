"""
tests/verify_live.py
Direct HTTP verification against the live running Flask server.
"""
import urllib.request
import urllib.parse
import http.cookiejar
import re
import os

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# 1. Login GET & extract csrf token
resp = opener.open('http://127.0.0.1:5000/login')
html = resp.read().decode('utf-8')
csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', html)
csrf_token = csrf_match.group(1) if csrf_match else ''

# 2. Login POST
login_data = urllib.parse.urlencode({
    'user_id': 'Bhuvana@123',
    'password': '123',
    'action': 'login',
    'csrf_token': csrf_token
}).encode('utf-8')
req = urllib.request.Request('http://127.0.0.1:5000/login', data=login_data)
resp = opener.open(req)
print(f"Login response status: {resp.status}")

# 3. Check Dashboard
resp = opener.open('http://127.0.0.1:5000/dashboard')
dash_html = resp.read().decode('utf-8')
assert 'Single Image Analysis' in dash_html, "Dashboard missing Single Image Analysis card"
assert 'without requiring an original copy' in dash_html, "Dashboard missing required description"
print("1. Dashboard Single Image Analysis Card: VERIFIED")

# 4. Check Single Analysis GET
resp = opener.open('http://127.0.0.1:5000/single-analysis')
sa_html = resp.read().decode('utf-8')
assert 'Single Image Metadata Authenticity Analysis' in sa_html
assert 'evidence_file' in sa_html
print("2. Dedicated Single Image Workspace: VERIFIED")

# Extract fresh CSRF token from authenticated session
csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', sa_html)
csrf_token = csrf_match.group(1) if csrf_match else ''

# 5. POST Upload using multipart/form-data
boundary = '----ForensicBoundary7MA4YWxkTrZu0gW'
sample_path = os.path.join(os.path.dirname(__file__), 'samples', 'sample_edited.jpg')
with open(sample_path, 'rb') as f:
    img_bytes = f.read()

body = (
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="csrf_token"\r\n\r\n{csrf_token}\r\n'
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="case_title"\r\n\r\nLive Verification Case\r\n'
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="notes"\r\n\r\nAutomated live endpoint test\r\n'
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="evidence_file"; filename="sample_edited.jpg"\r\n'
    f'Content-Type: image/jpeg\r\n\r\n'
).encode('utf-8') + img_bytes + f'\r\n--{boundary}--\r\n'.encode('utf-8')

req = urllib.request.Request(
    'http://127.0.0.1:5000/single-analysis',
    data=body,
    headers={'Content-Type': f'multipart/form-data; boundary={boundary}'}
)
resp = opener.open(req)
res_html = resp.read().decode('utf-8')

assert 'Suspicious Indicators Found' in res_html, "Expected Suspicious classification banner"
assert 'Photoshop' in res_html, "Expected Photoshop editor finding"
assert 'Cryptographic Evidence Fingerprint' in res_html
assert 'Checks Performed Matrix' in res_html
assert 'Metadata Completeness' in res_html
assert 'Image-Level Compression' in res_html
print("3. Single Analysis Execution & Forensic Dashboard: VERIFIED")

# 6. Extract generated Case ID
match = re.search(r'SA-\d{8}-[A-F0-9]+', res_html)
assert match, "Generated Case ID not found in HTML"
inv_id = match.group(0)
print(f"4. Investigation Recorded: {inv_id}")

# 7. Verify Printable Evidence Report
resp = opener.open(f'http://127.0.0.1:5000/single-analysis/report/{inv_id}')
report_html = resp.read().decode('utf-8')
assert 'TRACE: Single Image Metadata Authenticity Report' in report_html
assert 'Forensic Transparency' in report_html
assert inv_id in report_html
print("5. Standalone Printable Report: VERIFIED")

# 8. Verify JSON Export
resp = opener.open(f'http://127.0.0.1:5000/export/json/{inv_id}')
assert resp.status == 200
json_data = resp.read().decode('utf-8')
assert inv_id in json_data
print("6. Formatted JSON Export: VERIFIED")

print("\n>>> ALL LIVE FORENSIC WORKFLOWS VALIDATED ON RUNNING SERVER! <<<")
