"""
Vercel Serverless Function Entry Point for TRACE Digital Forensics Workbench.
Loads the Flask WSGI application instance, initializes storage, and provides
WSGI middleware for dynamic URL path resolution on Vercel's serverless edge.
"""

import os
import sys
from urllib.parse import parse_qs, urlencode

# Ensure project root is in Python sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Set Vercel environment flag
os.environ["VERCEL"] = "1"

from app import app
import core.database as db

# Ensure database tables and pre-seeded user exist in /tmp
db.init_db()


class VercelPathMiddleware:
    """
    WSGI Middleware to restore original request path on Vercel.
    When Vercel rewrites requests to /api/index?__path__=/$1, the WSGI environment
    often receives PATH_INFO = '/api/index' instead of the true requested URL.
    This middleware inspects the dynamic __path__ parameter, restores the correct
    PATH_INFO so Flask's URL routing works seamlessly, and removes __path__ from
    QUERY_STRING so application request.args remain clean.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        query_string = environ.get("QUERY_STRING", "")
        params = parse_qs(query_string, keep_blank_values=True)

        target_path = None
        if "__path__" in params and params["__path__"]:
            target_path = params.pop("__path__")[0]
            if not target_path.startswith("/"):
                target_path = "/" + target_path
            environ["QUERY_STRING"] = urlencode(params, doseq=True)

        if not target_path:
            matched_path = environ.get("HTTP_X_MATCHED_PATH")
            if matched_path and matched_path not in ("/api/index", "/api/index.py", "/api"):
                target_path = matched_path
            else:
                target_path = "/"

        # Normalize any double slashes (e.g. //login -> /login)
        while target_path.startswith("//"):
            target_path = target_path[1:]

        environ["PATH_INFO"] = target_path

        return self.wsgi_app(environ, start_response)


# Apply the path resolution middleware
app.wsgi_app = VercelPathMiddleware(app.wsgi_app)

# Expose WSGI app for Vercel's Python runtime
app = app
