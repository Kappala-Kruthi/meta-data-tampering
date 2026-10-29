"""
Vercel Serverless Function Entry Point for TRACE Digital Forensics Workbench.
Loads the Flask WSGI application instance and initializes storage.
"""

import os
import sys

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

# Expose WSGI app for Vercel's Python runtime
app = app
