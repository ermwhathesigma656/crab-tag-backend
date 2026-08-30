"""
Vercel serverless entry point.

Thin on purpose. The path-restoring middleware lives in app.py, not here,
because Vercel imports app.py directly - proved in production, where app.py's
404 handler ran while middleware installed from this file did not. Anything
that must always apply belongs next to the app it wraps.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app  # noqa: E402,F401
