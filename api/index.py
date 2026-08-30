"""
Vercel serverless entry point.

vercel.json rewrites every request to /api/index, and Vercel hands the WSGI app
that rewritten path with no header carrying the original - verified empirically:
a 404 diagnostic showed PATH_INFO as "/api/index" and none of
x-vercel-original-pathname, x-forwarded-uri or x-rewrite-url present.

So the rewrite passes the caller's path explicitly:

    "destination": "/api/index?__original_path=/$1"

and this middleware moves it back into PATH_INFO before Flask routes on it,
then strips the parameter so handlers never see it.

Trusting a client-supplied path here is not a privilege escalation: it only
selects which route runs, and every protected route still checks its own key.
Requesting /api/index?__original_path=/admin/stats is exactly as authorised as
requesting /admin/stats.
"""
import os
import sys
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app as flask_app  # noqa: E402

_FUNCTION_PATH = "/api/index"
_PATH_PARAM = "__original_path"


def _sanitise(value):
    """Path only: no scheme, no host, no query, always rooted."""
    if not value:
        return None
    path = urlsplit(unquote(value)).path
    if not path:
        return None
    if not path.startswith("/"):
        path = "/" + path
    if path.rstrip("/") == _FUNCTION_PATH:
        return None
    return path


class RestoreOriginalPath(object):
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        current = environ.get("PATH_INFO", "")

        if current.rstrip("/") == _FUNCTION_PATH or current in ("", "/"):
            pairs = parse_qsl(environ.get("QUERY_STRING", ""),
                              keep_blank_values=True)
            restored = None
            remaining = []
            for key, value in pairs:
                if key == _PATH_PARAM and restored is None:
                    restored = _sanitise(value)
                else:
                    remaining.append((key, value))
            if restored:
                environ["PATH_INFO"] = restored
                # Handlers should see the caller's query string, not ours.
                environ["QUERY_STRING"] = urlencode(remaining)

        # Direct hits on the function path keep working if the rewrite is ever
        # removed: /api/index/health -> /health
        elif current.startswith(_FUNCTION_PATH + "/"):
            environ["PATH_INFO"] = current[len(_FUNCTION_PATH):]

        return self.wsgi_app(environ, start_response)


flask_app.wsgi_app = RestoreOriginalPath(flask_app.wsgi_app)

app = flask_app
