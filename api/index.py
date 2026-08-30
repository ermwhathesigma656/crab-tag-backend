"""
Vercel serverless entry point.

vercel.json rewrites every request to /api/index, which means Vercel hands the
WSGI app the *rewritten* path rather than the one the caller asked for. Flask
then matches nothing and 404s on every route.

RestoreOriginalPath puts the caller's path back before Flask routes on it. It
reads the candidates Vercel is known to expose, falls back to stripping the
/api/index prefix, and leaves the request untouched if none apply - so if the
platform ever starts passing the real path through, this becomes a no-op rather
than a second bug.
"""
import os
import sys
from urllib.parse import unquote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app as flask_app  # noqa: E402

_FUNCTION_PATH = "/api/index"

# Checked in order; the first that yields a usable path wins.
_ORIGINAL_PATH_HEADERS = (
    "HTTP_X_VERCEL_ORIGINAL_PATHNAME",
    "HTTP_X_VERCEL_ORIGINAL_PATH",
    "HTTP_X_ORIGINAL_PATH",
    "HTTP_X_FORWARDED_URI",
    "HTTP_X_REWRITE_URL",
)


def _clean(value):
    if not value:
        return None
    path = urlsplit(unquote(value)).path or value
    if not path.startswith("/"):
        path = "/" + path
    # A header echoing the function path tells us nothing.
    if path.rstrip("/") == _FUNCTION_PATH:
        return None
    return path


class RestoreOriginalPath(object):
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        current = environ.get("PATH_INFO", "")

        if current.rstrip("/") == _FUNCTION_PATH or current in ("", "/"):
            for key in _ORIGINAL_PATH_HEADERS:
                restored = _clean(environ.get(key))
                if restored:
                    environ["PATH_INFO"] = restored
                    break

        # Vercel serves the function at /api/index; anything nested under that
        # is the real path with the function prefix glued on the front.
        elif current.startswith(_FUNCTION_PATH + "/"):
            environ["PATH_INFO"] = current[len(_FUNCTION_PATH):]

        return self.wsgi_app(environ, start_response)


flask_app.wsgi_app = RestoreOriginalPath(flask_app.wsgi_app)

app = flask_app
