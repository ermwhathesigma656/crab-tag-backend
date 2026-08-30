"""
Session tokens.

Stateless HMAC tokens so the game can carry proof of trust between calls, but
every token is also backed by a row in `sessions` - the row is what lets us
revoke a session mid-game. A token that verifies but has no live row is dead.

Format: base64url(payload_json).base64url(hmac_sha256)
No JWT dependency; the payload is ours and the algorithm is not negotiable,
which sidesteps the entire family of "alg: none" mistakes.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time

from config import config


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64u(text):
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def new_session_id():
    return secrets.token_urlsafe(24)


def issue(session_id, playfab_id, trust, ttl=None):
    ttl = ttl or config.SESSION_TTL_SECONDS
    payload = {
        "sid": session_id,
        "pid": playfab_id,
        "trust": trust,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl,
    }
    body = _b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = hmac.new(
        config.SESSION_SIGNING_KEY.encode(), body.encode(), hashlib.sha256
    ).digest()
    return "%s.%s" % (body, _b64u(sig))


def verify(token):
    """
    Returns the payload dict, or None if the token is malformed, forged or
    expired. Constant-time comparison, because timing a signature check is a
    genuinely practical attack over a network.
    """
    if not token or not config.SESSION_SIGNING_KEY:
        return None
    try:
        body, sig = token.split(".", 1)
    except ValueError:
        return None

    expected = hmac.new(
        config.SESSION_SIGNING_KEY.encode(), body.encode(), hashlib.sha256
    ).digest()
    try:
        given = _unb64u(sig)
    except Exception:
        return None
    if not hmac.compare_digest(expected, given):
        return None

    try:
        payload = json.loads(_unb64u(body))
    except Exception:
        return None

    if not isinstance(payload, dict) or payload.get("exp", 0) < time.time():
        return None
    return payload
