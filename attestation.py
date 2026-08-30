"""
Meta Device / Application Integrity verification.

This is the only evidence in the whole system a modified client cannot forge:
Meta signs the token, and we verify it server-to-server with the app secret.
Everything else the client tells us is, at best, a hint.

Never verify an attestation token on the client. Never trust claims the client
decoded for us - we decode them ourselves, from the response Meta signed.
"""
import base64
import binascii
import json
import secrets

import requests

from config import config

VERIFY_URL = "https://graph.oculus.com/platform_integrity/verify"
NONCE_URL = "https://graph.oculus.com/user_nonce_validate"


class AttestationError(Exception):
    """Raised when we cannot reach Meta. Never a reason to punish a player."""


def make_challenge_nonce():
    """
    Base64URL, unpadded, 43 chars - inside Meta's 22..172 requirement.
    secrets.token_urlsafe is CSPRNG-backed, unlike the Math.random() fallback
    the CloudScript version has to live with.
    """
    return secrets.token_urlsafe(32)


def _b64url_decode(data):
    if not data:
        return b""
    pad = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + pad)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("claims were not valid base64url: %s" % exc)


def verify_integrity_token(token):
    """
    Returns the decoded claims dict.

    Raises AttestationError for transport problems (our fault - degrade open)
    and ValueError for a token Meta actively rejected (their fault - degrade
    closed). Keeping those two apart is the difference between an outage and a
    mass false-positive.
    """
    if not config.meta_access_token:
        raise AttestationError("Meta app credentials are not configured")

    try:
        resp = requests.get(
            VERIFY_URL,
            params={"token": token, "access_token": config.meta_access_token},
            timeout=config.HTTP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise AttestationError("verify endpoint unreachable: %s" % exc)

    if resp.status_code >= 500:
        raise AttestationError("verify endpoint returned %s" % resp.status_code)

    try:
        payload = resp.json()
    except ValueError:
        raise AttestationError("verify endpoint returned non-JSON")

    entries = payload.get("data") or []
    if not entries:
        raise AttestationError("verify endpoint returned no data")

    entry = entries[0]
    message = entry.get("message")
    if message != "success":
        # "invalid signature" / "token expired" are verdicts, not outages.
        raise ValueError("attestation %s" % message)

    try:
        return json.loads(_b64url_decode(entry.get("claims", "")))
    except (ValueError, TypeError) as exc:
        raise AttestationError("could not decode claims: %s" % exc)


def validate_user_nonce(meta_user_id, nonce):
    """
    Proves the client actually controls `meta_user_id`. Without this an
    attacker can claim any Meta id they like.

    Returns True/False. Raises AttestationError if we could not ask.
    """
    if not (meta_user_id and nonce):
        return False
    try:
        resp = requests.post(
            NONCE_URL,
            params={
                "nonce": nonce,
                "user_id": meta_user_id,
                "access_token": config.meta_access_token,
            },
            timeout=config.HTTP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise AttestationError("user_nonce_validate unreachable: %s" % exc)

    if resp.status_code >= 500:
        raise AttestationError("user_nonce_validate returned %s" % resp.status_code)
    try:
        return resp.json().get("is_valid") is True
    except ValueError:
        raise AttestationError("user_nonce_validate returned non-JSON")


def summarise(claims):
    """Flatten the bits of the claim blob the rest of the service cares about."""
    request_details = claims.get("request_details") or {}
    app_state = claims.get("app_state") or {}
    device_state = claims.get("device_state") or {}
    device_ban = claims.get("device_ban") or {}
    return {
        "nonce": request_details.get("nonce"),
        "timestamp": request_details.get("timestamp"),
        "exp": request_details.get("exp"),
        "package_id": app_state.get("package_id"),
        "version": app_state.get("version"),
        "cert_digest": app_state.get("package_cert_sha256_digest"),
        "app_integrity_state": app_state.get("app_integrity_state"),
        "device_integrity_state": device_state.get("device_integrity_state"),
        "device_unique_id": device_state.get("unique_id"),
        "security_update_pending_days": device_state.get("security_update_pending_days"),
        "device_banned": device_ban.get("is_banned") is True,
        "device_ban_remaining": device_ban.get("remaining_ban_time"),
    }
