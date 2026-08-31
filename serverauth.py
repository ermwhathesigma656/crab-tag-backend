"""
Server-authoritative PlayFab login.

The client no longer asserts its own identity. It presents a Meta user proof;
this service validates that proof against Meta and only then asks PlayFab for a
session ticket via Server/LoginWithServerCustomId - an API that requires the
title secret key, which the client does not have.

That is what makes Client/LoginWithCustomID deniable in the title API policy,
and denying it is what stops mass account creation: a spammer posting
{"CustomId": "<random>", "CreateAccount": true} has no Meta proof to offer and
no secret key, so there is no path left to mint an account.

Identity failures degrade CLOSED. Everywhere else in this service an outage
degrades open so a Meta hiccup cannot mass-ban players, but login is the one
place where "we could not verify who you are" must never resolve to "come in".
Set AC_LOGIN_DEGRADE_OPEN=true to trade that away during a Meta outage.
"""

import requests

import attestation
from attestation import AttestationError
from config import config


def _playfab(group, endpoint, body, use_secret=True):
    """One PlayFab call. Never raises; the caller branches on ok/status."""
    if not config.PLAYFAB_TITLE_ID:
        return {"ok": False, "error": "PlayFab title id not configured"}
    if use_secret and not config.PLAYFAB_SECRET_KEY:
        return {"ok": False, "error": "PlayFab secret key not configured"}

    url = "https://%s.playfabapi.com/%s/%s" % (
        config.PLAYFAB_TITLE_ID, group, endpoint)
    headers = {}
    if use_secret:
        headers["X-SecretKey"] = config.PLAYFAB_SECRET_KEY

    try:
        resp = requests.post(url, json=body, headers=headers,
                             timeout=config.HTTP_TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}

    try:
        payload = resp.json() if resp.content else None
    except ValueError:
        return {"ok": False, "status": resp.status_code,
                "error": "non-JSON response"}

    return {"ok": resp.status_code < 300, "status": resp.status_code,
            "body": payload}


def server_custom_id(meta_user_id):
    """
    Same shape the CloudScript handlers already validate, so a migrated account
    keeps the identity string it always had - only the provider changes.
    """
    return "OCULUS%s" % meta_user_id


def _account_missing(res):
    """PlayFab reports a login miss for a non-existent id as AccountNotFound."""
    body = res.get("body") or {}
    return body.get("errorCode") == 1001 or body.get("error") == "AccountNotFound"


def _ticket_from(res):
    data = (res.get("body") or {}).get("data") or {}
    if not data.get("SessionTicket"):
        return None
    entity = data.get("EntityToken") or {}
    return {
        "playfab_id": data.get("PlayFabId"),
        "session_ticket": data.get("SessionTicket"),
        "entity_token": entity.get("EntityToken"),
        "entity_id": (entity.get("Entity") or {}).get("Id"),
        "entity_type": (entity.get("Entity") or {}).get("Type"),
        "newly_created": bool(data.get("NewlyCreated")),
    }


def _prove_identity(meta_user_id, nonce):
    """
    Returns (ok, reason). The client cannot skip this: without a nonce Meta
    signed for this exact user id there is no way to reach a session ticket.
    """
    try:
        if attestation.validate_user_nonce(meta_user_id, nonce):
            return True, None
        return False, "Meta rejected the user proof for this account"
    except AttestationError as exc:
        if config.LOGIN_DEGRADE_OPEN:
            return True, "identity unverified (Meta unreachable, degraded open)"
        return False, "could not reach Meta to verify identity: %s" % exc


def _check_integrity(token):
    """
    App/device integrity is a supporting signal, not the identity gate, so a
    Meta outage here degrades open. An active rejection still fails closed when
    enforcement is on.
    """
    if not token:
        return True, None, None
    try:
        claims = attestation.verify_integrity_token(token)
        return True, None, claims
    except ValueError as exc:
        if config.ENFORCE:
            return False, str(exc), None
        return True, "integrity rejected (audit only): %s" % exc, None
    except AttestationError as exc:
        return True, "integrity unverified (Meta unreachable): %s" % exc, None


def login(meta_user_id, nonce, integrity_token=None):
    """
    Returns (payload, http_status).

    Three paths, in order:
      1. account already keyed by ServerCustomId  -> log in
      2. legacy account keyed by the old CustomId -> link, then log in
      3. no account at all                        -> create
    Path 2 is the migration: it runs once per player, preserves their PlayFabId
    and therefore all progress, and only happens while Client/LoginWithCustomID
    is still permitted by the API policy.
    """
    meta_user_id = str(meta_user_id or "").strip()
    if not meta_user_id.isdigit():
        return {"error": "meta_user_id must be numeric"}, 400
    if not (nonce or "").strip():
        return {"error": "nonce required"}, 400

    ok, reason = _prove_identity(meta_user_id, nonce)
    if not ok:
        return {"error": "identity not proven", "reason": reason}, 403

    integrity_ok, integrity_note, claims = _check_integrity(integrity_token)
    if not integrity_ok:
        return {"error": "integrity check failed", "reason": integrity_note}, 403

    sid = server_custom_id(meta_user_id)
    notes = [n for n in (reason, integrity_note) if n]

    # 1. Already migrated, or created by this endpoint previously.
    res = _playfab("Server", "LoginWithServerCustomId",
                   {"ServerCustomId": sid, "CreateAccount": False})
    ticket = _ticket_from(res) if res.get("ok") else None
    if ticket:
        ticket["path"] = "existing"
        ticket["notes"] = notes
        ticket["claims"] = claims
        return ticket, 200
    if not res.get("ok") and not _account_missing(res):
        return {"error": "playfab login failed",
                "reason": res.get("error") or (res.get("body") or {}).get("errorMessage")}, 502

    # 2. Legacy CustomId account: link the new provider, keep the PlayFabId.
    legacy = _playfab("Client", "LoginWithCustomID",
                      {"TitleId": config.PLAYFAB_TITLE_ID,
                       "CustomId": sid, "CreateAccount": False},
                      use_secret=False)
    if legacy.get("ok"):
        legacy_id = ((legacy.get("body") or {}).get("data") or {}).get("PlayFabId")
        if legacy_id:
            link = _playfab("Server", "LinkServerCustomId",
                            {"PlayFabId": legacy_id, "ServerCustomId": sid,
                             "ForceLink": False})
            if not link.get("ok"):
                body = link.get("body") or {}
                # LinkedAccountAlreadyClaimed means a concurrent login won the
                # race; the retry below picks up whatever it created.
                notes.append("link: %s" % (body.get("error") or link.get("error")))

            res = _playfab("Server", "LoginWithServerCustomId",
                           {"ServerCustomId": sid, "CreateAccount": False})
            ticket = _ticket_from(res) if res.get("ok") else None
            if ticket:
                ticket["path"] = "migrated"
                ticket["notes"] = notes
                ticket["claims"] = claims
                return ticket, 200

    # 3. Genuinely new player.
    res = _playfab("Server", "LoginWithServerCustomId",
                   {"ServerCustomId": sid, "CreateAccount": True})
    ticket = _ticket_from(res) if res.get("ok") else None
    if ticket:
        ticket["path"] = "created"
        ticket["notes"] = notes
        ticket["claims"] = claims
        return ticket, 200

    body = res.get("body") or {}
    return {"error": "playfab login failed",
            "reason": res.get("error") or body.get("errorMessage")}, 502
