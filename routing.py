"""
Detection routing and enforcement.

Every signal lands in the `detections` table first - that is the analytics and
review surface. Routing then decides who hears about it and whether anything
automatic happens.

Enforcement is deliberately narrow:
  * config.ENFORCE must be on (your MetaEnforce-style master switch)
  * the evidence must include a SIGNED or OBSERVED signal
  * the score must clear THRESHOLD_BLOCK
Anything short of that goes to a human queue instead. Automated permanent
punishment on forgeable evidence is how you ban your own players.
"""
import json

import requests

import db
import trust
from config import config

SEVERITY_COLOURS = {
    "block": 0xE01B24,
    "suspect": 0xF57900,
    "watch": 0xF6D32D,
    "info": 0x3584E4,
}


def _post_webhook(url, title, description, colour, fields=None):
    if not url:
        return False
    embed = {
        "title": title[:250],
        "description": description[:4000],
        "color": colour,
    }
    if fields:
        embed["fields"] = [
            {"name": str(k)[:250], "value": str(v)[:1000], "inline": True}
            for k, v in list(fields.items())[:25]
        ]
    try:
        resp = requests.post(
            url, json={"embeds": [embed]},
            timeout=config.HTTP_TIMEOUT_SECONDS,
        )
        return resp.status_code < 300
    except requests.RequestException:
        # Never let the alerting path break the request that produced it.
        return False


def route(session, signals, trust_level, total_score):
    """
    Persist every signal, then notify. Returns the detection ids so an
    enforcement row can cite the evidence it acted on.
    """
    detection_ids = []
    for sig in signals:
        detection_ids.append(db.record_detection(
            signal=sig.name,
            severity=sig.severity,
            confidence=sig.confidence,
            session=session,
            detail=sig.detail,
        ))

    if not signals:
        return detection_ids

    if trust_level == trust.BLOCKED:
        bucket, colour = "block", SEVERITY_COLOURS["block"]
    elif trust_level == trust.SUSPECT:
        bucket, colour = "suspect", SEVERITY_COLOURS["suspect"]
    elif trust_level == trust.WATCH:
        bucket, colour = "watch", SEVERITY_COLOURS["watch"]
    else:
        bucket, colour = "info", SEVERITY_COLOURS["info"]

    # Only the noisy end goes to Discord; everything is queryable in /admin.
    if bucket in ("block", "suspect"):
        lines = [
            "**%s** `%s` (%s, severity %d)" % (
                s.name, json.dumps(s.detail)[:180], s.confidence, s.severity)
            for s in signals
        ]
        _post_webhook(
            config.DISCORD_WEBHOOK_SECURITY,
            "TRUST %s" % trust_level.upper(),
            "\n".join(lines)[:3800],
            colour,
            fields={
                "PlayFab": session["playfab_id"] if session else "?",
                "Meta ID": (session["meta_user_id"] if session else "?") or "-",
                "Device": (session["device_id"] if session else "?") or "-",
                "Score": total_score,
                "Session": (session["session_id"][:12] + "…") if session else "-",
            },
        )
    return detection_ids


# --- PlayFab enforcement --------------------------------------------------

def _playfab_admin(endpoint, body):
    if not (config.PLAYFAB_TITLE_ID and config.PLAYFAB_SECRET_KEY):
        return {"ok": False, "error": "PlayFab credentials not configured"}
    url = "https://%s.playfabapi.com/Admin/%s" % (config.PLAYFAB_TITLE_ID, endpoint)
    try:
        resp = requests.post(
            url, json=body,
            headers={"X-SecretKey": config.PLAYFAB_SECRET_KEY},
            timeout=config.HTTP_TIMEOUT_SECONDS,
        )
        return {"ok": resp.status_code < 300, "status": resp.status_code,
                "body": resp.json() if resp.content else None}
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}
    except ValueError:
        return {"ok": False, "error": "non-JSON response"}


def ban_account(playfab_id, reason, hours=None, detection_ids=None,
                automatic=True, device_id=None):
    """hours=None means permanent."""
    ban = {"PlayFabId": playfab_id, "Reason": reason[:140]}
    if hours is not None:
        ban["DurationInHours"] = hours
    result = _playfab_admin("BanUsers", {"Bans": [ban]})
    db.record_enforcement(
        action="ban_account_permanent" if hours is None else "ban_account",
        playfab_id=playfab_id, device_id=device_id, duration_hours=hours,
        reason=reason, automatic=automatic, detection_ids=detection_ids,
        result=result,
    )
    return result


def ban_ip(ip, playfab_id, reason, detection_ids=None, automatic=True,
           device_id=None):
    """
    Permanent IP ban. PlayFab's own note on this field: "May affect multiple
    players." Only ever called from the escalation path below.
    """
    result = _playfab_admin("BanUsers", {"Bans": [{
        "PlayFabId": playfab_id,
        "IPAddress": ip,
        "Reason": reason[:140],
    }]})
    db.record_enforcement(
        action="ban_ip", playfab_id=playfab_id, ip=ip, device_id=device_id,
        duration_hours=None, reason=reason, automatic=automatic,
        detection_ids=detection_ids, result=result,
    )
    _post_webhook(
        config.DISCORD_WEBHOOK_MODERATION, "IP BAN APPLIED",
        "IP `%s` permanently banned after %d distinct banned accounts.\n"
        "Reason: %s" % (ip, config.IP_BAN_AFTER_DISTINCT_ACCOUNTS, reason),
        SEVERITY_COLOURS["block"],
        fields={"Triggering account": playfab_id},
    )
    return result


def enforce(session, signals, trust_level, total_score, detection_ids):
    """
    The only place automatic punishment happens.

    Returns a dict describing what was done, so the caller can tell the client
    (and so it shows up in the response for debugging while ENFORCE is off).
    """
    if trust_level != trust.BLOCKED:
        return {"action": "none", "reason": "below block threshold"}

    if not trust.enforceable(signals):
        # Everything we have is client-reported. Queue it, do not act.
        return {"action": "queued",
                "reason": "no signed or observed evidence"}

    playfab_id = session["playfab_id"] if session else None
    ip = session["ip"] if session else None
    device_id = session["device_id"] if session else None
    names = {s.name for s in signals}
    summary = ", ".join(sorted(names))[:120]
    reason = "Anti-cheat: %s" % summary

    if not config.ENFORCE:
        return {"action": "audit_only", "would_have": "ban_account_permanent",
                "reason": reason}

    outcome = {"action": "ban_account_permanent", "reason": reason}
    outcome["account"] = ban_account(
        playfab_id, reason, hours=None, detection_ids=detection_ids,
        device_id=device_id)

    # An IP ban is permanent and, in PlayFab's own words, "may affect multiple
    # players" - so it needs a reason that cannot have been faked. Only signals
    # Meta signed qualify: a repacked APK, the wrong signing certificate, a
    # failed device-integrity check, or a device already banned before.
    signed_names = {s.name for s in signals if s.confidence == trust.SIGNED}
    hard_evidence = signed_names & {
        "meta.app_integrity", "meta.cert_digest", "meta.package_id",
        "meta.device_integrity", "meta.device_banned", "meta.token_rejected",
        "evasion.banned_device",
    }

    should_ip_ban = False
    ip_reason = None

    if hard_evidence and config.IP_BAN_ON_ATTESTATION_FAILURE:
        should_ip_ban = True
        ip_reason = "Modified build or untrusted device: %s" % (
            ", ".join(sorted(hard_evidence))[:90])

    if not should_ip_ban and ip:
        distinct = db.distinct_banned_accounts_for_ip(ip)
        if distinct >= config.IP_BAN_AFTER_DISTINCT_ACCOUNTS:
            should_ip_ban = True
            ip_reason = "Ban evasion: %d accounts from this address" % distinct

    if should_ip_ban and ip and not db.ip_already_banned(ip):
        outcome["action"] = "ban_account_permanent+ban_ip"
        outcome["ip"] = ban_ip(ip, playfab_id, ip_reason,
                               detection_ids=detection_ids, device_id=device_id)
        outcome["ip_reason"] = ip_reason

    return outcome


def report_evasion(session, network, prior_bans, prior_accounts):
    """
    A returning banned device, announced separately from the trust embed so it
    lands in the moderation channel with the context a human needs.
    """
    device_id = session["device_id"] if session else "?"
    net = "none"
    if network is not None and network.checked:
        net = "%s (%s)" % (
            "tor" if network.is_tor else
            "vpn" if network.is_vpn else
            "hosting" if network.is_hosting else
            "proxy" if network.is_proxy else "clean",
            network.provider or network.source)

    _post_webhook(
        config.DISCORD_WEBHOOK_MODERATION,
        "BAN EVASION DETECTED",
        "A device with **%d prior ban(s)** across **%d account(s)** attested on "
        "a new account.\n\nMeta signs the device id, so changing account, Meta "
        "login or IP does not hide it." % (prior_bans, prior_accounts),
        SEVERITY_COLOURS["block"],
        fields={
            "New account": session["playfab_id"] if session else "?",
            "Device": device_id,
            "IP": (session["ip"] if session else "?") or "-",
            "Network": net,
        },
    )
