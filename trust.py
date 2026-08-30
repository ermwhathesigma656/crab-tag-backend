"""
The trust engine.

Signals are scored, not simply true/false, and each carries a confidence tier
that reflects how hard it is to forge:

  SIGNED    Meta signed it. A modified client cannot lie about this.
  OBSERVED  We measured it ourselves (missed heartbeats, identity mismatch,
            movement we simulated). A cheater can avoid producing it but
            cannot fake a clean one.
  REPORTED  The client told us. Trivially forgeable, so it can raise mild
            suspicion but must never be the sole basis for enforcement.

That last rule is the whole reason this file exists. A client-side root check
that says "I am not rooted" is worth nothing; the same check saying "I am
rooted" is worth a little, because honest clients have no reason to lie in that
direction.
"""

SIGNED = "signed"
OBSERVED = "observed"
REPORTED = "reported"

TRUSTED = "trusted"
WATCH = "watch"
SUSPECT = "suspect"
BLOCKED = "blocked"

# Ordered worst-to-best so max()/min() comparisons read naturally.
TRUST_ORDER = [BLOCKED, SUSPECT, WATCH, TRUSTED]


class Signal(object):
    __slots__ = ("name", "severity", "confidence", "detail")

    def __init__(self, name, severity, confidence, detail=None):
        self.name = name
        self.severity = severity
        self.confidence = confidence
        self.detail = detail or {}

    def as_dict(self):
        return {
            "signal": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "detail": self.detail,
        }


def evaluate_attestation(summary, cfg):
    """
    Signals from Meta's signed claims. These are the backbone: root detection,
    tamper detection and file integrity all come from here, already signed.
    """
    signals = []

    if summary.get("device_banned"):
        signals.append(Signal(
            "meta.device_banned", 100, SIGNED,
            {"remaining": summary.get("device_ban_remaining")}))

    # Root / bootloader / unlocked device. Meta's own verdict on the device.
    device_state = summary.get("device_integrity_state")
    if cfg.META_ALLOWED_DEVICE_INTEGRITY and device_state not in cfg.META_ALLOWED_DEVICE_INTEGRITY:
        signals.append(Signal(
            "meta.device_integrity", 100, SIGNED, {"state": device_state}))

    # Binary tampering: the installed app is not what Meta published.
    app_state = summary.get("app_integrity_state")
    if cfg.META_ALLOWED_APP_INTEGRITY and app_state not in cfg.META_ALLOWED_APP_INTEGRITY:
        signals.append(Signal(
            "meta.app_integrity", 100, SIGNED, {"state": app_state}))

    # Resigned APK - the classic repack.
    cert = summary.get("cert_digest")
    if cfg.META_ALLOWED_CERT_DIGESTS and cert not in cfg.META_ALLOWED_CERT_DIGESTS:
        signals.append(Signal(
            "meta.cert_digest", 100, SIGNED, {"digest": cert}))

    if cfg.META_PACKAGE_ID and summary.get("package_id") != cfg.META_PACKAGE_ID:
        signals.append(Signal(
            "meta.package_id", 100, SIGNED, {"package_id": summary.get("package_id")}))

    # Not evidence of cheating, but useful context for a moderator.
    pending = summary.get("security_update_pending_days")
    if isinstance(pending, int) and pending > 180:
        signals.append(Signal(
            "meta.stale_security_patch", 5, SIGNED, {"days": pending}))

    return signals


def evaluate_evasion(device_id, prior_bans, prior_accounts, network,
                     accounts_on_device, cfg):
    """
    Ban evasion.

    device_unique_id comes out of Meta's signed claims, so it survives a new
    account, a new Meta login and a new IP. That is why this - not the VPN
    check - is what actually stops evasion. The network verdict is context for
    the moderator and a small score bump, never the reason on its own: plenty
    of honest players use a VPN, and a cheater who does not use one would sail
    past an IP-only rule.
    """
    signals = []

    if cfg.DEVICE_EVASION_ENABLED and prior_bans > 0:
        signals.append(Signal(
            "evasion.banned_device", 100, SIGNED,
            {"device_id": device_id, "prior_bans": prior_bans,
             "prior_accounts": prior_accounts}))

    # Many accounts from one physical device is not proof of anything - shared
    # headsets exist - so it is weighted as a hint, not a verdict.
    if len(accounts_on_device) >= 4:
        signals.append(Signal(
            "evasion.many_accounts_one_device", 20, SIGNED,
            {"accounts": len(accounts_on_device)}))

    if network is not None and network.checked and network.anonymised:
        kind = ("tor" if network.is_tor else
                "vpn" if network.is_vpn else
                "hosting" if network.is_hosting else "proxy")
        # Tor and datacenter addresses are rarer among ordinary players than a
        # consumer VPN, so they weigh a little more.
        severity = {"tor": 25, "hosting": 20, "vpn": 10, "proxy": 15}[kind]
        if prior_bans > 0:
            severity += 25          # a returning banned device behind a VPN
        signals.append(Signal(
            "network.anonymised", severity, OBSERVED,
            {"kind": kind, "provider": network.provider,
             "country": network.country, "risk": network.risk,
             "source": network.source}))

    return signals


def evaluate_modules(report, cfg):
    """
    Assemblies the client says it loaded, checked against an allowlist.

    REPORTED tier on purpose. A repacked APK is caught by Meta's signed
    app_integrity_state and package_cert_sha256_digest instead - those cannot be
    faked, and they are what actually stops an injected library. This check only
    adds colour for a moderator and catches the careless.
    """
    signals = []
    modules = (report or {}).get("modules") or []
    if not isinstance(modules, list):
        return signals

    allow = [a.lower() for a in cfg.MODULE_ALLOWLIST]
    unknown = []
    for m in modules[:200]:
        name = str(m)
        if not any(a in name.lower() for a in allow):
            unknown.append(name)

    if unknown:
        signals.append(Signal(
            "client.unrecognised_modules", min(30, 5 * len(unknown)), REPORTED,
            {"modules": unknown[:25], "count": len(unknown)}))
    return signals


def evaluate_client_report(report):
    """
    Client self-reported environment signals. REPORTED confidence throughout,
    so they colour a moderator's view and nudge the score without ever reaching
    the block threshold on their own.
    """
    signals = []
    if not isinstance(report, dict):
        return signals

    if report.get("root_indicators"):
        signals.append(Signal(
            "client.root_indicators", 15, REPORTED,
            {"indicators": report.get("root_indicators")[:20]}))

    if report.get("debugger_attached") is True:
        signals.append(Signal("client.debugger", 15, REPORTED, {}))

    unknown = report.get("unknown_modules") or []
    if unknown:
        signals.append(Signal(
            "client.unknown_modules", 20, REPORTED,
            {"modules": unknown[:20], "count": len(unknown)}))

    if report.get("mod_loader") is True:
        signals.append(Signal(
            "client.mod_loader", 10, REPORTED,
            {"name": report.get("mod_loader_name")}))

    return signals


def evaluate_runtime(telemetry, limits=None):
    """
    Server-side plausibility checks on gameplay. OBSERVED - we do the maths, so
    a cheater has to actually behave normally to avoid these, which is the
    point.

    Deliberately conservative. These numbers want tuning against your own
    telemetry before enforcement leans on them.
    """
    limits = limits or {}
    max_speed = limits.get("max_speed_mps", 18.0)
    max_teleport = limits.get("max_teleport_m", 25.0)
    max_tag_rate = limits.get("max_tags_per_minute", 30)

    signals = []
    if not isinstance(telemetry, dict):
        return signals

    speed = telemetry.get("peak_speed_mps")
    if isinstance(speed, (int, float)) and speed > max_speed:
        over = speed / max_speed
        signals.append(Signal(
            "runtime.speed", min(60, int(20 * over)), OBSERVED,
            {"peak_speed_mps": speed, "limit": max_speed}))

    jump = telemetry.get("max_position_delta_m")
    if isinstance(jump, (int, float)) and jump > max_teleport:
        signals.append(Signal(
            "runtime.teleport", 45, OBSERVED,
            {"delta_m": jump, "limit": max_teleport}))

    tags = telemetry.get("tags_per_minute")
    if isinstance(tags, (int, float)) and tags > max_tag_rate:
        signals.append(Signal(
            "runtime.tag_rate", 35, OBSERVED,
            {"tags_per_minute": tags, "limit": max_tag_rate}))

    if telemetry.get("physics_desync_events", 0) > 10:
        signals.append(Signal(
            "runtime.physics_desync", 20, OBSERVED,
            {"events": telemetry.get("physics_desync_events")}))

    return signals


def evaluate_session_continuity(session, now_ts, cfg):
    """
    A client that stops heart-beating but keeps playing has usually had its
    anti-cheat calls patched out. Silence is itself a signal - and it is one we
    observe rather than one the client volunteers.
    """
    signals = []
    gap = now_ts - session["last_seen_at"]
    allowed = cfg.HEARTBEAT_INTERVAL_SECONDS + cfg.HEARTBEAT_GRACE_SECONDS
    if gap > allowed:
        missed = gap / float(cfg.HEARTBEAT_INTERVAL_SECONDS)
        signals.append(Signal(
            "session.heartbeat_gap", min(50, int(10 * missed)), OBSERVED,
            {"gap_seconds": gap, "allowed": allowed}))

    stale = now_ts - (session["attested_at"] or session["started_at"])
    if stale > cfg.SESSION_TTL_SECONDS * 2:
        signals.append(Signal(
            "session.stale_attestation", 25, OBSERVED, {"age_seconds": stale}))

    return signals


def evaluate_identity(claimed_playfab_id, session_playfab_id,
                      meta_verified, meta_user_id, bound_meta_user_id):
    """Cross-checks. Any mismatch here is an active impersonation attempt."""
    signals = []

    if session_playfab_id and claimed_playfab_id and \
            claimed_playfab_id != session_playfab_id:
        signals.append(Signal(
            "identity.session_mismatch", 100, OBSERVED,
            {"claimed": claimed_playfab_id, "session": session_playfab_id}))

    if bound_meta_user_id and meta_user_id and bound_meta_user_id != meta_user_id:
        signals.append(Signal(
            "identity.meta_mismatch", 100, OBSERVED,
            {"claimed": meta_user_id, "bound": bound_meta_user_id}))

    if meta_user_id and not meta_verified:
        signals.append(Signal(
            "identity.unproven_meta_id", 60, OBSERVED,
            {"meta_user_id": meta_user_id}))

    return signals


def score(signals):
    return sum(s.severity for s in signals)


def trust_for_score(total, cfg):
    if total >= cfg.THRESHOLD_BLOCK:
        return BLOCKED
    if total >= cfg.THRESHOLD_SUSPECT:
        return SUSPECT
    if total >= cfg.THRESHOLD_WATCH:
        return WATCH
    return TRUSTED


def enforceable(signals):
    """
    Whether this evidence is strong enough to act on automatically.

    REPORTED-only evidence never qualifies, no matter how much of it there is.
    Someone who spoofs a hundred fake indicators must not be able to get another
    player banned, and a real cheater's client will simply report nothing.
    """
    return any(s.confidence in (SIGNED, OBSERVED) for s in signals)
