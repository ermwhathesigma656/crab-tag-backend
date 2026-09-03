"""
Flask application.

Two audiences, two auth schemes:

  /v1/*      called by your trusted server (PlayFab CloudScript) with
             X-AC-Server-Key, or by the game client carrying a session token we
             issued. The client never holds a long-lived secret.

  /admin/*   called by you, with X-AC-Admin-Key. Separate key so a leaked
             game-server key cannot unban anyone.

The client is never told *why* it failed in detail - a precise reason is a free
debugging tool for whoever is trying to defeat this. Moderators get the full
picture through /admin and Discord.
"""
import functools
import time
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

from flask import Flask, Response, g, jsonify, request

import attestation
import db
import netcheck
import routing
import serverauth
import sessions
import trust
from config import config


_MIGRATED = False


_FUNCTION_PATH = "/api/index"
_PATH_PARAM = "__original_path"


def _sanitise_path(value):
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
    """
    Serverless platforms rewrite the request path to the function's own path, so
    the WSGI app sees /api/index for every URL and Flask matches nothing.

    vercel.json passes the caller's path as a query parameter; this puts it back
    before routing and strips the parameter so handlers see only the caller's
    own query string.

    Trusting a client-supplied path here is not a privilege escalation: it only
    selects which route runs, and every protected route still checks its key.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        current = environ.get("PATH_INFO", "")

        if current.rstrip("/") == _FUNCTION_PATH or current in ("", "/"):
            restored, remaining = None, []
            for key, value in parse_qsl(environ.get("QUERY_STRING", ""),
                                        keep_blank_values=True):
                if key == _PATH_PARAM and restored is None:
                    restored = _sanitise_path(value)
                else:
                    remaining.append((key, value))
            if restored:
                environ["PATH_INFO"] = restored
                environ["QUERY_STRING"] = urlencode(remaining)

        elif current.startswith(_FUNCTION_PATH + "/"):
            environ["PATH_INFO"] = current[len(_FUNCTION_PATH):]

        return self.wsgi_app(environ, start_response)


def create_app():
    global _MIGRATED
    app = Flask(__name__)
    # Once per warm instance at most; skip entirely once the schema exists.
    if config.AUTO_MIGRATE and not _MIGRATED:
        db.init_db()
        _MIGRATED = True

    missing = config.missing_required()
    if missing:
        app.logger.error(
            "REFUSING TO TRUST ANYTHING - missing config: %s", ", ".join(missing))
    app.config["AC_MISCONFIGURED"] = bool(missing)

    register_routes(app)
    app.wsgi_app = RestoreOriginalPath(app.wsgi_app)
    return app


# --- auth helpers ---------------------------------------------------------

def _client_ip():
    """
    PythonAnywhere sits behind a proxy, so the socket address is theirs.
    X-Forwarded-For's *first* entry is the original client; later entries are
    proxies. Anything beyond the first is attacker-controllable in the general
    case, so we only ever read [0] and only trust it because PA overwrites it.
    """
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or ""


def require_server_key(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        key = request.headers.get("X-AC-Server-Key", "")
        if not config.SERVER_API_KEY or key != config.SERVER_API_KEY:
            return jsonify({"error": "unauthorised"}), 401
        return fn(*a, **kw)
    return wrapper


def require_admin_key(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        key = request.headers.get("X-AC-Admin-Key", "")
        if not config.ADMIN_API_KEY or key != config.ADMIN_API_KEY:
            return jsonify({"error": "unauthorised"}), 401
        return fn(*a, **kw)
    return wrapper


def require_session(fn):
    """Resolves the bearer token to a live, unended session row."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        auth = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        payload = sessions.verify(token)
        if not payload:
            return jsonify({"error": "invalid session"}), 401
        row = db.get_session(payload["sid"])
        if row is None or row["ended_at"] is not None:
            # Revoked or unknown: the token may verify, the session does not exist.
            return jsonify({"error": "session revoked"}), 401
        g.session = row
        g.token_payload = payload
        return fn(*a, **kw)
    return wrapper


def _json():
    return request.get_json(silent=True) or {}


def degrade_on_db_failure(fn):
    """
    Storage down must never lock players out. A free Postgres tier can suspend
    itself mid-month, and an anti-cheat that 500s in that state punishes exactly
    the honest players while the cheater simply stops calling us.
    """
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except db.DatabaseUnavailable as exc:
            return jsonify({
                "trust": trust.WATCH,
                "degraded": True,
                "reason": "storage unavailable",
                "detail": str(exc)[:200],
            }), 503
    return wrapper


def register_routes(app):

    @app.errorhandler(404)
    def not_found(_):
        """
        Serverless platforms rewrite paths, and a bare HTML 404 gives you no way
        to tell a wrong URL from a mangled one. Report what the app actually
        routed on. No secrets - just the path and the routing hints.
        """
        return jsonify({
            "error": "not found",
            "path_seen": request.path,
            "path_middleware": type(app.wsgi_app).__name__,
            "known_routes": sorted(
                r.rule for r in app.url_map.iter_rules()
                if r.endpoint != "static"),
            # Header NAMES only. Values are deliberately withheld: the
            # platform's own headers carry credentials (Vercel sends an OIDC
            # token and a proxy signature on every request), and a 404 body is
            # readable by anyone.
            "routing_header_names": sorted(
                k for k in request.headers.keys()
                if "vercel" in k.lower() or "original" in k.lower()
                or "rewrite" in k.lower() or "forwarded" in k.lower()
            ),
        }), 404

    @app.get("/")
    def index():
        """
        Deliberately says nothing useful. Anyone poking at the root of an
        anti-cheat service is not the audience for a feature list, and an
        endpoint inventory is a free map for whoever wants to work around it.
        """
        return Response("really cool backend\n", mimetype="text/plain")

    @app.get("/health")
    def health():
        storage_ok = db.ping()
        return jsonify({
            "service": config.SERVICE_NAME,
            "ok": (not app.config["AC_MISCONFIGURED"]) and storage_ok,
            "storage": "postgres" if db.IS_POSTGRES else "sqlite",
            "storage_ok": storage_ok,
            "enforcing": config.ENFORCE,
            # Key NAMES only, never values: enough to tell a configured backend
            # from one that will hand the game an empty config and strand it at
            # the login screen, without publishing anything.
            "client_config_keys": sorted(config.client_config.keys()),
            "admin_key_len": len(config.ADMIN_API_KEY or ""),
            "webhooks_set": {
                "security": bool(config.DISCORD_WEBHOOK_SECURITY),
                "moderation": bool(config.DISCORD_WEBHOOK_MODERATION),
            },
            "time": int(time.time()),
        })

    # ------------------------------------------------------------------
    # 0. Login. The only unauthenticated endpoint, and deliberately so: it is
    #    what the client calls INSTEAD of Client/LoginWithCustomID. It is not
    #    open in any meaningful sense - reaching a session ticket requires a
    #    nonce Meta signed for that exact Oculus account, which is precisely
    #    what an account spammer cannot produce.
    #
    #    This is also the first point where the real player IP is visible.
    #    Attestation reaches us relayed through PlayFab CloudScript, so the
    #    address on that request is PlayFab's, not the player's; here the
    #    client connects directly.
    # ------------------------------------------------------------------
    @app.post("/v1/auth/login")
    @degrade_on_db_failure
    def auth_login():
        body = _json()
        ip = _client_ip()
        if db.ip_already_banned(ip):
            return jsonify({"error": "identity not proven",
                            "reason": "this network address is banned"}), 403
        payload, status = serverauth.login(
            body.get("meta_user_id"),
            body.get("nonce"),
            body.get("integrity_token"),
        )

        if status == 200 and payload.get("playfab_id"):
            try:
                db.record_login_ip(payload["playfab_id"], ip)
            except Exception as exc:            # never fail a good login on bookkeeping
                app.logger.warning("record_login_ip failed: %s", exc)
            # Claims are for our records, not the client's.
            payload.pop("claims", None)
            # Connection settings travel with the login response: the caller has
            # just proven a Meta identity, and it needs these before it can talk
            # to PlayFab or Photon at all.
            payload["client_config"] = config.client_config
        return jsonify(payload), status

    # ------------------------------------------------------------------
    # In-game display text (MOTD, store signs). Public on purpose: this is
    # text shown on a wall to every player, and gating it behind a session
    # would only mean the boards stay blank until login finishes.
    #
    # The client appends the app version to the key, so MOTD becomes
    # MOTD_1.1.43. We fall back to the unversioned key so a new build does not
    # blank every sign until someone re-enters them.
    # ------------------------------------------------------------------
    @app.get("/v1/text/<path:key>")
    @degrade_on_db_failure
    def get_text(key):
        key = key.strip()[:128]
        try:
            value = db.get_text(key)
            if value is None and "_" in key:
                base, _, suffix = key.rpartition("_")
                if base and all(c.isdigit() or c == "." for c in suffix):
                    value = db.get_text(base)
        except Exception as exc:
            # A board with no text is a cosmetic problem; a 500 here is not.
            # degrade_on_db_failure only catches DatabaseUnavailable, so a
            # schema fault (missing table after a deploy) would otherwise reach
            # the client as an opaque 500 with nothing to act on.
            app.logger.exception("get_text(%s) failed", key)
            return jsonify({
                "error": "text unavailable",
                "kind": type(exc).__name__,
                "detail": str(exc)[:200],
            }), 503
        if value is None:
            return jsonify({"error": "not found", "key": key}), 404
        return jsonify({"key": key, "value": value})

    @app.get("/v1/text-diag")
    @degrade_on_db_failure
    def text_diag():
        """Which tables exist. No values, no secrets - just enough to tell a
        missing migration from an empty table."""
        try:
            with db.tx() as conn:
                if db.IS_POSTGRES:
                    rows = db._exec(conn, "SELECT table_name AS n FROM information_schema.tables"
                                          " WHERE table_schema='public' ORDER BY table_name").fetchall()
                else:
                    rows = db._exec(conn, "SELECT name AS n FROM sqlite_master"
                                          " WHERE type='table' ORDER BY name").fetchall()
            return jsonify({"backend": "postgres" if db.IS_POSTGRES else "sqlite",
                            "tables": [r["n"] for r in rows],
                            "auto_migrate": config.AUTO_MIGRATE})
        except Exception as exc:
            return jsonify({"kind": type(exc).__name__, "detail": str(exc)[:200]}), 503

    @app.post("/v1/admin/text")
    @degrade_on_db_failure
    @require_admin_key
    def set_text():
        body = _json()
        key = (body.get("key") or "").strip()
        value = body.get("value")
        if not key or value is None:
            return jsonify({"error": "key and value required"}), 400
        db.set_text(key[:128], str(value))
        return jsonify({"ok": True, "key": key})

    @app.get("/v1/admin/text")
    @degrade_on_db_failure
    @require_admin_key
    def list_texts():
        return jsonify({"texts": db.list_texts()})

    @app.post("/v1/enforce/check")
    @degrade_on_db_failure
    @require_server_key
    def enforce_check():
        body = _json()
        device_id = (body.get("device_id") or "").strip()
        playfab_id = (body.get("playfab_id") or "").strip()
        meta_user_id = str(body.get("meta_user_id") or "").strip()
        ip = db.last_login_ip(playfab_id) if playfab_id else None
        owner = db.device_owner(device_id)
        mismatch = bool(owner and meta_user_id and owner["meta_user_id"] != meta_user_id)
        return jsonify({
            "device_banned": db.device_banned(device_id),
            "ip_banned": db.ip_already_banned(ip) if ip else False,
            "ip": ip or "",
            "device_owner_mismatch": mismatch,
            "bound_meta_user_id": owner["meta_user_id"] if owner else "",
        })

    @app.post("/v1/admin/unban")
    @degrade_on_db_failure
    @require_admin_key
    def admin_unban():
        body = _json()
        ip = (body.get("ip") or "").strip()
        device_id = (body.get("device_id") or "").strip()
        playfab_id = (body.get("playfab_id") or "").strip()
        if not (ip or device_id or playfab_id):
            return jsonify({"error": "ip, device_id or playfab_id required"}), 400
        removed = db.clear_bans(ip=ip or None, device_id=device_id or None,
                                playfab_id=playfab_id or None)
        return jsonify({"ok": True, "removed": removed,
                        "ip_banned": db.ip_already_banned(ip) if ip else False,
                        "device_banned": db.device_banned(device_id) if device_id else False})

    @app.post("/v1/admin/unbind")
    @degrade_on_db_failure
    @require_admin_key
    def admin_unbind():
        body = _json()
        device_id = (body.get("device_id") or "").strip()
        if not device_id:
            return jsonify({"error": "device_id required"}), 400
        removed = db.unbind_device(device_id)
        return jsonify({"ok": True, "device_id": device_id, "removed": removed})

    @app.post("/v1/enforce/bind")
    @degrade_on_db_failure
    @require_server_key
    def enforce_bind():
        body = _json()
        device_id = (body.get("device_id") or "").strip()
        meta_user_id = str(body.get("meta_user_id") or "").strip()
        playfab_id = (body.get("playfab_id") or "").strip()
        if not (device_id and meta_user_id):
            return jsonify({"error": "device_id and meta_user_id required"}), 400
        existing = db.device_owner(device_id)
        if existing is None:
            db.bind_device(device_id, meta_user_id, playfab_id)
            return jsonify({"ok": True, "bound": True, "meta_user_id": meta_user_id})
        return jsonify({"ok": True, "bound": False,
                        "meta_user_id": existing["meta_user_id"],
                        "matches": existing["meta_user_id"] == meta_user_id})

    @app.post("/v1/enforce/ban")
    @degrade_on_db_failure
    @require_server_key
    def enforce_ban():
        body = _json()
        playfab_id = (body.get("playfab_id") or "").strip()
        device_id = (body.get("device_id") or "").strip()
        reason = (body.get("reason") or "attestation failure")[:200]
        if not playfab_id:
            return jsonify({"error": "playfab_id required"}), 400
        ip = db.last_login_ip(playfab_id) or ""
        if device_id:
            db.record_enforcement(action="ban_device", playfab_id=playfab_id,
                                  device_id=device_id, reason=reason)
        if ip:
            db.record_enforcement(action="ban_ip", playfab_id=playfab_id, ip=ip,
                                  device_id=device_id or None, reason=reason)
        return jsonify({"ok": True, "ip": ip, "device_id": device_id,
                        "ip_banned": bool(ip), "device_banned": bool(device_id)})

    # ------------------------------------------------------------------
    # 1. Challenge. Called by CloudScript on the player's behalf so the
    #    nonce is bound to a PlayFab identity the client cannot choose.
    # ------------------------------------------------------------------
    @app.post("/v1/session/challenge")
    @degrade_on_db_failure
    @require_server_key
    def challenge():
        body = _json()
        playfab_id = (body.get("playfab_id") or "").strip()
        if not playfab_id:
            return jsonify({"error": "playfab_id required"}), 400

        db.purge_expired_challenges()
        nonce = attestation.make_challenge_nonce()
        db.store_challenge(nonce, playfab_id)
        return jsonify({"challenge": nonce, "ttl": config.CHALLENGE_TTL_SECONDS})

    # ------------------------------------------------------------------
    # 2. Verify. The heavy one: proves the device, proves the identity,
    #    opens a session and hands back a token.
    # ------------------------------------------------------------------
    @app.post("/v1/session/verify")
    @degrade_on_db_failure
    @require_server_key
    def verify_session():
        body = _json()
        playfab_id = (body.get("playfab_id") or "").strip()
        token = body.get("integrity_token") or ""
        challenge_nonce = body.get("challenge") or ""
        meta_user_id = str(body.get("meta_user_id") or "").strip()
        user_proof = body.get("user_proof_nonce") or ""
        client_report = body.get("client_report") or {}
        ip = body.get("client_ip") or _client_ip()

        if not (playfab_id and token and challenge_nonce):
            return jsonify({"error": "playfab_id, integrity_token and challenge required"}), 400

        row = db.consume_challenge(challenge_nonce, playfab_id)
        if row is None:
            db.quiet(db.record_detection, "session.bad_challenge", 60,
                     trust.OBSERVED, playfab_id=playfab_id, ip=ip,
                     detail={"challenge": challenge_nonce[:16]})
            return jsonify({"error": "challenge not recognised"}), 400
        if db.now() - row["issued_at"] > config.CHALLENGE_TTL_SECONDS:
            return jsonify({"error": "challenge expired"}), 400

        # --- signed evidence ------------------------------------------
        try:
            claims = attestation.verify_integrity_token(token)
        except attestation.AttestationError as exc:
            # Our problem. Degrade open, but say so loudly.
            db.quiet(db.record_detection, "infra.attestation_unavailable", 0,
                     trust.OBSERVED, playfab_id=playfab_id, ip=ip,
                     detail={"error": str(exc)})
            return jsonify({"trust": trust.WATCH, "degraded": True,
                            "reason": "attestation unavailable"}), 503
        except ValueError as exc:
            db.quiet(db.record_detection, "meta.token_rejected", 100,
                     trust.SIGNED, playfab_id=playfab_id, ip=ip,
                     detail={"error": str(exc)})
            return jsonify({"trust": trust.BLOCKED}), 403

        summary = attestation.summarise(claims)

        signals = []
        if summary.get("nonce") != challenge_nonce:
            signals.append(trust.Signal("meta.nonce_mismatch", 100, trust.SIGNED,
                                        {"expected": challenge_nonce[:16]}))
        age = db.now() - int(summary.get("timestamp") or 0)
        if summary.get("timestamp") and age > config.ATTESTATION_MAX_AGE_SECONDS:
            signals.append(trust.Signal("meta.token_replayed", 70, trust.SIGNED,
                                        {"age_seconds": age}))

        signals += trust.evaluate_attestation(summary, config)

        # --- identity --------------------------------------------------
        meta_verified = False
        if meta_user_id and user_proof:
            try:
                meta_verified = attestation.validate_user_nonce(meta_user_id, user_proof)
            except attestation.AttestationError:
                meta_verified = False  # unproven, not disproven
        signals += trust.evaluate_identity(
            claimed_playfab_id=playfab_id, session_playfab_id=playfab_id,
            meta_verified=meta_verified, meta_user_id=meta_user_id,
            bound_meta_user_id=None)

        signals += trust.evaluate_client_report(client_report)
        signals += trust.evaluate_modules(client_report, config)

        # --- ban evasion -----------------------------------------------
        # device_unique_id is part of Meta's signed claims, so it identifies the
        # physical headset regardless of account, Meta login or IP. That is what
        # actually stops evasion; the network verdict is context around it.
        device_id = summary.get("device_unique_id")
        prior_bans, prior_accounts = db.quiet(
            db.prior_bans_for_device, device_id) or (0, 0)
        other_accounts = db.quiet(
            db.accounts_seen_on_device, device_id, playfab_id) or []
        network = netcheck.lookup(ip)
        signals += trust.evaluate_evasion(
            device_id, prior_bans, prior_accounts, network,
            other_accounts, config)

        total = trust.score(signals)
        level = trust.trust_for_score(total, config)

        session_id = sessions.new_session_id()
        db.create_session(session_id, playfab_id, meta_user_id,
                          summary.get("device_unique_id"), ip, level, total,
                          summary)
        session_row = db.get_session(session_id)

        detection_ids = routing.route(session_row, signals, level, total)
        if prior_bans > 0:
            routing.report_evasion(session_row, network, prior_bans, prior_accounts)
        action = routing.enforce(session_row, signals, level, total, detection_ids)

        if level == trust.BLOCKED and config.ENFORCE:
            db.end_session(session_id)
            return jsonify({"trust": level, "enforcement": action}), 403

        return jsonify({
            "trust": level,
            "session_token": sessions.issue(session_id, playfab_id, level),
            "heartbeat_interval": config.HEARTBEAT_INTERVAL_SECONDS,
            "enforcement": action,
        })

    # ------------------------------------------------------------------
    # 3. Heartbeat. Re-attests periodically and carries runtime telemetry,
    #    so integrity is validated through the session, not only at launch.
    # ------------------------------------------------------------------
    @app.post("/v1/session/heartbeat")
    @degrade_on_db_failure
    @require_session
    def heartbeat():
        body = _json()
        session = g.session
        signals = trust.evaluate_session_continuity(session, db.now(), config)
        signals += trust.evaluate_runtime(body.get("telemetry"))
        signals += trust.evaluate_client_report(body.get("client_report"))

        # Optional mid-session re-attestation. The client asks for a fresh
        # challenge, gets a new Meta token, and sends it here.
        fresh_token = body.get("integrity_token")
        fresh_challenge = body.get("challenge")
        re_attested = False
        if fresh_token and fresh_challenge:
            row = db.consume_challenge(fresh_challenge, session["playfab_id"])
            if row is None:
                signals.append(trust.Signal("session.bad_challenge", 60,
                                            trust.OBSERVED, {}))
            else:
                try:
                    claims = attestation.verify_integrity_token(fresh_token)
                    summary = attestation.summarise(claims)
                    if summary.get("nonce") != fresh_challenge:
                        signals.append(trust.Signal("meta.nonce_mismatch", 100,
                                                    trust.SIGNED, {}))
                    signals += trust.evaluate_attestation(summary, config)
                    re_attested = True
                except attestation.AttestationError:
                    pass                       # degrade open
                except ValueError as exc:
                    signals.append(trust.Signal("meta.token_rejected", 100,
                                                trust.SIGNED, {"error": str(exc)}))

        total = session["score"] + trust.score(signals)
        level = trust.trust_for_score(total, config)
        db.touch_session(session["session_id"], trust=level, score=total,
                         attested=re_attested)

        session = db.get_session(session["session_id"])
        detection_ids = routing.route(session, signals, level, total)
        action = routing.enforce(session, signals, level, total, detection_ids)

        if level == trust.BLOCKED and config.ENFORCE:
            db.end_session(session["session_id"])
            return jsonify({"trust": level, "enforcement": action}), 403

        return jsonify({
            "trust": level,
            "re_attested": re_attested,
            "next_heartbeat": config.HEARTBEAT_INTERVAL_SECONDS,
        })

    # ------------------------------------------------------------------
    # 4. Trust lookup, for your own server to gate rewards on.
    # ------------------------------------------------------------------
    @app.get("/v1/session/<session_id>/trust")
    @require_server_key
    def session_trust(session_id):
        row = db.get_session(session_id)
        if row is None:
            return jsonify({"error": "unknown session"}), 404
        stale = db.now() - row["last_seen_at"]
        return jsonify({
            "trust": row["trust"],
            "score": row["score"],
            "playfab_id": row["playfab_id"],
            "ended": row["ended_at"] is not None,
            "seconds_since_seen": stale,
        })

    @app.post("/v1/session/end")
    @require_session
    def end():
        db.end_session(g.session["session_id"])
        return jsonify({"ok": True})

    # ------------------------------------------------------------------
    # 5. Admin: the review, moderation and analytics surface.
    # ------------------------------------------------------------------
    @app.get("/admin/detections")
    @require_admin_key
    def admin_detections():
        rows = db.list_detections(
            state=request.args.get("state"),
            playfab_id=request.args.get("playfab_id"),
            limit=min(int(request.args.get("limit", 100)), 500),
            offset=int(request.args.get("offset", 0)),
        )
        return jsonify({"detections": [dict(r) for r in rows]})

    @app.post("/admin/detections/<int:detection_id>/review")
    @require_admin_key
    def admin_review(detection_id):
        body = _json()
        state = body.get("state")
        if state not in ("open", "confirmed", "dismissed", "actioned"):
            return jsonify({"error": "bad state"}), 400
        ok = db.set_review_state(detection_id, state,
                                 body.get("reviewer", "admin"), body.get("note"))
        return jsonify({"ok": ok}), (200 if ok else 404)

    @app.post("/admin/prune")
    @require_admin_key
    def admin_prune():
        """
        Retention. Call from a scheduler (Koyeb cron, GitHub Action, cron-job.org)
        so `detections` cannot creep up to a free tier's storage cap.
        Confirmed and actioned rows are kept as the evidence trail.
        """
        raw = _json().get("days")
        days = config.DETECTION_RETENTION_DAYS if raw is None else int(raw)
        removed = db.prune_detections(days=days)
        return jsonify({"removed": removed, "older_than_days": days})

    @app.get("/admin/stats")
    @require_admin_key
    def admin_stats():
        return jsonify({"rows": db.storage_stats(),
                        "retention_days": config.DETECTION_RETENTION_DAYS})

    @app.post("/admin/enforce")
    @require_admin_key
    def admin_enforce():
        """Manual action by a moderator. Always allowed, ENFORCE flag or not."""
        body = _json()
        playfab_id = body.get("playfab_id")
        if not playfab_id:
            return jsonify({"error": "playfab_id required"}), 400
        result = routing.ban_account(
            playfab_id, body.get("reason", "Manual review"),
            hours=body.get("hours"), automatic=False,
            detection_ids=body.get("detection_ids"))
        return jsonify(result)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
