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

from flask import Flask, g, jsonify, request

import attestation
import db
import routing
import sessions
import trust
from config import config


_MIGRATED = False


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
            "known_routes": sorted(
                r.rule for r in app.url_map.iter_rules()
                if r.endpoint != "static"),
            "routing_hints": {
                k: v for k, v in request.headers.items()
                if "vercel" in k.lower() or "original" in k.lower()
                or "rewrite" in k.lower() or "forwarded-uri" in k.lower()
            },
        }), 404

    @app.get("/health")
    def health():
        storage_ok = db.ping()
        return jsonify({
            "service": config.SERVICE_NAME,
            "ok": (not app.config["AC_MISCONFIGURED"]) and storage_ok,
            "storage": "postgres" if db.IS_POSTGRES else "sqlite",
            "storage_ok": storage_ok,
            "enforcing": config.ENFORCE,
            "time": int(time.time()),
        })

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

        total = trust.score(signals)
        level = trust.trust_for_score(total, config)

        session_id = sessions.new_session_id()
        db.create_session(session_id, playfab_id, meta_user_id,
                          summary.get("device_unique_id"), ip, level, total,
                          summary)
        session_row = db.get_session(session_id)

        detection_ids = routing.route(session_row, signals, level, total)
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
