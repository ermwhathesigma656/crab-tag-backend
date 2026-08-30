"""
Configuration. Everything sensitive comes from the environment.

On PythonAnywhere set these in the WSGI file (see README) or a .env loaded by
python-dotenv. Never commit real values.
"""
import os


def _bool(name, default=False):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes")


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _list(name):
    raw = os.environ.get(name, "")
    return [p.strip() for p in raw.split(",") if p.strip()]


class Config:
    # --- identity of this deployment -------------------------------------
    SERVICE_NAME = os.environ.get("AC_SERVICE_NAME", "crabtag-anticheat")

    # --- shared secrets ---------------------------------------------------
    # Signs the session tokens we hand to clients. Rotating this invalidates
    # every live session, which is the intended emergency lever.
    SESSION_SIGNING_KEY = os.environ.get("AC_SESSION_KEY", "")

    # CloudScript (and any other trusted server) authenticates to us with this.
    # Sent as X-AC-Server-Key. Never ship it in the game client.
    SERVER_API_KEY = os.environ.get("AC_SERVER_KEY", "")

    # Protects /admin. Separate from SERVER_API_KEY so a leaked game-server key
    # cannot unban people.
    ADMIN_API_KEY = os.environ.get("AC_ADMIN_KEY", "")

    # --- Meta -------------------------------------------------------------
    META_APP_ID = os.environ.get("AC_META_APP_ID", "")
    META_APP_SECRET = os.environ.get("AC_META_APP_SECRET", "")
    META_PACKAGE_ID = os.environ.get("AC_META_PACKAGE_ID", "com.LegendaryLLC.CrabTag")

    # Empty list = accept anything. Fill these in from your first audit run,
    # exactly like MetaAllowedAppIntegrity in PlayFab Title Data.
    META_ALLOWED_APP_INTEGRITY = _list("AC_META_ALLOWED_APP_INTEGRITY")
    META_ALLOWED_DEVICE_INTEGRITY = _list("AC_META_ALLOWED_DEVICE_INTEGRITY")
    META_ALLOWED_CERT_DIGESTS = _list("AC_META_ALLOWED_CERT_DIGESTS")

    @property
    def meta_access_token(self):
        if not self.META_APP_ID or not self.META_APP_SECRET:
            return ""
        return "OC|%s|%s" % (self.META_APP_ID, self.META_APP_SECRET)

    # --- PlayFab (enforcement) -------------------------------------------
    PLAYFAB_TITLE_ID = os.environ.get("AC_PLAYFAB_TITLE_ID", "")
    PLAYFAB_SECRET_KEY = os.environ.get("AC_PLAYFAB_SECRET_KEY", "")

    # --- detection routing ------------------------------------------------
    DISCORD_WEBHOOK_SECURITY = os.environ.get("AC_DISCORD_SECURITY", "")
    DISCORD_WEBHOOK_MODERATION = os.environ.get("AC_DISCORD_MODERATION", "")

    # --- policy -----------------------------------------------------------
    # Master switch. Leave False until you have watched the detections for a
    # while - same discipline as MetaEnforce.
    ENFORCE = _bool("AC_ENFORCE", False)

    SESSION_TTL_SECONDS = _int("AC_SESSION_TTL", 900)          # token lifetime
    HEARTBEAT_INTERVAL_SECONDS = _int("AC_HEARTBEAT_INTERVAL", 120)
    # How late a heartbeat may be before we treat the gap as a signal. Generous,
    # because real players lose wifi in ways cheaters do not care to fake.
    HEARTBEAT_GRACE_SECONDS = _int("AC_HEARTBEAT_GRACE", 90)
    CHALLENGE_TTL_SECONDS = _int("AC_CHALLENGE_TTL", 120)
    ATTESTATION_MAX_AGE_SECONDS = _int("AC_ATTESTATION_MAX_AGE", 300)

    # Score thresholds. Higher score = more evidence of trouble.
    THRESHOLD_WATCH = _int("AC_THRESHOLD_WATCH", 20)
    THRESHOLD_SUSPECT = _int("AC_THRESHOLD_SUSPECT", 50)
    THRESHOLD_BLOCK = _int("AC_THRESHOLD_BLOCK", 100)

    # Repeat-offender escalation (matches the ban policy discussed for CloudScript).
    IP_BAN_AFTER_DISTINCT_ACCOUNTS = _int("AC_IP_BAN_AFTER", 3)

    # Retention. Free Postgres tiers are small and `detections` only grows.
    DETECTION_RETENTION_DAYS = _int("AC_DETECTION_RETENTION_DAYS", 30)

    # --- storage ----------------------------------------------------------
    # Postgres when set (any host), SQLite otherwise (local dev + tests only).
    DATABASE_URL = os.environ.get("AC_DATABASE_URL", "")
    DB_PATH = os.environ.get("AC_DB_PATH", "anticheat.sqlite3")

    # Serverless cold-starts re-import the app, so schema DDL would run on every
    # one. Harmless (CREATE TABLE IF NOT EXISTS) but wasteful. Run migrate.py
    # once, then set AC_AUTO_MIGRATE=false.
    AUTO_MIGRATE = _bool("AC_AUTO_MIGRATE", True)

    HTTP_TIMEOUT_SECONDS = _int("AC_HTTP_TIMEOUT", 10)

    def missing_required(self):
        """Names of settings that must be present for the service to be safe."""
        required = {
            "AC_SESSION_KEY": self.SESSION_SIGNING_KEY,
            "AC_SERVER_KEY": self.SERVER_API_KEY,
            "AC_ADMIN_KEY": self.ADMIN_API_KEY,
            "AC_META_APP_ID": self.META_APP_ID,
            "AC_META_APP_SECRET": self.META_APP_SECRET,
        }
        return [k for k, v in required.items() if not v]


config = Config()
