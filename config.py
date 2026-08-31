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

    # Login is the one gate that fails CLOSED: if Meta cannot confirm who the
    # caller is, no session ticket is issued. Flip this only to keep the game
    # playable through a Meta outage, and understand it re-opens account spam
    # for as long as it is on.
    LOGIN_DEGRADE_OPEN = _bool("AC_LOGIN_DEGRADE_OPEN", False)

    # --- PlayFab (enforcement) -------------------------------------------
    PLAYFAB_TITLE_ID = os.environ.get("AC_PLAYFAB_TITLE_ID", "")
    PLAYFAB_SECRET_KEY = os.environ.get("AC_PLAYFAB_SECRET_KEY", "")

    # --- client connection settings ---------------------------------------
    # Handed to the game after it proves its Meta identity, so the title id and
    # Photon app ids are not sitting in the APK for anyone to grep out. These
    # are NOT secrets - the client transmits them on every connection - but
    # keeping them here means they can be rotated without a rebuild and are not
    # handed to callers who never proved who they are.
    #
    # No defaults on purpose: this repository is public, and a default would put
    # the real values somewhere far easier to read than the APK.
    CLIENT_PLAYFAB_TITLE_ID = os.environ.get("AC_CLIENT_TITLE_ID", "")
    PHOTON_APP_ID_REALTIME = os.environ.get("AC_PHOTON_REALTIME", "")
    PHOTON_APP_ID_VOICE = os.environ.get("AC_PHOTON_VOICE", "")
    PHOTON_APP_VERSION = os.environ.get("AC_PHOTON_VERSION", "")
    PHOTON_FIXED_REGION = os.environ.get("AC_PHOTON_REGION", "")

    @property
    def client_config(self):
        """Only non-empty values, so a half-configured backend cannot blank out
        a setting the client already had working."""
        pairs = (
            ("playfab_title_id", self.CLIENT_PLAYFAB_TITLE_ID or self.PLAYFAB_TITLE_ID),
            ("photon_realtime", self.PHOTON_APP_ID_REALTIME),
            ("photon_voice", self.PHOTON_APP_ID_VOICE),
            ("photon_version", self.PHOTON_APP_VERSION),
            ("photon_region", self.PHOTON_FIXED_REGION),
        )
        return dict((k, v) for k, v in pairs if v)

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

    # Repeat-offender escalation.
    IP_BAN_AFTER_DISTINCT_ACCOUNTS = _int("AC_IP_BAN_AFTER", 3)

    # Permanently IP-ban on a SIGNED attestation failure (repacked APK, wrong
    # signing cert, failed device integrity). Only ever fires on Meta-signed
    # evidence - never on anything the client merely claimed.
    # PlayFab's own note on the field: "May affect multiple players."
    IP_BAN_ON_ATTESTATION_FAILURE = _bool("AC_IP_BAN_ON_ATTESTATION_FAILURE", False)

    # A device that has been banned before, arriving on a fresh account, is ban
    # evasion. device_unique_id is signed by Meta, so a VPN does not hide it.
    DEVICE_EVASION_ENABLED = _bool("AC_DEVICE_EVASION", True)

    # --- network reputation ----------------------------------------------
    NETCHECK_ENABLED = _bool("AC_NETCHECK", False)
    NETCHECK_PROVIDER = os.environ.get("AC_NETCHECK_PROVIDER", "proxycheck")
    PROXYCHECK_API_KEY = os.environ.get("AC_PROXYCHECK_KEY", "")
    VPNAPI_KEY = os.environ.get("AC_VPNAPI_KEY", "")
    IP_INTEL_TTL_SECONDS = _int("AC_IP_INTEL_TTL", 86400)

    # Allowlisted assemblies. Anything the client reports outside this list is a
    # signal, never a verdict - a modified client simply reports a clean list.
    # GorillaShirts and Harmony load in the legitimate build, so they belong here.
    MODULE_ALLOWLIST = _list("AC_MODULE_ALLOWLIST") or [
        "GorillaShirts", "0Harmony", "HarmonyLib", "BepInEx",
        "Assembly-CSharp", "Assembly-CSharp-firstpass", "UnityEngine",
        "Photon", "PlayFab", "Oculus", "Unity", "Mono", "System", "netstandard",
    ]

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
