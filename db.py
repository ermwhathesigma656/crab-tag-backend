"""
Storage. Postgres when AC_DATABASE_URL is set, SQLite otherwise.

SQLite is for local development and the smoke test. Any real deployment on a
serverless or scale-to-zero host has an ephemeral filesystem, so SQLite there
silently loses every session, detection and ban record - and the ban history is
what `distinct_banned_accounts_for_ip` depends on.

Fail-open policy
----------------
Free database tiers can stop dead: Neon suspends compute when you exceed a
monthly limit, hosts restart, connections drop. An anti-cheat that 500s when its
database is unavailable locks out every honest player while doing nothing to a
cheater, who simply stops calling us.

So reads that inform a decision raise DatabaseUnavailable, and the API layer
turns that into "degraded, trust = watch" rather than an error. Writes that only
record evidence are allowed to fail quietly - losing a log line is better than
losing a login.
"""
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager

from config import config

_local = threading.local()

DATABASE_URL = os.environ.get("AC_DATABASE_URL", "").strip()
IS_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://"))

if IS_POSTGRES:
    import psycopg
    from psycopg.rows import dict_row


class DatabaseUnavailable(Exception):
    """Storage is unreachable. Callers must degrade, never punish."""


# --- schema ---------------------------------------------------------------

_SERIAL = "BIGSERIAL PRIMARY KEY" if IS_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"

SCHEMA = """
CREATE TABLE IF NOT EXISTS challenges (
    nonce           TEXT PRIMARY KEY,
    playfab_id      TEXT NOT NULL,
    issued_at       BIGINT NOT NULL,
    consumed_at     BIGINT
);
CREATE INDEX IF NOT EXISTS idx_challenges_player ON challenges(playfab_id);
CREATE INDEX IF NOT EXISTS idx_challenges_issued ON challenges(issued_at);

CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    playfab_id      TEXT NOT NULL,
    meta_user_id    TEXT,
    device_id       TEXT,
    ip              TEXT,
    trust           TEXT NOT NULL,
    score           BIGINT NOT NULL DEFAULT 0,
    started_at      BIGINT NOT NULL,
    last_seen_at    BIGINT NOT NULL,
    ended_at        BIGINT,
    attested_at     BIGINT,
    claims_json     TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_player ON sessions(playfab_id);
CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip);

CREATE TABLE IF NOT EXISTS detections (
    id              __SERIAL__,
    session_id      TEXT,
    playfab_id      TEXT,
    meta_user_id    TEXT,
    device_id       TEXT,
    ip              TEXT,
    signal          TEXT NOT NULL,
    severity        BIGINT NOT NULL,
    confidence      TEXT NOT NULL,
    detail_json     TEXT,
    created_at      BIGINT NOT NULL,
    review_state    TEXT NOT NULL DEFAULT 'open',
    reviewed_by     TEXT,
    reviewed_at     BIGINT,
    review_note     TEXT
);
CREATE INDEX IF NOT EXISTS idx_detections_player ON detections(playfab_id);
CREATE INDEX IF NOT EXISTS idx_detections_state ON detections(review_state);
CREATE INDEX IF NOT EXISTS idx_detections_created ON detections(created_at);

CREATE TABLE IF NOT EXISTS enforcements (
    id              __SERIAL__,
    playfab_id      TEXT,
    ip              TEXT,
    device_id       TEXT,
    action          TEXT NOT NULL,
    duration_hours  BIGINT,
    reason          TEXT,
    automatic       BIGINT NOT NULL DEFAULT 1,
    detection_ids   TEXT,
    created_at      BIGINT NOT NULL,
    result_json     TEXT
);
CREATE INDEX IF NOT EXISTS idx_enforcements_player ON enforcements(playfab_id);
CREATE INDEX IF NOT EXISTS idx_enforcements_ip ON enforcements(ip);
CREATE INDEX IF NOT EXISTS idx_enforcements_device ON enforcements(device_id);

CREATE TABLE IF NOT EXISTS ip_intel (
    ip              TEXT PRIMARY KEY,
    verdict_json    TEXT NOT NULL,
    checked_at      BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS texts (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_owners (
    device_id       TEXT PRIMARY KEY,
    meta_user_id    TEXT NOT NULL,
    playfab_id      TEXT,
    bound_at        BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_ips (
    playfab_id      TEXT NOT NULL,
    ip              TEXT NOT NULL,
    first_seen_at   BIGINT NOT NULL,
    last_seen_at    BIGINT NOT NULL,
    hits            BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (playfab_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_login_ips_ip ON login_ips(ip);
""".replace("__SERIAL__", _SERIAL)


# --- connection handling --------------------------------------------------

def _connect():
    if IS_POSTGRES:
        return psycopg.connect(DATABASE_URL, row_factory=dict_row,
                               connect_timeout=10, autocommit=False)
    conn = sqlite3.connect(config.DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _healthy(conn):
    if conn is None:
        return False
    if IS_POSTGRES:
        return not conn.closed
    return True


def get_conn():
    """
    One connection per thread, reconnected if the far end went away - which on
    a scale-to-zero database happens routinely, not exceptionally.
    """
    conn = getattr(_local, "conn", None)
    if not _healthy(conn):
        try:
            conn = _local.conn = _connect()
        except Exception as exc:
            _local.conn = None
            raise DatabaseUnavailable(str(exc))
    return conn


def _q(sql):
    """SQLite uses ?, psycopg uses %s. One dialect in the source, both at runtime."""
    return sql.replace("?", "%s") if IS_POSTGRES else sql


@contextmanager
def tx():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except DatabaseUnavailable:
        raise
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        # A dropped connection surfaces here; make it recoverable next call.
        if IS_POSTGRES and isinstance(exc, psycopg.OperationalError):
            _local.conn = None
            raise DatabaseUnavailable(str(exc))
        raise


def _exec(conn, sql, args=()):
    cur = conn.cursor()
    cur.execute(_q(sql), args)
    return cur


def quiet(fn, *a, **kw):
    """
    Run a write whose only purpose is to record evidence. If storage is down we
    would rather drop the log line than fail the player's request.
    Returns None on failure.
    """
    try:
        return fn(*a, **kw)
    except DatabaseUnavailable:
        return None
    except Exception:
        return None


# Columns added after the first schema shipped. CREATE TABLE IF NOT EXISTS does
# nothing to an existing table, so a deployment migrated before these landed
# keeps the old shape and every insert touching the new column fails at runtime.
# Applied only where the column is genuinely absent.
_ADDED_COLUMNS = [
    ("enforcements", "device_id", "TEXT"),
]


def _existing_columns(conn, table):
    if IS_POSTGRES:
        rows = _exec(conn,
                     "SELECT column_name FROM information_schema.columns"
                     " WHERE table_name=?", (table,)).fetchall()
        return set(r["column_name"] for r in rows)
    rows = _exec(conn, "PRAGMA table_info(%s)" % table).fetchall()
    return set(r["name"] for r in rows)


def _apply_column_migrations(conn):
    applied = []
    for table, column, coltype in _ADDED_COLUMNS:
        try:
            if column in _existing_columns(conn, table):
                continue
            _exec(conn, "ALTER TABLE %s ADD COLUMN %s %s" % (table, column, coltype))
            applied.append("%s.%s" % (table, column))
        except Exception:
            # Missing table is fine: SCHEMA above just created it with the
            # column already present.
            pass
    return applied


def init_db(raise_on_error=False):
    """
    Column migrations run BEFORE the schema, not after.

    SCHEMA declares an index on enforcements(device_id); on a database created
    before that column existed, the index statement aborts the whole script and
    nothing else in it gets applied. Adding the column first makes the schema
    valid in both cases - on a fresh database the migration is a harmless no-op
    because the table does not exist yet.
    """
    try:
        try:
            with tx() as conn:
                _apply_column_migrations(conn)
        except Exception:
            pass                      # fresh database: nothing to migrate yet

        with tx() as conn:
            if IS_POSTGRES:
                _exec(conn, SCHEMA)
            else:
                conn.executescript(SCHEMA)

        with tx() as conn:
            _apply_column_migrations(conn)
        return True
    except Exception:
        # Do not crash the worker on boot; /health reports it instead.
        if raise_on_error:
            raise
        return False


def ping():
    try:
        with tx() as conn:
            _exec(conn, "SELECT 1")
        return True
    except Exception:
        return False


def now():
    return int(time.time())


# --- challenges -----------------------------------------------------------

def store_challenge(nonce, playfab_id):
    with tx() as conn:
        _exec(conn, "INSERT INTO challenges (nonce, playfab_id, issued_at)"
                    " VALUES (?,?,?)", (nonce, playfab_id, now()))


def consume_challenge(nonce, playfab_id):
    """
    Single use, bound to one player. The UPDATE ... WHERE consumed_at IS NULL is
    the atomic part: two racing requests cannot both win it.
    """
    with tx() as conn:
        cur = _exec(conn,
                    "UPDATE challenges SET consumed_at=? "
                    "WHERE nonce=? AND playfab_id=? AND consumed_at IS NULL",
                    (now(), nonce, playfab_id))
        if cur.rowcount != 1:
            return None
        return _exec(conn, "SELECT * FROM challenges WHERE nonce=?",
                     (nonce,)).fetchone()


def purge_expired_challenges():
    cutoff = now() - config.CHALLENGE_TTL_SECONDS * 4
    with tx() as conn:
        _exec(conn, "DELETE FROM challenges WHERE issued_at < ?", (cutoff,))


# --- sessions -------------------------------------------------------------

def create_session(session_id, playfab_id, meta_user_id, device_id, ip,
                   trust, score, claims):
    ts = now()
    with tx() as conn:
        _exec(conn,
              "INSERT INTO sessions (session_id, playfab_id, meta_user_id,"
              " device_id, ip, trust, score, started_at, last_seen_at,"
              " attested_at, claims_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
              (session_id, playfab_id, meta_user_id, device_id, ip, trust,
               score, ts, ts, ts, json.dumps(claims or {})))


def get_session(session_id):
    with tx() as conn:
        return _exec(conn, "SELECT * FROM sessions WHERE session_id=?",
                     (session_id,)).fetchone()


def touch_session(session_id, trust=None, score=None, attested=False):
    sets, vals = ["last_seen_at=?"], [now()]
    if trust is not None:
        sets.append("trust=?")
        vals.append(trust)
    if score is not None:
        sets.append("score=?")
        vals.append(score)
    if attested:
        sets.append("attested_at=?")
        vals.append(now())
    vals.append(session_id)
    with tx() as conn:
        _exec(conn, "UPDATE sessions SET %s WHERE session_id=?" % ",".join(sets),
              vals)


def end_session(session_id):
    with tx() as conn:
        _exec(conn, "UPDATE sessions SET ended_at=? WHERE session_id=?"
                    " AND ended_at IS NULL", (now(), session_id))


# --- detections -----------------------------------------------------------

def record_detection(signal, severity, confidence, session=None, detail=None,
                     playfab_id=None, ip=None):
    sid = session["session_id"] if session else None
    pid = playfab_id or (session["playfab_id"] if session else None)
    muid = session["meta_user_id"] if session else None
    did = session["device_id"] if session else None
    addr = ip or (session["ip"] if session else None)

    sql = ("INSERT INTO detections (session_id, playfab_id, meta_user_id,"
           " device_id, ip, signal, severity, confidence, detail_json,"
           " created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
    args = (sid, pid, muid, did, addr, signal, severity, confidence,
            json.dumps(detail or {}), now())

    with tx() as conn:
        if IS_POSTGRES:
            return _exec(conn, sql + " RETURNING id", args).fetchone()["id"]
        return _exec(conn, sql, args).lastrowid


def list_detections(state=None, playfab_id=None, limit=100, offset=0):
    q, args = "SELECT * FROM detections WHERE 1=1", []
    if state:
        q += " AND review_state=?"
        args.append(state)
    if playfab_id:
        q += " AND playfab_id=?"
        args.append(playfab_id)
    q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args += [limit, offset]
    with tx() as conn:
        return _exec(conn, q, args).fetchall()


def set_review_state(detection_id, state, reviewer, note=None):
    with tx() as conn:
        cur = _exec(conn,
                    "UPDATE detections SET review_state=?, reviewed_by=?,"
                    " reviewed_at=?, review_note=? WHERE id=?",
                    (state, reviewer, now(), note, detection_id))
        return cur.rowcount == 1


def prune_detections(days=None, keep_states=("confirmed", "actioned")):
    """
    Retention. The detections table only grows, and 0.5 GB of free Postgres
    fills eventually. Reviewed-and-confirmed rows are kept as the evidence
    trail; routine noise ages out.

    Returns the number of rows removed.
    """
    # `days or DEFAULT` would swallow 0, which is a legitimate
    # "prune everything" request.
    days = config.DETECTION_RETENTION_DAYS if days is None else int(days)
    cutoff = now() - days * 86400
    placeholders = ",".join("?" for _ in keep_states)
    with tx() as conn:
        cur = _exec(conn,
                    "DELETE FROM detections WHERE created_at < ?"
                    " AND review_state NOT IN (%s)" % placeholders,
                    (cutoff,) + tuple(keep_states))
        return cur.rowcount


def storage_stats():
    with tx() as conn:
        out = {}
        for table in ("challenges", "sessions", "detections",
                      "enforcements", "ip_intel"):
            row = _exec(conn, "SELECT COUNT(*) AS n FROM %s" % table).fetchone()
            out[table] = row["n"]
        return out


# --- enforcement ----------------------------------------------------------

def record_enforcement(action, playfab_id=None, ip=None, device_id=None,
                       duration_hours=None, reason=None, automatic=True,
                       detection_ids=None, result=None):
    sql = ("INSERT INTO enforcements (playfab_id, ip, device_id, action,"
           " duration_hours, reason, automatic, detection_ids, created_at,"
           " result_json) VALUES (?,?,?,?,?,?,?,?,?,?)")
    args = (playfab_id, ip, device_id, action, duration_hours, reason,
            1 if automatic else 0, json.dumps(detection_ids or []), now(),
            json.dumps(result or {}))
    with tx() as conn:
        if IS_POSTGRES:
            return _exec(conn, sql + " RETURNING id", args).fetchone()["id"]
        return _exec(conn, sql, args).lastrowid


def distinct_banned_accounts_for_ip(ip):
    """Repeat-offender signal: separate accounts we have banned on this address."""
    if not ip:
        return 0
    with tx() as conn:
        row = _exec(conn,
                    "SELECT COUNT(DISTINCT playfab_id) AS n FROM enforcements"
                    " WHERE ip=? AND action LIKE 'ban_account%'"
                    " AND playfab_id IS NOT NULL", (ip,)).fetchone()
    return (row["n"] if row else 0) or 0


def prior_bans_for_device(device_id):
    """
    Meta signs device_state.unique_id, so this survives a new account, a new
    Meta login and a new IP address. It is the only evasion signal in the
    system a VPN cannot defeat.

    Returns (ban_count, distinct_accounts).
    """
    if not device_id:
        return (0, 0)
    with tx() as conn:
        row = _exec(conn,
                    "SELECT COUNT(*) AS n, COUNT(DISTINCT playfab_id) AS accts"
                    " FROM enforcements WHERE device_id=?"
                    " AND action LIKE 'ban_%'", (device_id,)).fetchone()
    if not row:
        return (0, 0)
    return (row["n"] or 0, row["accts"] or 0)


def accounts_seen_on_device(device_id, exclude_playfab_id=None):
    """Distinct accounts that have ever attested from this physical device."""
    if not device_id:
        return []
    q = "SELECT DISTINCT playfab_id FROM sessions WHERE device_id=?"
    args = [device_id]
    if exclude_playfab_id:
        q += " AND playfab_id<>?"
        args.append(exclude_playfab_id)
    with tx() as conn:
        return [r["playfab_id"] for r in _exec(conn, q, args).fetchall()]


# --- ip reputation cache --------------------------------------------------

def get_ip_intel(ip, max_age_seconds):
    with tx() as conn:
        row = _exec(conn, "SELECT verdict_json, checked_at FROM ip_intel"
                          " WHERE ip=?", (ip,)).fetchone()
    if not row:
        return None
    if now() - row["checked_at"] > max_age_seconds:
        return None
    return row["verdict_json"]


def store_ip_intel(ip, verdict_json):
    with tx() as conn:
        if IS_POSTGRES:
            _exec(conn, "INSERT INTO ip_intel (ip, verdict_json, checked_at)"
                        " VALUES (?,?,?) ON CONFLICT (ip) DO UPDATE SET"
                        " verdict_json=EXCLUDED.verdict_json,"
                        " checked_at=EXCLUDED.checked_at",
                  (ip, verdict_json, now()))
        else:
            _exec(conn, "INSERT OR REPLACE INTO ip_intel"
                        " (ip, verdict_json, checked_at) VALUES (?,?,?)",
                  (ip, verdict_json, now()))


def get_text(key):
    """In-game display text. Returns None when the key was never set."""
    with tx() as conn:
        row = _exec(conn, "SELECT value FROM texts WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def set_text(key, value):
    ts = now()
    with tx() as conn:
        if IS_POSTGRES:
            _exec(conn, "INSERT INTO texts (key, value, updated_at) VALUES (?,?,?)"
                        " ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value,"
                        " updated_at=EXCLUDED.updated_at", (key, value, ts))
        else:
            _exec(conn, "INSERT OR REPLACE INTO texts (key, value, updated_at)"
                        " VALUES (?,?,?)", (key, value, ts))


def list_texts():
    with tx() as conn:
        rows = _exec(conn, "SELECT key, updated_at FROM texts ORDER BY key").fetchall()
    return [{"key": r["key"], "updated_at": r["updated_at"]} for r in rows]


def record_login_ip(playfab_id, ip):
    """
    The address a player actually logged in from.

    This is the only place we ever see it. Attestation arrives relayed through
    PlayFab CloudScript, so its source address is PlayFab's egress, not the
    player's - banning that would ban everyone. Enforcement that needs a real
    IP reads it from here.
    """
    if not (playfab_id and ip):
        return
    ts = now()
    with tx() as conn:
        if IS_POSTGRES:
            _exec(conn, "INSERT INTO login_ips"
                        " (playfab_id, ip, first_seen_at, last_seen_at, hits)"
                        " VALUES (?,?,?,?,1)"
                        " ON CONFLICT (playfab_id, ip) DO UPDATE SET"
                        " last_seen_at=EXCLUDED.last_seen_at,"
                        " hits=login_ips.hits+1",
                  (playfab_id, ip, ts, ts))
        else:
            _exec(conn, "INSERT INTO login_ips"
                        " (playfab_id, ip, first_seen_at, last_seen_at, hits)"
                        " VALUES (?,?,?,?,1)"
                        " ON CONFLICT (playfab_id, ip) DO UPDATE SET"
                        " last_seen_at=excluded.last_seen_at,"
                        " hits=login_ips.hits+1",
                  (playfab_id, ip, ts, ts))


def last_login_ip(playfab_id):
    """Most recent address for a player, or None if they never logged in here."""
    with tx() as conn:
        row = _exec(conn, "SELECT ip FROM login_ips WHERE playfab_id=?"
                          " ORDER BY last_seen_at DESC LIMIT 1",
                    (playfab_id,)).fetchone()
    return row["ip"] if row else None


def accounts_from_ip(ip):
    """How many distinct accounts have logged in from one address."""
    with tx() as conn:
        row = _exec(conn, "SELECT COUNT(*) AS n FROM login_ips WHERE ip=?",
                    (ip,)).fetchone()
    return int(row["n"]) if row else 0


def device_owner(device_id):
    if not device_id:
        return None
    with tx() as conn:
        row = _exec(conn, "SELECT meta_user_id, playfab_id FROM device_owners"
                          " WHERE device_id=?", (device_id,)).fetchone()
    return {"meta_user_id": row["meta_user_id"], "playfab_id": row["playfab_id"]} if row else None


def bind_device(device_id, meta_user_id, playfab_id):
    if not (device_id and meta_user_id):
        return False
    ts = now()
    with tx() as conn:
        if IS_POSTGRES:
            _exec(conn, "INSERT INTO device_owners (device_id, meta_user_id, playfab_id, bound_at)"
                        " VALUES (?,?,?,?) ON CONFLICT (device_id) DO NOTHING",
                  (device_id, meta_user_id, playfab_id, ts))
        else:
            _exec(conn, "INSERT OR IGNORE INTO device_owners"
                        " (device_id, meta_user_id, playfab_id, bound_at) VALUES (?,?,?,?)",
                  (device_id, meta_user_id, playfab_id, ts))
    return True


def unbind_device(device_id):
    if not device_id:
        return False
    with tx() as conn:
        cur = _exec(conn, "DELETE FROM device_owners WHERE device_id=?", (device_id,))
        return (cur.rowcount or 0) > 0


def clear_bans(ip=None, device_id=None, playfab_id=None):
    where, args = [], []
    if ip:
        where.append("ip=?"); args.append(ip)
    if device_id:
        where.append("device_id=?"); args.append(device_id)
    if playfab_id:
        where.append("playfab_id=?"); args.append(playfab_id)
    if not where:
        return 0
    sql = ("DELETE FROM enforcements WHERE action LIKE 'ban_%' AND ("
           + " OR ".join(where) + ")")
    with tx() as conn:
        cur = _exec(conn, sql, tuple(args))
        return cur.rowcount or 0


def device_banned(device_id):
    if not device_id:
        return False
    with tx() as conn:
        return _exec(conn, "SELECT 1 AS x FROM enforcements WHERE device_id=?"
                           " AND action='ban_device' LIMIT 1", (device_id,)).fetchone() is not None


def ip_already_banned(ip):
    if not ip:
        return False
    with tx() as conn:
        return _exec(conn, "SELECT 1 AS x FROM enforcements WHERE ip=?"
                           " AND action='ban_ip' LIMIT 1", (ip,)).fetchone() is not None
