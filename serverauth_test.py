"""
Tests for server-authoritative login.

The thing under test is not "does it return a ticket" but "can anything reach a
ticket without a Meta proof". That is the whole security property: if it can,
Client/LoginWithCustomID cannot safely be denied, and the account spam stays.
"""
import os
import sys

os.environ.setdefault("AC_DB_PATH", "test_serverauth.sqlite3")
os.environ.setdefault("AC_PLAYFAB_TITLE_ID", "FBFD4")
os.environ.setdefault("AC_PLAYFAB_SECRET_KEY", "test-secret")
os.environ.setdefault("AC_META_APP_ID", "1251153274754895")
os.environ.setdefault("AC_META_APP_SECRET", "test")

import attestation
import db
import serverauth
from attestation import AttestationError

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print("  %s %s" % ("ok  " if cond else "FAIL", label))


# ---- fakes ---------------------------------------------------------------
class PlayFab(object):
    """Stands in for the title. `accounts` maps provider -> id -> playfab_id."""

    def __init__(self, server_ids=None, custom_ids=None):
        self.server_ids = dict(server_ids or {})
        self.custom_ids = dict(custom_ids or {})
        self.calls = []
        self.next_id = 1000

    def __call__(self, group, endpoint, body, use_secret=True):
        self.calls.append((group, endpoint))
        route = "%s/%s" % (group, endpoint)

        if route == "Server/LoginWithServerCustomId":
            sid = body["ServerCustomId"]
            if sid in self.server_ids:
                return self._ticket(self.server_ids[sid])
            if body.get("CreateAccount"):
                self.next_id += 1
                pid = "NEW%d" % self.next_id
                self.server_ids[sid] = pid
                return self._ticket(pid, newly_created=True)
            return self._miss()

        if route == "Client/LoginWithCustomID":
            cid = body["CustomId"]
            if cid in self.custom_ids:
                return self._ticket(self.custom_ids[cid])
            return self._miss()

        if route == "Server/LinkServerCustomId":
            self.server_ids[body["ServerCustomId"]] = body["PlayFabId"]
            return {"ok": True, "status": 200, "body": {"data": {}}}

        raise AssertionError("unexpected call " + route)

    def _ticket(self, pid, newly_created=False):
        return {"ok": True, "status": 200, "body": {"data": {
            "PlayFabId": pid,
            "SessionTicket": "TICKET-" + pid,
            "NewlyCreated": newly_created,
            "EntityToken": {"EntityToken": "ET-" + pid,
                            "Entity": {"Id": "E" + pid, "Type": "title_player_account"}},
        }}}

    def _miss(self):
        return {"ok": False, "status": 400,
                "body": {"errorCode": 1001, "error": "AccountNotFound"}}


def use(pf, nonce_result=True, integrity=None):
    serverauth._playfab = pf
    if isinstance(nonce_result, Exception):
        def _nonce(uid, n): raise nonce_result
    else:
        def _nonce(uid, n): return nonce_result
    attestation.validate_user_nonce = _nonce
    if isinstance(integrity, Exception):
        def _int(t): raise integrity
    else:
        def _int(t): return integrity or {}
    attestation.verify_integrity_token = _int


META = "28106802062346639"
SID = "OCULUS" + META

print("identity gate")
pf = PlayFab()
use(pf, nonce_result=False)
body, status = serverauth.login(META, "bad-nonce")
check("Meta rejects proof -> 403", status == 403)
check("no PlayFab call attempted on bad proof", pf.calls == [])

body, status = serverauth.login("not-a-number", "n")
check("non-numeric meta id -> 400", status == 400)

body, status = serverauth.login(META, "")
check("missing nonce -> 400", status == 400)

print("\nfails closed when Meta is unreachable")
serverauth.config.LOGIN_DEGRADE_OPEN = False
pf = PlayFab()
use(pf, nonce_result=AttestationError("timeout"))
body, status = serverauth.login(META, "n")
check("Meta outage -> 403 (no ticket minted)", status == 403)
check("no account created during outage", pf.calls == [])

serverauth.config.LOGIN_DEGRADE_OPEN = True
use(PlayFab(), nonce_result=AttestationError("timeout"))
body, status = serverauth.login(META, "n")
check("escape hatch lets outage through when explicitly enabled", status == 200)
serverauth.config.LOGIN_DEGRADE_OPEN = False

print("\nexisting player")
pf = PlayFab(server_ids={SID: "10F5234B79CDDF6F"})
use(pf)
body, status = serverauth.login(META, "good")
check("returns a ticket", status == 200 and body["session_ticket"] == "TICKET-10F5234B79CDDF6F")
check("path=existing", body["path"] == "existing")
check("keeps the same PlayFabId", body["playfab_id"] == "10F5234B79CDDF6F")

print("\nmigration from the legacy CustomId account")
pf = PlayFab(custom_ids={SID: "10F5234B79CDDF6F"})
use(pf)
body, status = serverauth.login(META, "good")
check("migrated, not recreated", status == 200 and body["path"] == "migrated")
check("progress preserved: same PlayFabId", body["playfab_id"] == "10F5234B79CDDF6F")
check("link was issued", ("Server", "LinkServerCustomId") in pf.calls)
body, status = serverauth.login(META, "good")
check("second login takes the fast path", body["path"] == "existing")

print("\nbrand new player")
pf = PlayFab()
use(pf)
body, status = serverauth.login(META, "good")
check("created", status == 200 and body["path"] == "created")
check("flagged newly_created", body["newly_created"] is True)

print("\nintegrity token")
pf = PlayFab(server_ids={SID: "P1"})
use(pf, integrity=ValueError("attestation invalid signature"))
serverauth.config.ENFORCE = True
body, status = serverauth.login(META, "good", "tok")
check("rejected token blocks login while enforcing", status == 403)
serverauth.config.ENFORCE = False
body, status = serverauth.login(META, "good", "tok")
check("rejected token is audit-only when not enforcing", status == 200)

pf = PlayFab(server_ids={SID: "P1"})
use(pf, integrity=AttestationError("meta down"))
serverauth.config.ENFORCE = True
body, status = serverauth.login(META, "good", "tok")
check("integrity outage degrades open (identity already proven)", status == 200)
serverauth.config.ENFORCE = False

print("\nreal client IP is recorded")
db.init_db(raise_on_error=True)
db.record_login_ip("10F5234B79CDDF6F", "203.0.113.9")
db.record_login_ip("10F5234B79CDDF6F", "203.0.113.9")
db.record_login_ip("OTHER", "203.0.113.9")
check("last_login_ip round-trips", db.last_login_ip("10F5234B79CDDF6F") == "203.0.113.9")
check("distinct accounts per IP counted", db.accounts_from_ip("203.0.113.9") == 2)
check("unknown player has no IP", db.last_login_ip("NOBODY") is None)

print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    sys.exit(1)
print("ALL PASSED")
