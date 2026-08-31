"""
End-to-end: the real Flask route, with Meta and PlayFab faked, then the JSON it
returns parsed by a faithful port of the C# ReadField in PlayFabSessionCache.

The point is to catch a mismatch between what the backend emits and what the
client can actually read, which no unit test on either side would notice.
"""
import os

os.environ.setdefault("AC_DB_PATH", "test_login_e2e.sqlite3")
os.environ.setdefault("AC_PLAYFAB_TITLE_ID", "FBFD4")
os.environ.setdefault("AC_PLAYFAB_SECRET_KEY", "test-secret")
os.environ.setdefault("AC_META_APP_ID", "1251153274754895")
os.environ.setdefault("AC_META_APP_SECRET", "test")

import attestation
import app as appmod
import serverauth

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print("  %s %s" % ("ok  " if cond else "FAIL", label))


# ---- port of the C# ReadField, character for character --------------------
def read_field(json_text, key):
    if not json_text:
        return ""
    needle = '"' + key + '"'
    at = json_text.find(needle)
    if at < 0:
        return ""
    at = json_text.find(":", at + len(needle))
    if at < 0:
        return ""
    at += 1
    while at < len(json_text) and json_text[at].isspace():
        at += 1
    if at >= len(json_text) or json_text[at] != '"':
        return ""
    at += 1
    out = []
    while at < len(json_text) and json_text[at] != '"':
        if json_text[at] == "\\" and at + 1 < len(json_text):
            at += 1
        out.append(json_text[at])
        at += 1
    return "".join(out)


META = "28106802062346639"
SID = "OCULUS" + META


def fake_playfab(group, endpoint, body, use_secret=True):
    if endpoint == "LoginWithServerCustomId":
        if body.get("CreateAccount"):
            return {"ok": True, "status": 200, "body": {"data": {
                "PlayFabId": "10F5234B79CDDF6F",
                "SessionTicket": "FBFD4-abc123|def456",
                "NewlyCreated": True,
                "EntityToken": {
                    "EntityToken": "ENTITY-TOKEN-xyz",
                    "Entity": {"Id": "E1234", "Type": "title_player_account"}},
            }}}
        return {"ok": False, "status": 400,
                "body": {"errorCode": 1001, "error": "AccountNotFound"}}
    if endpoint == "LoginWithCustomID":
        return {"ok": False, "status": 400,
                "body": {"errorCode": 1001, "error": "AccountNotFound"}}
    return {"ok": True, "status": 200, "body": {"data": {}}}


serverauth._playfab = fake_playfab
attestation.validate_user_nonce = lambda uid, n: n == "valid-proof"

application = appmod.create_app()
client = application.test_client()

print("rejects a caller with no valid Meta proof")
r = client.post("/v1/auth/login",
                json={"meta_user_id": META, "nonce": "forged"})
check("forged proof -> 403", r.status_code == 403)
check("no ticket in body", "session_ticket" not in r.get_data(as_text=True))

print("\nrejects the account-spam shape outright")
r = client.post("/v1/auth/login", json={"meta_user_id": "sk3tchy", "nonce": "x"})
check("non-numeric id -> 400", r.status_code == 400)
r = client.post("/v1/auth/login", json={})
check("empty body -> 4xx", 400 <= r.status_code < 500)

print("\naccepts a proven player")
r = client.post("/v1/auth/login",
                json={"meta_user_id": META, "nonce": "valid-proof"},
                headers={"X-Forwarded-For": "203.0.113.44, 10.0.0.1"})
check("200", r.status_code == 200)
text = r.get_data(as_text=True)
print("    payload:", text)

print("\nthe C# client can read every field it needs")
check("session_ticket", read_field(text, "session_ticket") == "FBFD4-abc123|def456")
check("playfab_id", read_field(text, "playfab_id") == "10F5234B79CDDF6F")
check("entity_token", read_field(text, "entity_token") == "ENTITY-TOKEN-xyz")
check("entity_id", read_field(text, "entity_id") == "E1234")
check("entity_type", read_field(text, "entity_type") == "title_player_account")
check("path", read_field(text, "path") == "created")
check("missing key returns empty, not a crash", read_field(text, "nope") == "")

print("\nserver-side records the real client IP")
import db
check("IP taken from X-Forwarded-For, not the proxy hop",
      db.last_login_ip("10F5234B79CDDF6F") == "203.0.113.44")

print("\nclaims never leak to the client")
check("no claims field in response", "claims" not in text)

print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    raise SystemExit(1)
print("ALL PASSED")
