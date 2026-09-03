import os

os.environ.setdefault("AC_DB_PATH", "test_enforce.sqlite3")
os.environ.setdefault("AC_PLAYFAB_TITLE_ID", "FBFD4")
os.environ.setdefault("AC_PLAYFAB_SECRET_KEY", "test-secret")
os.environ.setdefault("AC_META_APP_ID", "1251153274754895")
os.environ.setdefault("AC_META_APP_SECRET", "test")
os.environ.setdefault("AC_SESSION_KEY", "k")
os.environ.setdefault("AC_SERVER_KEY", "srv")
os.environ.setdefault("AC_ADMIN_KEY", "adm")

import attestation
import app as appmod
import db
import serverauth

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print("  %s %s" % ("ok  " if cond else "FAIL", label))


def fake_playfab(group, endpoint, body, use_secret=True):
    if endpoint == "LoginWithServerCustomId":
        return {"ok": True, "status": 200, "body": {"data": {
            "PlayFabId": "VICTIM01", "SessionTicket": "T", "NewlyCreated": False,
            "EntityToken": {"EntityToken": "E", "Entity": {"Id": "X", "Type": "title_player_account"}}}}}
    return {"ok": False, "status": 400, "body": {"errorCode": 1001, "error": "AccountNotFound"}}


serverauth._playfab = fake_playfab
attestation.validate_user_nonce = lambda uid, n: True
db.init_db(raise_on_error=True)

application = appmod.create_app()
c = application.test_client()
SRV = {"X-AC-Server-Key": "srv"}
META = "28106802062346639"
CHEATER_IP = "198.51.100.7"
DEVICE = "046ed1d3f7b33525144acb96886755172ce3c2fd5300fa9d49fd4ac8f96a4bca"

print("clean login records the real ip")
r = c.post("/v1/auth/login", json={"meta_user_id": META, "nonce": "ok"},
           headers={"X-Forwarded-For": CHEATER_IP})
check("login 200", r.status_code == 200)
check("ip recorded against account", db.last_login_ip("VICTIM01") == CHEATER_IP)

print("\nenforce/check before any ban")
r = c.post("/v1/enforce/check", json={"device_id": DEVICE, "playfab_id": "VICTIM01"}, headers=SRV)
j = r.get_json()
check("200", r.status_code == 200)
check("device not banned yet", j["device_banned"] is False)
check("ip not banned yet", j["ip_banned"] is False)
check("returns the recorded ip", j["ip"] == CHEATER_IP)

print("\nenforce/ban requires the server key")
r = c.post("/v1/enforce/ban", json={"playfab_id": "VICTIM01"})
check("no key -> 401", r.status_code == 401)

print("\nenforce/ban bans device and ip from the recorded login")
r = c.post("/v1/enforce/ban", json={"playfab_id": "VICTIM01", "device_id": DEVICE,
                                    "reason": "unauthorised native library libzenith.so"}, headers=SRV)
j = r.get_json()
check("200", r.status_code == 200)
check("ip resolved from login_ips", j["ip"] == CHEATER_IP)
check("ip_banned true", j["ip_banned"] is True)
check("device_banned true", j["device_banned"] is True)

print("\nafter the ban")
r = c.post("/v1/enforce/check", json={"device_id": DEVICE, "playfab_id": "VICTIM01"}, headers=SRV)
j = r.get_json()
check("device now banned", j["device_banned"] is True)
check("ip now banned", j["ip_banned"] is True)

print("\nnew meta account, same headset, same ip -> stopped at login")
r = c.post("/v1/auth/login", json={"meta_user_id": "99999999999999999", "nonce": "ok"},
           headers={"X-Forwarded-For": CHEATER_IP})
check("banned ip -> 403 before any PlayFab call", r.status_code == 403)
check("no ticket issued", "session_ticket" not in r.get_data(as_text=True))

print("\nnew meta account, same headset, NEW ip -> login passes, device check catches it")
r = c.post("/v1/auth/login", json={"meta_user_id": "99999999999999999", "nonce": "ok"},
           headers={"X-Forwarded-For": "203.0.113.200"})
check("fresh ip logs in", r.status_code == 200)
r = c.post("/v1/enforce/check", json={"device_id": DEVICE, "playfab_id": "VICTIM01"}, headers=SRV)
check("device still banned across accounts and ips", r.get_json()["device_banned"] is True)

print("\nunrelated device is unaffected")
r = c.post("/v1/enforce/check", json={"device_id": "aaaa1111", "playfab_id": "NOBODY"}, headers=SRV)
check("clean device not banned", r.get_json()["device_banned"] is False)

print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    raise SystemExit(1)
print("ALL PASSED")
