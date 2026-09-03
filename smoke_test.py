"""Offline smoke test: exercises the real code paths with Meta stubbed out."""
import os, tempfile, json
os.environ.update(
    AC_SESSION_KEY="k"*64, AC_SERVER_KEY="s"*64, AC_ADMIN_KEY="a"*64,
    AC_META_APP_ID="1", AC_META_APP_SECRET="x",
    AC_META_PACKAGE_ID="com.LegendaryLLC.CrabTag",
    AC_META_ALLOWED_APP_INTEGRITY="PLAY_RECOGNIZED",
    AC_META_ALLOWED_DEVICE_INTEGRITY="MEETS_DEVICE_INTEGRITY",
    AC_DB_PATH=os.path.join(tempfile.mkdtemp(), "t.sqlite3"),
    AC_ENFORCE="false",
)
import attestation, app as appmod, sessions, trust

SRV = {"X-AC-Server-Key": "s"*64}
ADM = {"X-AC-Admin-Key": "a"*64}
state = {"nonce": None, "device": "MEETS_DEVICE_INTEGRITY"}

def fake_verify(token):
    return {"request_details": {"nonce": state["nonce"], "timestamp": __import__("time").time()},
            "app_state": {"package_id": "com.LegendaryLLC.CrabTag", "version": "1",
                          "app_integrity_state": "PLAY_RECOGNIZED",
                          "package_cert_sha256_digest": "AA"},
            "device_state": {"device_integrity_state": state["device"], "unique_id": "dev-1"}}
attestation.verify_integrity_token = fake_verify
attestation.validate_user_nonce = lambda uid, n: True

c = appmod.app.test_client()
fail = []
def check(label, cond):
    print(("  ok   " if cond else "  FAIL ") + label)
    if not cond: fail.append(label)

print("health / auth")
check("health 200", c.get("/health").status_code == 200)
check("challenge rejects missing key", c.post("/v1/session/challenge", json={"playfab_id":"P1"}).status_code == 401)
check("admin rejects server key", c.get("/admin/detections", headers=SRV).status_code == 401)

print("clean session")
r = c.post("/v1/session/challenge", json={"playfab_id":"P1"}, headers=SRV)
state["nonce"] = r.get_json()["challenge"]
r = c.post("/v1/session/verify", headers=SRV, json={
    "playfab_id":"P1","integrity_token":"t","challenge":state["nonce"],
    "meta_user_id":"999","user_proof_nonce":"n"})
body = r.get_json()
check("verify 200", r.status_code == 200)
check("trust=trusted", body.get("trust") == trust.TRUSTED)
tok = body.get("session_token")
check("issued token", bool(tok))

print("replay protection")
r2 = c.post("/v1/session/verify", headers=SRV, json={
    "playfab_id":"P1","integrity_token":"t","challenge":state["nonce"]})
check("challenge is single-use", r2.status_code == 400)

print("session token")
AUTH = {"Authorization": "Bearer " + tok}
check("heartbeat 200", c.post("/v1/session/heartbeat", headers=AUTH, json={}).status_code == 200)
check("forged token rejected", c.post("/v1/session/heartbeat",
      headers={"Authorization": "Bearer " + tok[:-4] + "AAAA"}, json={}).status_code == 401)

print("runtime heuristics")
r = c.post("/v1/session/heartbeat", headers=AUTH,
           json={"telemetry": {"peak_speed_mps": 400, "max_position_delta_m": 900}})
check("speed+teleport downgrade trust", r.get_json()["trust"] in (trust.SUSPECT, trust.BLOCKED))

print("rooted device is blocked")
state["device"] = "FAILS_DEVICE_INTEGRITY"
r = c.post("/v1/session/challenge", json={"playfab_id":"P2"}, headers=SRV)
state["nonce"] = r.get_json()["challenge"]
r = c.post("/v1/session/verify", headers=SRV, json={
    "playfab_id":"P2","integrity_token":"t","challenge":state["nonce"]})
check("root -> blocked", r.get_json()["trust"] == trust.BLOCKED)
check("audit_only while ENFORCE=false", r.get_json()["enforcement"]["action"] == "audit_only")

print("client-only evidence never auto-enforces")
sigs = [trust.Signal("client.root_indicators", 200, trust.REPORTED, {})]
check("REPORTED alone is not enforceable", not trust.enforceable(sigs))

print("detections recorded")
d = c.get("/admin/detections", headers=ADM).get_json()["detections"]
check("detections logged", len(d) > 0)
check("signed signal present", any(x["confidence"] == "signed" for x in d))

print("retention + stats")
stats = c.get("/admin/stats", headers=ADM).get_json()
check("stats reports rows", stats["rows"]["detections"] > 0)
import db as _db
# Age one detection 40 days and mark another as confirmed evidence, then prune
# with a 30-day window: the old open row must go, the confirmed row must stay.
with _db.tx() as _c:
    _db._exec(_c, "UPDATE detections SET created_at=? WHERE id=(SELECT MIN(id) FROM detections)",
              (_db.now() - 40*86400,))
    _db._exec(_c, "UPDATE detections SET created_at=?, review_state='confirmed'"
                  " WHERE id=(SELECT MAX(id) FROM detections)",
              (_db.now() - 40*86400,))
before = c.get("/admin/stats", headers=ADM).get_json()["rows"]["detections"]
pruned = c.post("/admin/prune", headers=ADM, json={"days": 30}).get_json()
after = c.get("/admin/stats", headers=ADM).get_json()["rows"]["detections"]
check("prune removes aged open detections", pruned["removed"] == 1)
check("prune keeps confirmed evidence", after == before - 1)
check("days=0 is not swallowed by falsy check",
      c.post("/admin/prune", headers=ADM, json={"days": 0}).get_json()["older_than_days"] == 0)

print("fail-open when storage dies")
import db as dbmod
def dead(*a, **kw):
    raise dbmod.DatabaseUnavailable("simulated outage")
orig = dbmod.store_challenge
dbmod.store_challenge = dead
r = c.post("/v1/session/challenge", json={"playfab_id":"P3"}, headers=SRV)
check("db outage -> 503 not 500", r.status_code == 503)
check("db outage -> trust=watch", r.get_json()["trust"] == trust.WATCH)
check("db outage -> nobody blocked", r.get_json()["trust"] != trust.BLOCKED)
dbmod.store_challenge = orig

orig_get = dbmod.get_session
dbmod.get_session = dead
r = c.post("/v1/session/heartbeat", headers=AUTH, json={})
check("outage inside require_session is caught", r.status_code == 503)
dbmod.get_session = orig_get

print("health")
pub = c.get("/health").get_json()
check("public health hides storage backend", "storage" not in pub)
check("public health hides enforcing flag", "enforcing" not in pub)
check("public health hides admin key length", "admin_key_len" not in pub)
check("public health hides webhook state", "webhooks_set" not in pub)
check("public health still answers ok", "ok" in pub)
check("wrong admin key gets the public view",
      "storage" not in c.get("/health", headers={"X-AC-Admin-Key": "nope"}).get_json())
h = c.get("/health", headers=ADM).get_json()
check("health reports storage backend", h["storage"] in ("sqlite","postgres"))
check("health reports storage_ok", h["storage_ok"] is True)

print()
print("FAILED: %d  -> %s" % (len(fail), fail) if fail else "ALL PASSED")
