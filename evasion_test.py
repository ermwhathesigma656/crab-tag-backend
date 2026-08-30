"""Covers the new enforcement paths: repacked APK, ban evasion, VPN, modules."""
import os, tempfile, sys, time
os.environ.update(
    AC_SESSION_KEY="k"*64, AC_SERVER_KEY="s"*64, AC_ADMIN_KEY="a"*64,
    AC_META_APP_ID="1", AC_META_APP_SECRET="x",
    AC_META_PACKAGE_ID="com.LegendaryLLC.CrabTag",
    AC_META_ALLOWED_APP_INTEGRITY="MATCHES_STORE",
    AC_META_ALLOWED_DEVICE_INTEGRITY="MEETS_INTEGRITY",
    AC_META_ALLOWED_CERT_DIGESTS="GOODCERT",
    AC_DB_PATH=os.path.join(tempfile.mkdtemp(),"t.sqlite3"),
    AC_ENFORCE="true", AC_IP_BAN_ON_ATTESTATION_FAILURE="true",
    AC_NETCHECK="false",
)
sys.path.insert(0,".")
import attestation, trust, db, routing, netcheck
from app import app
from config import config

state = {"nonce":None, "cert":"GOODCERT", "app":"MATCHES_STORE",
         "dev":"MEETS_INTEGRITY", "device":"headset-A"}
attestation.verify_integrity_token = lambda t: {
    "request_details":{"nonce":state["nonce"],"timestamp":time.time()},
    "app_state":{"package_id":"com.LegendaryLLC.CrabTag","version":"1",
                 "app_integrity_state":state["app"],
                 "package_cert_sha256_digest":state["cert"]},
    "device_state":{"device_integrity_state":state["dev"],"unique_id":state["device"]}}
attestation.validate_user_nonce = lambda u,n: True
routing._playfab_admin = lambda ep, body: {"ok": True, "stub": True, "sent": body}
routing._post_webhook = lambda *a, **k: True

SRV={"X-AC-Server-Key":"s"*64}
c=app.test_client()
fail=[]
def check(l,v): print(("  ok   " if v else "  FAIL ")+l); (fail.append(l) if not v else None)

def verify(pid, modules=None, ip="8.8.8.8"):
    state["nonce"]=c.post("/v1/session/challenge",json={"playfab_id":pid},headers=SRV).get_json()["challenge"]
    return c.post("/v1/session/verify",headers=SRV,json={
        "playfab_id":pid,"integrity_token":"t","challenge":state["nonce"],
        "meta_user_id":"777","user_proof_nonce":"n","client_ip":ip,
        "client_report":{"modules":modules or []}})

print("legitimate build with GorillaShirts + Harmony")
r=verify("GOOD", ["Assembly-CSharp","GorillaShirts","0Harmony","UnityEngine.CoreModule"])
check("trusted", r.get_json()["trust"]==trust.TRUSTED)
check("mod loader does NOT trip it", r.status_code==200)

print("repacked APK with an injected lib (re-signed -> cert changes)")
state["cert"]="ATTACKERCERT"
r=verify("REPACK", ["Assembly-CSharp","evil_hack"])
j=r.get_json()
check("blocked", j["trust"]==trust.BLOCKED)
check("permanent account ban", "ban_account_permanent" in j["enforcement"]["action"])
check("permanent IP ban too", "ban_ip" in j["enforcement"]["action"])
state["cert"]="GOODCERT"

print("ban evasion: same headset, brand new account, different IP")
r=verify("NEWACCT", ["Assembly-CSharp"], ip="1.2.3.4")
j=r.get_json()
check("device recognised -> blocked", j["trust"]==trust.BLOCKED)
d=db.list_detections()
check("evasion.banned_device signal raised",
      any(x["signal"]=="evasion.banned_device" for x in d))
check("evasion signal is SIGNED tier",
      any(x["signal"]=="evasion.banned_device" and x["confidence"]=="signed" for x in d))

print("a clean device is unaffected")
state["device"]="headset-B"
r=verify("INNOCENT", ["Assembly-CSharp","GorillaShirts"])
check("different headset still trusted", r.get_json()["trust"]==trust.TRUSTED)

print("forgeable evidence alone never bans")
sigs=[trust.Signal("client.unrecognised_modules",500,trust.REPORTED,{})]
check("REPORTED cannot reach enforcement", not trust.enforceable(sigs))
out=routing.enforce({"playfab_id":"X","ip":"9.9.9.9","device_id":"d"},sigs,
                    trust.BLOCKED,500,[])
check("enforce() queues instead of banning", out["action"]=="queued")

print()
print("FAILED: %s" % fail if fail else "ALL PASSED")
