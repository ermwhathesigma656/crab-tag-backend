import json
import os
import sys
import urllib.error
import urllib.request

TITLE = os.environ.get("AC_PLAYFAB_TITLE_ID", "FBFD4")
SECRET = os.environ.get("AC_PLAYFAB_SECRET_KEY", "")

DENY = [
    "Client/LoginWithCustomID",
    "Client/LoginWithAndroidDeviceID",
    "Client/LoginWithIOSDeviceID",
    "Client/LoginWithEmailAddress",
    "Client/LoginWithPlayFab",
    "Client/LoginWithOpenIdConnect",
    "Client/RegisterPlayFabUser",
]

USAGE = """
lock_playfab_login.py status   show which client login APIs are denied
lock_playfab_login.py lock     deny client-side login (backend becomes the only way in)
lock_playfab_login.py unlock   remove those denies

Set AC_PLAYFAB_SECRET_KEY first.

DO NOT run "lock" until:
  1. the client that logs in through /v1/auth/login is live, and
  2. your players have opened it at least once

Every player still on an older build logs in with Client/LoginWithCustomID.
Locking before they have migrated leaves them unable to reach their account,
and the backend migration path itself calls that API to find the legacy
account, so it stops working too.
"""


def api(endpoint, body):
    req = urllib.request.Request(
        "https://%s.playfabapi.com/Admin/%s" % (TITLE, endpoint),
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-SecretKey": SECRET})
    try:
        return json.load(urllib.request.urlopen(req))["data"]
    except urllib.error.HTTPError as exc:
        print("HTTP %s: %s" % (exc.code, exc.read().decode("utf-8", "replace")[:300]))
        sys.exit(1)


def get_statements():
    return api("GetPolicy", {"PolicyName": "ApiPolicy"})["Statements"]


def is_our_deny(st):
    res = st.get("Resource", "")
    return (st.get("Effect") == "Deny"
            and any(res == "pfrn:api--/" + d for d in DENY))


def status():
    st = get_statements()
    denied = [s["Resource"].replace("pfrn:api--/", "") for s in st if is_our_deny(s)]
    print("total statements :", len(st))
    print("client login denied :", len(denied))
    for d in denied:
        print("   ", d)
    if not denied:
        print("    (none - client login is open)")
    return denied


def lock():
    st = get_statements()
    existing = set(s["Resource"] for s in st if is_our_deny(s))
    added = 0
    for d in DENY:
        res = "pfrn:api--/" + d
        if res in existing:
            continue
        st.append({
            "Resource": res,
            "Action": "*",
            "Effect": "Deny",
            "Principal": "*",
            "Comment": "Login goes through the anti-cheat backend only",
        })
        added += 1
    if not added:
        print("already locked")
        return
    api("UpdatePolicy", {"PolicyName": "ApiPolicy", "Statements": st, "OverwritePolicy": True})
    print("locked - added %d deny statements" % added)
    status()


def unlock():
    st = get_statements()
    kept = [s for s in st if not is_our_deny(s)]
    removed = len(st) - len(kept)
    if not removed:
        print("nothing to remove")
        return
    api("UpdatePolicy", {"PolicyName": "ApiPolicy", "Statements": kept, "OverwritePolicy": True})
    print("unlocked - removed %d deny statements" % removed)


if __name__ == "__main__":
    if not SECRET:
        print("AC_PLAYFAB_SECRET_KEY is not set")
        sys.exit(2)
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "status":
        status()
    elif cmd == "lock":
        lock()
    elif cmd == "unlock":
        unlock()
    else:
        print(USAGE)
        sys.exit(2)
