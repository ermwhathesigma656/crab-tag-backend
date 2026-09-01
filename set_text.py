"""
Push in-game display text to the backend.

    python set_text.py MOTD motd.txt

Reads the admin key from AC_ADMIN_KEY, or pass it as a third argument. The key
is never written anywhere by this script.

Keys the game currently asks for (the client appends the app version, and the
endpoint falls back to the unversioned key):

    MOTD                    the board in the computer room
    BundleBoardSign         store signage
    BundleLargeSign
    BundleKioskSign
    BundleKioskButton
    SeasonalStoreBoardSign
"""
import io
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("AC_BASE_URL", "https://crab-tag-backend.vercel.app")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2

    key = sys.argv[1]
    path = sys.argv[2]
    admin_key = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("AC_ADMIN_KEY", "")

    if not admin_key:
        print("No admin key. Pass it as the third argument or set AC_ADMIN_KEY.")
        return 2

    value = io.open(path, encoding="utf-8").read()
    print("key   : %s" % key)
    print("source: %s (%d chars)" % (path, len(value)))

    body = json.dumps({"key": key, "value": value}).encode("utf-8")
    req = urllib.request.Request(
        BASE + "/v1/admin/text", data=body,
        headers={"Content-Type": "application/json", "X-AC-Admin-Key": admin_key})
    try:
        urllib.request.urlopen(req)
    except urllib.error.HTTPError as exc:
        print("FAILED %s: %s" % (exc.code, exc.read().decode("utf-8", "replace")[:300]))
        if exc.code == 500:
            print("\nA 500 here usually means the texts table does not exist yet.")
            print("Set AC_AUTO_MIGRATE=true in Vercel and redeploy once.")
        return 1

    # Read it back rather than trusting the write.
    with urllib.request.urlopen(BASE + "/v1/text/" + urllib.parse.quote(key)) as resp:
        got = json.load(resp).get("value", "")
    if got == value:
        print("OK - stored and verified byte for byte")
        return 0
    print("MISMATCH - stored %d chars, read back %d" % (len(value), len(got)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
