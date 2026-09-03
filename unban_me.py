"""
Lift an IP / device / account ban.

    python unban_me.py <ADMIN_KEY>

Clears the bans on this headset and its last known address so a false
positive is recoverable. The PlayFab account ban is separate and is revoked
from the PlayFab dashboard or the Admin API.
"""
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("AC_BASE_URL", "https://crab-tag-backend.vercel.app")
DEVICE = "046ed1d3f7b33525144acb96886755172ce3c2fd5300fa9d49fd4ac8f96a4bca"
PLAYFAB = "10F5234B79CDDF6F"
IP = "38.248.64.15"


def post(path, body, key):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-AC-Admin-Key": key})
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as exc:
        return {"error": exc.code, "detail": exc.read().decode("utf-8", "replace")[:200]}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    key = sys.argv[1]
    print("unban:", post("/v1/admin/unban",
                         {"ip": IP, "device_id": DEVICE, "playfab_id": PLAYFAB}, key))
    print("unbind:", post("/v1/admin/unbind", {"device_id": DEVICE}, key))
    return 0


if __name__ == "__main__":
    sys.exit(main())
