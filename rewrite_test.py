import os, tempfile, sys
os.environ.update(
    AC_SESSION_KEY="k"*64, AC_SERVER_KEY="s"*64, AC_ADMIN_KEY="a"*64,
    AC_META_APP_ID="1", AC_META_APP_SECRET="x",
    AC_DB_PATH=os.path.join(tempfile.mkdtemp(), "t.sqlite3"),
)
sys.path.insert(0, ".")
from api.index import app, RestoreOriginalPath

fail = []
def check(label, cond):
    print(("  ok   " if cond else "  FAIL ") + label)
    if not cond: fail.append(label)

def vercel_get(path, query="", headers=None):
    qs = "__original_path=" + path
    if query: qs += "&" + query
    return app.test_client().get("/api/index?" + qs, headers=headers or {})

print("routing (this is what was broken in production)")
r = vercel_get("/health")
check("/health -> 200", r.status_code == 200)
check("/health -> json", r.get_json().get("service") is not None)
check("/admin/detections -> 401 not 404", vercel_get("/admin/detections").status_code == 401)
check("POST route -> 405 not 404", vercel_get("/v1/session/challenge").status_code in (401,405))
r = app.test_client().get("/api/index/health")
check("/api/index/health fallback -> 200", r.status_code == 200)

print("query handling (middleware in isolation)")
seen = {}
def spy(environ, start_response):
    seen.update(PATH_INFO=environ["PATH_INFO"], QUERY_STRING=environ["QUERY_STRING"])
    start_response("200 OK", [("Content-Type","text/plain")]); return [b"ok"]
mw = RestoreOriginalPath(spy)
def run(qs, path="/api/index"):
    seen.clear()
    mw({"PATH_INFO": path, "QUERY_STRING": qs, "REQUEST_METHOD":"GET"}, lambda *a: None)
    return dict(seen)

out = run("__original_path=/admin/detections&limit=5&state=open")
check("path restored", out["PATH_INFO"] == "/admin/detections")
check("caller query preserved", sorted(out["QUERY_STRING"].split("&")) == ["limit=5","state=open"])
check("__original_path stripped", "__original_path" not in out["QUERY_STRING"])

out = run("__original_path=https://evil.test/admin/stats%3Fx%3D1")
check("absolute URL reduced to path only", out["PATH_INFO"] == "/admin/stats")

out = run("__original_path=/")
check("root path handled", out["PATH_INFO"] == "/")
out = run("")
check("no param leaves path alone", out["PATH_INFO"] == "/api/index")

print("404 no longer leaks credentials")
body = vercel_get("/nope").get_data(as_text=True)
check("json diagnostic present", "known_routes" in body)
check("no header VALUES in body", "Oidc" not in body and "Bearer" not in body and "eyJ" not in body)
check("header names only", "routing_header_names" in body)

print()
print("FAILED: %s" % fail if fail else "ALL PASSED")
