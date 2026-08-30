# Crab Tag anti-cheat backend

Server-side trust service. Nothing in here goes into the Unity project — the
game only gains three HTTP calls, all of which go through CloudScript.

## How the six requirements map

| You asked for | Where it lives | What actually makes it work |
|---|---|---|
| Runtime protection | `trust.evaluate_runtime` + `/v1/session/heartbeat` | Server-side plausibility maths on movement, teleports and tag rate. The client sends raw numbers; the server decides. |
| Root detection | `trust.evaluate_attestation` → `meta.device_integrity` | Meta's **signed** `device_integrity_state`. Blocked at `/v1/session/verify`, before a session token exists. |
| Device trust | `sessions` table + `device_unique_id` from claims | Trust level attached to a session, keyed to the attested device, revocable mid-game. |
| Integrity validation | `/v1/session/verify` *and* re-attestation inside `/v1/session/heartbeat` | `app_integrity_state` + `package_cert_sha256_digest`, re-checked on a fresh nonce throughout the session, not only at launch. |
| Detection routing | `routing.route` → `detections` table + Discord | Every signal persisted with severity/confidence/review state; block- and suspect-tier alerts pushed to Discord; `/admin/detections` is the review and analytics surface. |
| Session enforcement | `sessions.py` + `routing.enforce` | HMAC session tokens backed by a revocable row. Trust degrades live; revoking the row kills the session even though the token still verifies. |

## The one design rule

Every signal carries a **confidence tier**:

- `signed` — Meta signed it. A modified client cannot forge it.
- `observed` — we measured it (missed heartbeats, impossible movement, identity mismatch). A cheater can avoid producing one but cannot fake a clean one.
- `reported` — the client said so. Trivially forgeable.

`trust.enforceable()` refuses to auto-punish on `reported` evidence alone. This
matters in both directions: a cheater's client will simply report nothing, and
without the rule anyone could get another player banned by spoofing indicators.

Client-side root scans are therefore *inputs*, not verdicts. The verdict comes
from Meta.

## Deploy (Vercel + Neon, free)

Both free, both permanent, no card. Vercel runs the API; Supabase holds the
data. They are separate because the free tiers that are good at one are bad at
the other.

**SQLite is for local dev only.** Vercel's filesystem is ephemeral — SQLite
there loses the `enforcements` table, which is the ban-evasion history the IP
escalation depends on.

### 1. Database — Neon

1. neon.tech → New project
2. Connection Details → copy the connection string
3. **Use the pooled one** — its host contains `-pooler`.

   Serverless creates many short-lived connections and the direct endpoint will
   exhaust Postgres connection slots under load. (On a long-lived host like
   Render, the direct endpoint is correct instead.)

That string is `AC_DATABASE_URL`.

Free plan: permanent, no card. 0.5 GB storage, 5 GB egress, 100 CU-hours/month.

Compute is billed only while the database is awake and scales to zero after 5
minutes idle, so at the 0.25 CU floor that allowance is roughly 400 active
hours. Bursty play sits well inside it. If you ever do exceed a monthly limit
Neon suspends compute until the next billing period — which is exactly what the
database fail-open below exists for: players get `trust: watch`, not a locked
door.

### 2. Create the schema, once

```
AC_DATABASE_URL="postgresql://...-pooler.../neondb" python migrate.py
```

Then set `AC_AUTO_MIGRATE=false` so cold starts skip the DDL.

### 3. API — Vercel

1. Push this folder to a GitHub repo
2. vercel.com → **Add New Project** → import the repo
3. Framework preset **Other** — `vercel.json` handles the routing
4. Settings → Environment Variables → add everything from `.env.example`
5. Deploy, then `curl https://YOURAPP.vercel.app/health`

`api/index.py` exposes the Flask app to Vercel's Python runtime; `vercel.json`
rewrites every path to it. Nothing else to configure.

Generate each key with `openssl rand -hex 32`. Leaving any blank makes the
service log `REFUSING TO TRUST ANYTHING` and reject attestations — the safe
direction.

### Host options, as of now

| Host | Verdict |
|---|---|
| **Vercel + Neon** | Recommended. ~1s cold start, both permanently free, no card. |
| **Render + Neon** | Also works, `Procfile` included — but sleeps after 15 min idle, so the first login after a quiet spell waits 30–60s. Use the direct endpoint there, not the pooler. |
| **Oracle Cloud Free** | Always-free VM, no cold start, SQLite stays viable. Most setup work. |
| ~~Koyeb~~ | Closed to new signups — acquired by Mistral, Feb 2026. |
| ~~Render free Postgres~~ | Deleted after 30 days. Fine as a web host, not as the database. |
| **Supabase** | Equivalent swap if you ever want it — 500 MB, pauses after 7 days idle. |

| **Supabase / Aiven** | Equivalent Postgres swaps — only `AC_DATABASE_URL` changes. |
| ~~Fly.io / Railway~~ | No longer truly free. |

### Retention

`detections` only grows and free Postgres is small. Point any scheduler
(GitHub Action, cron-job.org, Vercel Cron) at:

```
POST /admin/prune   X-AC-Admin-Key: <key>   {"days": 30}
```

Rows reviewed as `confirmed` or `actioned` are kept as the evidence trail;
routine noise ages out. `GET /admin/stats` shows current row counts.

## Wire-up

Three CloudScript handlers call this; the game never holds a backend secret.

```
Game                 CloudScript                  This service            Meta
 |  MetaIssueChallenge -> |  POST /v1/session/challenge -> |
 |  <----------------- nonce ------------------------------|
 |-- GetIntegrityToken(nonce) ------------------------------------------> |
 |  MetaVerifyAttestation -> | POST /v1/session/verify ---> | verify ----> |
 |  <-------------- session_token + trust ------------------|
 |  (every 120s) --------> | POST /v1/session/heartbeat --> |
```

`X-AC-Server-Key` goes in PlayFab **Title Internal Data**, never in the client.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | liveness + whether enforcing |
| POST | `/v1/session/challenge` | server key | issue a CSPRNG nonce bound to a PlayFabId |
| POST | `/v1/session/verify` | server key | verify token, score, open session |
| POST | `/v1/session/heartbeat` | session token | re-attest + runtime telemetry |
| GET | `/v1/session/<id>/trust` | server key | gate rewards on live trust |
| POST | `/v1/session/end` | session token | close cleanly |
| GET | `/admin/detections` | admin key | review queue / analytics |
| POST | `/admin/detections/<id>/review` | admin key | confirm / dismiss / action |
| POST | `/admin/enforce` | admin key | manual ban, works even with `AC_ENFORCE=false` |
| POST | `/admin/prune` | admin key | retention sweep |
| GET | `/admin/stats` | admin key | row counts per table |

## Rollout

`AC_ENFORCE=false` first — same discipline as `MetaEnforce`. The service scores
and routes everything but only reports `"action": "audit_only"`.

Leave the three `AC_META_ALLOWED_*` lists **blank** initially; blank means allow
anything. Watch `/admin/detections`, read the real `app_integrity_state`,
`device_integrity_state` and cert digest your build produces, fill them in, then
set `AC_ENFORCE=true`. Guessing those strings locks out every player at once.

## Failure behaviour

Everything degrades open except a token Meta actively rejected.

- Meta unreachable → HTTP 503, trust `watch`, nobody punished
- Meta **rejects** the token → HTTP 403, `blocked` (a verdict, not an outage)
- **Database unavailable** → HTTP 503, trust `watch`. Free tiers suspend
  themselves; an anti-cheat that 500s in that state locks out honest players
  while the cheater just stops calling. Evidence-only writes drop silently
  rather than fail a login.
- PlayFab or Discord unreachable → logged, never breaks the request
- Rotating `AC_SESSION_KEY` invalidates every live session — the emergency lever

## Tuning

The thresholds in `config.py` and the limits in `trust.evaluate_runtime`
(`max_speed_mps`, `max_teleport_m`, `max_tags_per_minute`) are placeholders.
Run in audit mode, look at what real players produce, then tighten. Shipping
these numbers unchecked will generate false positives.

## Test

`python smoke_test.py` — runs the real code paths with Meta stubbed. 21 checks,
all passing: auth separation, single-use challenges, forged tokens,
root→blocked, runtime heuristics, client-reported evidence never auto-enforcing,
retention keeping confirmed evidence, and database-outage fail-open (including
inside `require_session`, where the decorator order matters).

## Not included

- No client-side scanning code (backend-only, as asked — and the signed
  device signal is worth more than a spoofable local scan)
- No CloudScript handlers or Unity heartbeat loop yet — say the word
- Rate limiting — add PythonAnywhere-level throttling or a `flask-limiter`
- Telemetry is trusted as *values*; the plausibility maths is what makes it
  useful. A cheater who reports honest-looking numbers passes, which is why the
  signed Meta signals carry the weight.
