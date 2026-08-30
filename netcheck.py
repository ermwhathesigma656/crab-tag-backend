"""
Network reputation: VPN, proxy, Tor and datacenter detection.

Used for ban-evasion context, not as a ban reason on its own. Plenty of honest
players use a VPN, and plenty of cheaters do not - so a VPN flag raises the
score and colours the moderator's view, while the thing that actually catches
evasion is the signed device id (see trust.evaluate_evasion).

Provider is pluggable. proxycheck.io is the default: 1,000 free lookups a day
without a key, and it distinguishes VPN from datacenter from Tor.

Results are cached in the database, because the same handful of addresses show
up over and over and the free quota is small.
"""
import json

import requests

import db
from config import config

PROXYCHECK_URL = "https://proxycheck.io/v2/%s"
VPNAPI_URL = "https://vpnapi.io/api/%s"


class NetworkVerdict(object):
    __slots__ = ("ip", "is_vpn", "is_proxy", "is_tor", "is_hosting",
                 "provider", "country", "risk", "source", "checked")

    def __init__(self, ip, **kw):
        self.ip = ip
        self.is_vpn = kw.get("is_vpn", False)
        self.is_proxy = kw.get("is_proxy", False)
        self.is_tor = kw.get("is_tor", False)
        self.is_hosting = kw.get("is_hosting", False)
        self.provider = kw.get("provider") or ""
        self.country = kw.get("country") or ""
        self.risk = kw.get("risk")
        self.source = kw.get("source") or "none"
        self.checked = kw.get("checked", False)

    @property
    def anonymised(self):
        return self.is_vpn or self.is_proxy or self.is_tor or self.is_hosting

    def as_dict(self):
        return {
            "ip": self.ip, "is_vpn": self.is_vpn, "is_proxy": self.is_proxy,
            "is_tor": self.is_tor, "is_hosting": self.is_hosting,
            "provider": self.provider, "country": self.country,
            "risk": self.risk, "source": self.source, "checked": self.checked,
        }


def _unchecked(ip, why):
    return NetworkVerdict(ip, source=why, checked=False)


def _query_proxycheck(ip):
    params = {"vpn": "1", "asn": "1", "risk": "1"}
    if config.PROXYCHECK_API_KEY:
        params["key"] = config.PROXYCHECK_API_KEY
    resp = requests.get(PROXYCHECK_URL % ip, params=params,
                        timeout=config.HTTP_TIMEOUT_SECONDS)
    payload = resp.json()
    if payload.get("status") not in ("ok", "warning"):
        raise ValueError(payload.get("message") or payload.get("status"))
    node = payload.get(ip) or {}
    ptype = (node.get("type") or "").lower()
    return NetworkVerdict(
        ip,
        is_vpn=node.get("proxy") == "yes" and ptype == "vpn",
        is_proxy=node.get("proxy") == "yes",
        is_tor=ptype == "tor",
        is_hosting=ptype in ("hosting", "business"),
        provider=node.get("provider") or node.get("organisation") or "",
        country=node.get("isocode") or "",
        risk=node.get("risk"),
        source="proxycheck", checked=True,
    )


def _query_vpnapi(ip):
    if not config.VPNAPI_KEY:
        raise ValueError("no vpnapi key")
    resp = requests.get(VPNAPI_URL % ip, params={"key": config.VPNAPI_KEY},
                        timeout=config.HTTP_TIMEOUT_SECONDS)
    payload = resp.json()
    sec = payload.get("security") or {}
    net = payload.get("network") or {}
    loc = payload.get("location") or {}
    return NetworkVerdict(
        ip,
        is_vpn=bool(sec.get("vpn")), is_proxy=bool(sec.get("proxy")),
        is_tor=bool(sec.get("tor")), is_hosting=bool(sec.get("relay")),
        provider=net.get("autonomous_system_organization") or "",
        country=loc.get("country_code") or "",
        source="vpnapi", checked=True,
    )


_PROVIDERS = {"proxycheck": _query_proxycheck, "vpnapi": _query_vpnapi}


def _is_private(ip):
    if not ip:
        return True
    if ip.startswith(("10.", "127.", "192.168.", "172.16.", "172.17.",
                      "172.18.", "172.19.", "172.2", "172.30.", "172.31.",
                      "169.254.", "::1", "fc", "fd")):
        return True
    return False


def lookup(ip, max_age_seconds=None):
    """
    Never raises. An unreachable reputation service returns checked=False, which
    scores nothing - a third party being down must not decide whether a player
    gets to play.
    """
    max_age = max_age_seconds or config.IP_INTEL_TTL_SECONDS

    if not config.NETCHECK_ENABLED:
        return _unchecked(ip, "disabled")
    if _is_private(ip):
        return _unchecked(ip, "private")

    cached = db.quiet(db.get_ip_intel, ip, max_age)
    if cached:
        try:
            return NetworkVerdict(ip, **json.loads(cached))
        except (ValueError, TypeError):
            pass

    provider = _PROVIDERS.get(config.NETCHECK_PROVIDER)
    if provider is None:
        return _unchecked(ip, "no provider")

    try:
        verdict = provider(ip)
    except (requests.RequestException, ValueError, KeyError) as exc:
        return _unchecked(ip, "lookup failed: %s" % str(exc)[:80])

    db.quiet(db.store_ip_intel, ip, json.dumps(verdict.as_dict()))
    return verdict
