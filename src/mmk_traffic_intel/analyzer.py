"""Normalize request exports into a privacy-safe Logalytics data payload.

The analyzer intentionally separates facts from inference. Country, ASN, and
organization values come from the input or an opt-in enrichment provider;
traffic intent is a transparent heuristic and never an identity claim.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import re
import secrets
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit


FIELD_ALIASES = {
    "timestamp": ("EdgeStartTimestamp", "ClientRequestStartTimestamp", "timestamp", "time", "datetime"),
    "ip": ("ClientIP", "client_ip", "clientIP", "ip", "remote_addr", "origin_ip"),
    "host": ("ClientRequestHost", "host", "hostname"),
    "method": ("ClientRequestMethod", "method", "http_method"),
    "uri": ("ClientRequestURI", "ClientRequestPath", "uri", "path", "request_uri"),
    "status": ("EdgeResponseStatus", "OriginResponseStatus", "status", "status_code"),
    "user_agent": ("ClientRequestUserAgent", "UserAgent", "user_agent", "userAgent", "agent"),
    "referer": ("ClientRequestReferer", "referer", "referrer"),
    "country": ("ClientCountry", "country", "country_code", "countryCode"),
    "city": ("ClientCity", "city"),
    "asn": ("ClientASN", "asn", "asn_number", "autonomous_system_number"),
    "asn_name": ("ClientASNDescription", "asn_name", "asn_org", "organization", "isp"),
    "rdns": ("ClientReverseDNS", "rdns", "hostname_reverse", "reverse_dns"),
    "action": ("SecurityAction", "action", "security_action"),
    "rule_id": ("SecurityRuleID", "rule_id", "rule"),
    "bot_score": ("BotScore", "bot_score"),
    "verified_bot": ("BotScoreSrc", "verified_bot", "bot_verified"),
    "colo": ("EdgeColoName", "colo", "edge_colo"),
    "ja4": ("JA4", "ja4", "ja4_hash"),
}

BOT_PATTERN = re.compile(
    r"bot|crawler|spider|slurp|curl|python-requests|httpx|go-http-client|"
    r"wget|zgrab|masscan|nmap|censys|shodan|internet-measurement|uptime|"
    r"monitor|lighthouse|headless|facebookexternalhit|semrush|ahrefs|"
    r"bingpreview|googlebot|applebot|gptbot|claudebot|bytespider",
    re.IGNORECASE,
)

HOSTING_PATTERN = re.compile(
    r"amazon|aws|google|microsoft|azure|oracle|digitalocean|linode|hetzner|"
    r"ovh|leaseweb|vultr|contabo|akamai|scaleway|cloudflare|hosting|"
    r"datacenter|data center|server|vps|dedicated|network",
    re.IGNORECASE,
)

MALICIOUS_PATHS = (
    (re.compile(r"wp-admin|wp-login|wp-content|wp-includes|wordpress|xmlrpc", re.I), "WordPress probe"),
    (re.compile(r"\.env|\.git|\.config|config\.php|web\.config|backup", re.I), "Config or secret probe"),
    (re.compile(r"cgi-bin|bin/sh|cmd\.exe|shell|\.asp|\.jsp", re.I), "RCE or shell probe"),
    (re.compile(r"phpmyadmin|adminer|\.sql|\.sqlite|\.db", re.I), "Database probe"),
    (re.compile(r"\.aws|\.kube|identity|token", re.I), "Cloud credential probe"),
)

COUNTRY_NAMES = {
    "FR": "France",
    "US": "United States",
    "SG": "Singapore",
    "DE": "Germany",
    "BR": "Brazil",
    "CA": "Canada",
    "GB": "United Kingdom",
    "IN": "India",
    "JP": "Japan",
    "AU": "Australia",
}


def _first(record: Dict[str, Any], key: str, default: Any = None) -> Any:
    lowered = {str(k).lower(): v for k, v in record.items()}
    for alias in FIELD_ALIASES[key]:
        if alias.lower() in lowered and lowered[alias.lower()] not in (None, ""):
            return lowered[alias.lower()]
    return default


def _parse_timestamp(value: Any) -> float:
    if value is None or value == "":
        return 0.0
    if isinstance(value, (int, float)):
        number = float(value)
        return number / 1000 if number > 10_000_000_000 else number
    text = str(value).strip()
    try:
        return _parse_timestamp(float(text))
    except ValueError:
        pass
    normalized = text.replace("Z", "+00:00")
    if normalized.endswith("+0000"):
        normalized = normalized[:-5] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                parsed = None
        if parsed is None:
            return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _normalize_path(value: Any) -> str:
    if not value:
        return "/"
    path = urlsplit(str(value)).path or "/"
    path = re.sub(r"/{2,}", "/", path)
    return "".join(char for char in path if char.isprintable())[:512]


def _country_name(value: Any) -> str:
    code = str(value or "ZZ").upper()
    return COUNTRY_NAMES.get(code, code)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _redact_ip(ip: str, salt: str) -> str:
    if not ip or not _is_ip(ip):
        return "unknown-source"
    digest = hashlib.sha256((salt + ip).encode("utf-8")).hexdigest()[:12]
    return "source_" + digest


def _verified_bot(value: Any) -> bool:
    text = str(value or "").lower()
    return "verified" in text or text in {"true", "1", "yes"}


def _classify(event: Dict[str, Any]) -> Tuple[str, List[str], bool, bool, bool]:
    ua = event["user_agent"]
    identity = " ".join(str(event.get(key) or "") for key in ("ua", "asn_name", "rdns"))
    path = event["path"]
    tags: List[str] = []
    bot = bool(event.get("bot_score") is not None and event["bot_score"] <= 30) or bool(BOT_PATTERN.search(ua))
    verified = _verified_bot(event.get("verified_bot"))
    hosting = bool(HOSTING_PATTERN.search(identity))
    malicious_label = None
    for pattern, label in MALICIOUS_PATHS:
        if pattern.search(path):
            malicious_label = label
            break
    blocked = str(event.get("action") or "").lower() in {"block", "blocked", "challenge", "managed_challenge"}
    if verified:
        tags.append("verified-bot")
    elif bot:
        tags.append("automated")
    if hosting:
        tags.append("hosting-network")
    if blocked:
        tags.append("edge-mitigated")
    if malicious_label:
        tags.append("scanner")
        return "Active Scanning", tags, bot, hosting, True
    if blocked:
        return "Edge Mitigated", tags, bot, hosting, False
    if bot and hosting:
        return "Hosting Automation", tags, bot, hosting, False
    if bot:
        return "Crawler or Bot", tags, bot, hosting, False
    if hosting:
        return "Hosting Infrastructure", tags, bot, hosting, False
    return "Browser Traffic", tags, bot, hosting, False


def load_records(path: Path) -> List[Dict[str, Any]]:
    """Load Cloudflare JSON/NDJSON or CSV exports without executing input."""
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if path.suffix.lower() == ".csv":
        return [dict(row) for row in csv.DictReader(text.splitlines())]
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows
    if isinstance(decoded, list):
        return [row for row in decoded if isinstance(row, dict)]
    if isinstance(decoded, dict):
        for key in ("data", "events", "records", "result", "items"):
            value = decoded.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
        return [decoded]
    raise ValueError("Input must be a JSON object, JSON array, NDJSON file, or CSV export")


def _normalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    bot_score = _first(record, "bot_score")
    try:
        bot_score = float(bot_score) if bot_score not in (None, "") else None
    except (TypeError, ValueError):
        bot_score = None
    asn = _first(record, "asn")
    try:
        asn = int(float(asn)) if asn not in (None, "") else None
    except (TypeError, ValueError):
        asn = None
    status = _first(record, "status", 0)
    try:
        status = int(float(status))
    except (TypeError, ValueError):
        status = 0
    return {
        "timestamp": _parse_timestamp(_first(record, "timestamp")),
        "ip": str(_first(record, "ip", "")),
        "host": str(_first(record, "host", "")),
        "method": str(_first(record, "method", "GET")).upper(),
        "path": _normalize_path(_first(record, "uri", "/")),
        "status": status,
        "user_agent": str(_first(record, "user_agent", ""))[:512],
        "referer": str(_first(record, "referer", ""))[:512],
        "country": str(_first(record, "country", "ZZ")).upper()[:3],
        "city": str(_first(record, "city", ""))[:128],
        "asn": asn,
        "asn_name": str(_first(record, "asn_name", ""))[:256],
        "rdns": str(_first(record, "rdns", ""))[:256],
        "action": str(_first(record, "action", "")),
        "rule_id": str(_first(record, "rule_id", ""))[:128],
        "bot_score": bot_score,
        "verified_bot": _first(record, "verified_bot", ""),
        "colo": str(_first(record, "colo", ""))[:32],
        "ja4": str(_first(record, "ja4", ""))[:128],
    }


def analyze(records: Iterable[Dict[str, Any]], keep_ip: bool = False, enrichment: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    salt = secrets.token_hex(16)
    normalized = [_normalize_record(record) for record in records]
    normalized = [record for record in normalized if record["ip"] and record["timestamp"]]
    normalized.sort(key=lambda record: record["timestamp"])
    sessions: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
    country_counts: Dict[str, Counter] = defaultdict(Counter)
    hourly: Dict[int, Dict[str, Any]] = {}
    notable: Dict[str, Dict[str, Any]] = {}
    top_paths = Counter()
    methods = Counter()
    actions = Counter()
    user_agents = Counter()
    source_stats: Dict[str, Dict[str, Any]] = {}

    for event in normalized:
        intent, tags, bot, hosting, malicious = _classify({**event, "ua": event["user_agent"]})
        event["intent"] = intent
        event["tags"] = tags
        event["is_bot"] = bot
        event["is_hosting"] = hosting
        event["is_malicious"] = malicious
        event["is_blocked"] = "edge-mitigated" in tags
        country = event["country"]
        country_counts[country]["malicious" if malicious else "bots" if bot else "legit"] += 1
        top_paths[event["path"]] += 1
        methods[event["method"]] += 1
        if event["action"]:
            actions[event["action"]] += 1
        user_agents[event["user_agent"] or "(empty)"] += 1
        source = source_stats.setdefault(event["ip"], {
            "requests": 0,
            "first_seen": event["timestamp"],
            "last_seen": event["timestamp"],
            "country": country,
            "city": event["city"],
            "asn": event["asn"],
            "asn_name": event["asn_name"],
            "rdns": event["rdns"],
            "bots": 0,
            "hosting": 0,
            "malicious": 0,
            "blocked": 0,
            "intents": Counter(),
            "paths": Counter(),
            "user_agents": Counter(),
        })
        source["requests"] += 1
        source["last_seen"] = event["timestamp"]
        source["bots"] += int(bot)
        source["hosting"] += int(hosting)
        source["malicious"] += int(malicious)
        source["blocked"] += int(event["is_blocked"])
        source["intents"][intent] += 1
        source["paths"][event["path"]] += 1
        source["user_agents"][event["user_agent"] or "(empty)"] += 1
        hour = int(event["timestamp"] // 3600) * 3600
        bucket = hourly.setdefault(hour, {"total": 0, "bots": 0, "blocked": 0, "malicious": 0, "countries": Counter()})
        bucket["total"] += 1
        bucket["bots"] += int(bot)
        bucket["blocked"] += int(event["is_blocked"])
        bucket["malicious"] += int(malicious)
        bucket["countries"][country] += 1
        key = (event["ip"], event["user_agent"], int(event["timestamp"] // 300))
        session = sessions.setdefault(
            key,
            {
                "raw_ip": event["ip"],
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "req_count": 0,
                "paths": [],
                "tags": set(),
                "country": country,
                "city": event["city"],
                "asn": event["asn"],
                "asn_name": event["asn_name"],
                "rdns": event["rdns"],
                "user_agent": event["user_agent"],
                "intent": intent,
                "is_bot": bot,
                "is_verified_bot": _verified_bot(event.get("verified_bot")),
                "is_hosting": hosting,
                "is_malicious": malicious,
                "is_blocked": event["is_blocked"],
            },
        )
        session["last_seen"] = event["timestamp"]
        session["req_count"] += 1
        session["tags"].update(tags)
        for path in [event["path"]]:
            if path not in session["paths"] and len(session["paths"]) < 10:
                session["paths"].append(path)
        session["is_malicious"] = session["is_malicious"] or malicious
        session["is_blocked"] = session["is_blocked"] or event["is_blocked"]
        session["is_verified_bot"] = session["is_verified_bot"] or _verified_bot(event.get("verified_bot"))
        if event["asn"] or event["asn_name"] or event["rdns"]:
            label = f"ASN: AS{event['asn'] or '?'} ({event['asn_name'] or event['rdns'] or 'unknown'}) | Confidence: infrastructure metadata only | Actor: unknown"
            entry = notable.setdefault(label, {"ips": set(), "count": 0})
            entry["ips"].add(event["ip"])
            entry["count"] += 1

    output_sessions = []
    for session in sessions.values():
        duration = max(1.0, session["last_seen"] - session["first_seen"])
        public_ip = session["raw_ip"] if keep_ip else _redact_ip(session["raw_ip"], salt)
        output_sessions.append(
            {
                "origin_ip": public_ip,
                "edge_ip": public_ip,
                "geo": {
                    "city": session["city"],
                    "country": _country_name(session["country"]),
                    "country_code": session["country"],
                    "hostname": session["rdns"],
                    "asn": session["asn"],
                    "asn_name": session["asn_name"],
                "is_bot": session["is_bot"],
                    "is_verified_bot": session["is_verified_bot"],
                    "is_cloud": bool(re.search(r"amazon|aws|google|microsoft|azure|oracle", session["asn_name"] or "", re.I)),
                    "is_hosting": session["is_hosting"],
                    "lat": None,
                    "lon": None,
                },
                "first_seen": session["first_seen"],
                "last_seen": session["last_seen"],
                "intent": session["intent"],
                "tags": sorted(session["tags"]),
                "is_malicious": session["is_malicious"],
                "is_blocked": session["is_blocked"],
                "req_count": session["req_count"],
                "req_rate": round(session["req_count"] / duration, 3),
                "is_spike": session["req_count"] >= 20 or session["req_count"] / duration > 5.0,
                "first_seen_iso": datetime.fromtimestamp(session["first_seen"], timezone.utc).isoformat(),
                "last_seen_iso": datetime.fromtimestamp(session["last_seen"], timezone.utc).isoformat(),
                "path_summary": session["paths"],
                "user_agent": session["user_agent"],
            }
        )
    output_sessions.sort(key=lambda item: item["last_seen"], reverse=True)
    timeline = []
    for hour, bucket in sorted(hourly.items()):
        timeline.append({
            "hour": datetime.fromtimestamp(hour, timezone.utc).isoformat(),
            "total": bucket["total"],
            "bots": bucket["bots"],
            "blocked": bucket["blocked"],
            "malicious": bucket["malicious"],
            "countries": dict(bucket["countries"]),
        })
    summary_countries = {}
    for country, counts in country_counts.items():
        summary_countries[country] = {
            "legit": counts.get("legit", 0),
            "bots": counts.get("bots", 0),
            "malicious": counts.get("malicious", 0),
            "name": _country_name(country),
        }
    source_intelligence = []
    for ip, source in sorted(source_stats.items(), key=lambda item: item[1]["requests"], reverse=True):
        source_id = ip if keep_ip else _redact_ip(ip, salt)
        source_entry = {
            "source_id": source_id,
            "requests": source["requests"],
            "first_seen": datetime.fromtimestamp(source["first_seen"], timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(source["last_seen"], timezone.utc).isoformat(),
            "country": source["country"],
            "country_name": _country_name(source["country"]),
            "city": source["city"],
            "asn": source["asn"],
            "asn_name": source["asn_name"],
            "rdns": source["rdns"],
            "signals": {
                "bot_requests": source["bots"],
                "hosting_requests": source["hosting"],
                "malicious_path_requests": source["malicious"],
                "edge_mitigated_requests": source["blocked"],
            },
            "intents": dict(source["intents"]),
            "top_paths": [{"path": path, "requests": count} for path, count in source["paths"].most_common(10)],
            "top_user_agents": [{"user_agent": ua, "requests": count} for ua, count in source["user_agents"].most_common(5)],
        }
        if enrichment and ip in enrichment:
            source_entry["rdap"] = enrichment[ip]
        source_intelligence.append(source_entry)
    investigation = {
        "privacy": {
            "ip_mode": "raw-local-only" if keep_ip else "pseudonymized",
            "query_strings_removed": True,
            "request_bodies_discarded": True,
            "public_safe": not keep_ip,
        },
        "timeline": timeline,
        "top_paths": [{"path": path, "requests": count} for path, count in top_paths.most_common(25)],
        "methods": dict(methods),
        "actions": dict(actions),
        "top_user_agents": [{"user_agent": ua, "requests": count} for ua, count in user_agents.most_common(20)],
        "sources": source_intelligence,
        "limits": {"identity_claim": "not supported", "geolocation": "network metadata only"},
    }
    return {
        "sessions": output_sessions,
        "summary": {
            "countries": summary_countries,
            "total_requests": len(normalized),
            "unique_origin_ips": len({event["ip"] for event in normalized}),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        "notable": [
            {"label": label, "ips": [ip if keep_ip else _redact_ip(ip, salt) for ip in sorted(entry["ips"])], "count": len(entry["ips"])}
            for label, entry in notable.items()
        ],
        "investigation": investigation,
    }


def write_json(payload: Dict[str, Any], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
