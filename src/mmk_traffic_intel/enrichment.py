"""Opt-in, rate-limited infrastructure enrichment.

Only selected source IPs are sent to RDAP when the CLI flag is provided. The
returned record is reduced to network facts; contact emails and raw URLs are
intentionally omitted from generated reports.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _read_cache(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_cache(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _reduce_rdap(payload: Dict[str, Any]) -> Dict[str, Any]:
    entities = payload.get("entities") or []
    roles = sorted({role for entity in entities if isinstance(entity, dict) for role in entity.get("roles", []) if isinstance(role, str)})
    return {
        "status": "ok",
        "registry": payload.get("port43") or payload.get("rdapConformance", [None])[0],
        "network_name": payload.get("name") or payload.get("handle"),
        "country": payload.get("country"),
        "start_address": payload.get("startAddress"),
        "end_address": payload.get("endAddress"),
        "roles_present": roles,
        "abuse_contact_present": "abuse" in roles,
    }


def lookup_rdap(ip: str, timeout: float = 8.0) -> Dict[str, Any]:
    request = Request(
        "https://rdap.org/ip/" + ip,
        headers={"Accept": "application/rdap+json", "User-Agent": "mmk-traffic-intel/0.1 local-investigation"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
        payload = json.loads(body)
        return _reduce_rdap(payload if isinstance(payload, dict) else {})
    except HTTPError as exc:
        return {"status": "unavailable", "reason": "http_" + str(exc.code)}
    except (URLError, TimeoutError, OSError, json.JSONDecodeError):
        return {"status": "unavailable", "reason": "lookup_failed"}


def enrich_ips(ips: Iterable[str], cache_path: Path, max_lookups: int = 20, delay_seconds: float = 0.35) -> Dict[str, Dict[str, Any]]:
    """Resolve at most ``max_lookups`` unique IPs and persist only reduced facts."""
    cache = _read_cache(cache_path)
    output: Dict[str, Dict[str, Any]] = {}
    candidates = list(dict.fromkeys(ip for ip in ips if ip))
    performed = 0
    for ip in candidates:
        if ip in cache and isinstance(cache[ip], dict):
            output[ip] = cache[ip]
            continue
        if performed >= max_lookups:
            output[ip] = {"status": "skipped", "reason": "lookup_budget"}
            continue
        output[ip] = lookup_rdap(ip)
        cache[ip] = output[ip]
        performed += 1
        if delay_seconds > 0 and performed < max_lookups:
            time.sleep(delay_seconds)
    _write_cache(cache_path, cache)
    return output
