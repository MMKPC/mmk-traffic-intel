"""Command line entry point for MMK Traffic Intel."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import analyze, load_records, write_json
from .enrichment import enrich_ips


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze a Cloudflare or web-server request export locally.")
    parser.add_argument("input", type=Path, help="JSON, NDJSON, or CSV request export")
    parser.add_argument("--output", type=Path, default=Path("dashboard/data.json"), help="Generated Logalytics-compatible JSON")
    parser.add_argument("--keep-ip", action="store_true", help="Keep raw IPs; use only for private local reports")
    parser.add_argument("--enrich-rdap", action="store_true", help="Opt in to RDAP lookups for selected source IPs")
    parser.add_argument("--max-rdap-lookups", type=int, default=20, help="Maximum unique RDAP lookups (default: 20)")
    parser.add_argument("--rdap-cache", type=Path, default=Path(".cache/rdap.json"), help="Local RDAP cache file")
    parser.add_argument("--pretty-report", type=Path, help="Also write a short human-readable report")
    return parser


def _report(payload: dict) -> str:
    summary = payload["summary"]
    countries = sorted(
        summary["countries"].items(),
        key=lambda item: sum(item[1].get(key, 0) for key in ("legit", "bots", "malicious")),
        reverse=True,
    )
    lines = [
        "MMK Traffic Intel report",
        "========================",
        f"Requests: {summary['total_requests']}",
        f"Unique sources: {summary['unique_origin_ips']}",
        f"IP mode: {payload['investigation']['privacy']['ip_mode']}",
        "",
        "Countries:",
    ]
    for code, counts in countries[:10]:
        total = sum(counts.get(key, 0) for key in ("legit", "bots", "malicious"))
        lines.append(f"- {counts['name']} ({code}): {total} requests; bots={counts['bots']}; malicious-path={counts['malicious']}")
    lines += ["", "Top paths:"]
    for item in payload["investigation"]["top_paths"][:10]:
        lines.append(f"- {item['path']}: {item['requests']}")
    lines += ["", "This report describes infrastructure and request behavior; it does not identify people."]
    return "\n".join(lines) + "\n"


def main() -> int:
    args = build_parser().parse_args()
    records = load_records(args.input)
    enrichment = None
    if args.enrich_rdap:
        raw_ips = {str(record.get("ClientIP") or record.get("client_ip") or record.get("ip") or "") for record in records}
        print("RDAP enrichment is enabled: selected source IPs will be sent to rdap.org.")
        enrichment = enrich_ips(raw_ips, cache_path=args.rdap_cache, max_lookups=max(0, args.max_rdap_lookups))
    payload = analyze(records, keep_ip=args.keep_ip, enrichment=enrichment)
    write_json(payload, args.output)
    if args.pretty_report:
        args.pretty_report.parent.mkdir(parents=True, exist_ok=True)
        args.pretty_report.write_text(_report(payload), encoding="utf-8")
    print(json.dumps({"input_records": len(records), "output": str(args.output), "public_safe": not args.keep_ip}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
