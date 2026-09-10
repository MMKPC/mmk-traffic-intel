# Project Operating Notes

## Scope

MMK Traffic Intel is a local-first, privacy-preserving analyzer for web request
exports. It enriches infrastructure metadata and classifies behavior. It must
not claim to identify a person from an IP address.

## Safety Rules

- Never commit real Cloudflare exports, raw IP addresses, cookies, request
  bodies, tokens, or account identifiers.
- Keep network enrichment opt-in. The default test and demo path is offline.
- Do not add blanket country blocks or automated abuse reports.
- Treat country and city as probabilistic metadata, not a physical identity.
- Preserve upstream attribution for the vendored Logalytics dashboard.

## Ownership

- `src/mmk_traffic_intel/` owns parsing, normalization, redaction, enrichment,
  classification, and report generation.
- `dashboard/` is a read-only visual surface derived from Logalytics and must
  consume generated `data.json` without receiving secrets.
- `tests/` owns regression coverage for parser and privacy behavior.

## Verification

Run `python -m unittest discover -s tests -v` from the project root before
claiming completion. Use `python -m mmk_traffic_intel.cli` through the package
path shown in the README for fixture analysis.
