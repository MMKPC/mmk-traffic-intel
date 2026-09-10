# Threat Model

## Purpose

The tool helps an operator understand automated web traffic without exposing
private logs in a public portfolio repository.

## Protected data

- source IP addresses
- request query strings and bodies
- cookies, authorization headers, Ray IDs, and account identifiers
- private hostnames and internal paths

## Default controls

- input is parsed as data, never executed
- query strings are removed
- source IPs are pseudonymized with a per-run salt
- public fixtures use documentation-only address ranges
- no network enrichment runs unless explicitly requested
- no country-wide blocks or abuse reports are automated

## Main failure modes

1. A real export is committed to GitHub.
2. A geolocation record is mistaken for a person or exact location.
3. A reputation provider is treated as ground truth.
4. A legitimate bot is blocked because it looks automated.
5. A public dashboard exposes raw source IPs or sensitive paths.

## Response

Run the public-data check before publishing:

```powershell
$json = Get-Content -Raw dashboard/data.json
if($json -match 'ClientIP|RayID|request_body|cookie|198\.51\.100\.7|203\.0\.113\.42') { throw 'Sensitive or fixture source data detected' }
```

Investigations should correlate request path, method, user-agent, ASN,
country, status, and recurrence before any block or escalation decision.
