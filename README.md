# MMK Traffic Intel

Local-first web traffic investigation for understanding **what kind of
infrastructure is contacting a site**, how often it returns, and which request
patterns deserve attention.

This project combines a read-only Logalytics dashboard with a privacy-safe
Python ingest layer. It can read Cloudflare-style JSON/NDJSON exports and CSV
files, remove query strings, pseudonymize source IPs, cluster requests into
short sessions, classify common bot/scanner patterns, and produce a dashboard
payload plus a text report.

## What it can and cannot tell you

It can show:

- source-country and ASN metadata supplied by the log export
- hosting or cloud indicators
- user-agent and request-method patterns
- repeated paths, request bursts, blocks, and challenges
- hourly history grouped by country and behavior
- infrastructure-only attribution with an explicit unknown-actor label

It cannot identify a person, prove intent from a country, or turn a hosting
network into a confirmed attacker. A city on an IP geolocation record is an
estimate, not a physical identity.

## Quick start

The default path is offline and uses only the synthetic fixture:

```powershell
python -m unittest discover -s tests -v
$env:PYTHONPATH = "src"
python -m mmk_traffic_intel.cli fixtures/cloudflare.sample.ndjson `
  --output dashboard/data.json `
  --pretty-report reports/demo-report.txt
python -m http.server 8788 --directory dashboard
```

Open `http://localhost:8788` to view the synthetic public demo. The dashboard
is derived from Logalytics and is included with attribution in
`THIRD_PARTY_NOTICES.md`.

For a real Cloudflare export, keep the result private and pseudonymized:

```powershell
$env:PYTHONPATH = "src"
python -m mmk_traffic_intel.cli "C:\path\to\cloudflare-export.ndjson" `
  --output reports/private/mmkprospects.data.json `
  --pretty-report reports/private/mmkprospects.txt
```

To view a private generated payload locally, copy it into the dashboard folder
and use an explicit query parameter, for example:

`http://localhost:8788/?data=mmkprospects.data.json`

The default dashboard path always loads `public-demo.json`.

`--keep-ip` exists only for a local investigation. It marks the generated
payload as not public-safe and should never be used for a repository fixture.

## Enrichment boundary

The repository does not silently send IP addresses to outside services. RDAP
enrichment is available only through an explicit flag and sends selected source
addresses to `rdap.org`, with a local cache and a lookup budget. It returns
reduced network facts and omits contact emails. BGP, reverse DNS, and abuse
intelligence remain future opt-in adapters. Without `--enrich-rdap`, the
analyzer uses only metadata already present in the export.

```powershell
$env:PYTHONPATH = "src"
python -m mmk_traffic_intel.cli "C:\path\to\cloudflare-export.ndjson" `
  --enrich-rdap --max-rdap-lookups 20 `
  --output reports/private/enriched.data.json
```

This keeps the complete Cloudflare export under your control while making the
network boundary visible in the command itself.

The downloaded `howismyip` project is retained outside this public project as a
reference for multi-source enrichment. It should be run only against selected
source addresses, never against a raw private export.

## Public-repository rules

- Commit synthetic fixtures only.
- Do not commit Cloudflare exports, raw IPs, Ray IDs, request bodies, cookies,
  tokens, account IDs, or private reports.
- Do not add country-wide blocks by default.
- Do not auto-report IPs to abuse services.
- Treat reputation providers as evidence sources that can disagree, not as a
  single truth score.

## Next milestones

1. Add a documented Cloudflare export adapter for the exact fields available on
   the account.
2. Add opt-in RDAP/BGP enrichment with local caching and retry budgets.
3. Add a timeline view for country, ASN, path, and user-agent recurrence.
4. Add a private report mode with local-only raw IPs and a public export mode.
5. Add regression fixtures for false positives such as legitimate search bots,
   uptime monitors, and social link previews.
