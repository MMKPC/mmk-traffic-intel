$ErrorActionPreference = 'Stop'
$env:PYTHONPATH = Join-Path $PSScriptRoot 'src'
python -m unittest discover -s (Join-Path $PSScriptRoot 'tests') -v
python -m mmk_traffic_intel.cli (Join-Path $PSScriptRoot 'fixtures\cloudflare.sample.ndjson') `
  --output (Join-Path $PSScriptRoot 'dashboard\data.json') `
  --pretty-report (Join-Path $PSScriptRoot 'reports\demo-report.txt')
Write-Host "Dashboard data generated. Serve the dashboard with:"
Write-Host "python -m http.server 8788 --directory dashboard"
