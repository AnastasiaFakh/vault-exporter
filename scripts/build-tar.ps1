param(
    [string]$OutputDir = "dist",
    [string]$ArchiveName = "vault-exporter.tar.gz"
)

$ErrorActionPreference = "Stop"

$repoRoot = (git rev-parse --show-toplevel).Trim()
$head = (git rev-parse --verify HEAD).Trim()
$outputPath = Join-Path $repoRoot $OutputDir
$archivePath = Join-Path $outputPath $ArchiveName

New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

git archive `
    --format=tar.gz `
    --prefix="vault-exporter/" `
    --output=$archivePath `
    $head

Write-Host "Created $archivePath"
