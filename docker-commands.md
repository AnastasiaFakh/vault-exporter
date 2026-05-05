# Docker Build And Run Commands

## PowerShell

```powershell
# Required
$env:VAULT_ADDR = "https://vault.example.com"
$env:VAULT_TOKEN = "<vault-token>"

# Optional
$env:VAULT_KV_MOUNTS = "app,secret,test"
$env:SCRAPE_INTERVAL_SECONDS = "300"
$env:LISTEN_PORT = "9108"

docker build -t vault-kv-cert-exporter:latest .

docker run --rm --name vault-kv-cert-exporter `
  -p 9108:9108 `
  -e VAULT_ADDR="$env:VAULT_ADDR" `
  -e VAULT_TOKEN="$env:VAULT_TOKEN" `
  -e VAULT_KV_MOUNTS="$env:VAULT_KV_MOUNTS" `
  -e SCRAPE_INTERVAL_SECONDS="$env:SCRAPE_INTERVAL_SECONDS" `
  -e LISTEN_PORT="$env:LISTEN_PORT" `
  vault-kv-cert-exporter:latest
```

## Check `database` KV Version

```powershell
curl.exe -sS -H "X-Vault-Token: $env:VAULT_TOKEN" "$env:VAULT_ADDR/v1/sys/mounts/database"
```

Add `database` only when Vault reports `type=kv` and `options.version=2`:

```powershell
$env:VAULT_KV_MOUNTS = "app,secret,test,database"
```

## Git Bash / Linux / macOS

```bash
# Required
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="<vault-token>"

# Optional
export VAULT_KV_MOUNTS="app,secret,test"
export SCRAPE_INTERVAL_SECONDS="300"
export LISTEN_PORT="9108"

docker build -t vault-kv-cert-exporter:latest .

docker run --rm --name vault-kv-cert-exporter \
  -p 9108:9108 \
  -e VAULT_ADDR="$VAULT_ADDR" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  -e VAULT_KV_MOUNTS="$VAULT_KV_MOUNTS" \
  -e SCRAPE_INTERVAL_SECONDS="$SCRAPE_INTERVAL_SECONDS" \
  -e LISTEN_PORT="$LISTEN_PORT" \
  vault-kv-cert-exporter:latest
```

## Start In Background

```powershell
docker run -d --name vault-kv-cert-exporter `
  -p 9108:9108 `
  -e VAULT_ADDR="$env:VAULT_ADDR" `
  -e VAULT_TOKEN="$env:VAULT_TOKEN" `
  -e VAULT_KV_MOUNTS="$env:VAULT_KV_MOUNTS" `
  vault-kv-cert-exporter:latest

docker logs -f vault-kv-cert-exporter
```

## Check Metrics

```powershell
curl.exe http://localhost:9108/metrics
```

## Stop Background Container

```powershell
docker stop vault-kv-cert-exporter
docker rm vault-kv-cert-exporter
```
