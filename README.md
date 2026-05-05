# Vault KV Certificate Exporter

Python exporter for Prometheus. It scans Vault KV v2 mounts, finds secrets with certificate-like paths and fields, parses PEM/DER certificates and PEM/DER CRLs, and exports expiration metrics.

## Metrics

- `vault_certificate_not_after_timestamp_seconds` - certificate expiration timestamp.
- `vault_certificate_days_until_expiry` - days until expiration.
- `vault_certificate_valid` - `1` when a certificate-like field was parsed, `0` when it was not.
- `vault_crl_next_update_timestamp_seconds` - CRL `nextUpdate` timestamp.
- `vault_crl_days_until_next_update` - days until CRL `nextUpdate`.
- `vault_crl_last_update_timestamp_seconds` - CRL `lastUpdate` timestamp.
- `vault_crl_revoked_certificates` - number of revoked certificates listed in the CRL.
- `vault_crl_valid` - `1` when a CRL-like field was parsed, `0` when it was not.
- `vault_secret_inventory_present` - inventory metric for discovered certificate, CRL, private key, keystore and truststore fields.
- `vault_certificate_exporter_scrape_success` - latest scrape status.
- `vault_certificate_exporter_scrape_duration_seconds` - latest scrape duration.
- `vault_certificate_exporter_scrape_errors_total` - errors during latest scrape.
- `vault_certificate_exporter_discovered_certificates` - certificates parsed during latest scrape.
- `vault_certificate_exporter_discovered_crls` - CRLs parsed during latest scrape.

Certificate labels:

- `mount`
- `path`
- `field`
- `subject`
- `issuer`
- `serial_number`

## Configuration

Required:

- `VAULT_ADDR` - Vault URL, for example `https://vault.example.com`.

Authentication, choose one:

- `VAULT_TOKEN`
- `VAULT_ROLE_ID` and `VAULT_SECRET_ID` for AppRole auth.
- `VAULT_KUBERNETES_ROLE` for Kubernetes auth.

Optional:

- `VAULT_KV_MOUNTS` - comma-separated KV v2 mounts. Default: `app,secret,test`.
- `VAULT_PATH_PREFIXES` - comma-separated metadata path prefixes to scan inside every mount. Default: full mount scan.
- `VAULT_VERIFY_TLS` - verify Vault TLS certificate. Default: `true`.
- `VAULT_REQUEST_TIMEOUT_SECONDS` - Vault request timeout. Default: `15`.
- `VAULT_MAX_DEPTH` - recursive metadata scan depth. Default: `10`.
- `SCRAPE_INTERVAL_SECONDS` - scan interval. Default: `300`.
- `LISTEN_ADDR` - HTTP bind address. Default: `0.0.0.0`.
- `LISTEN_PORT` - HTTP port. Default: `9108`.
- `CERT_PATH_REGEX` - regex for secret paths to read.
- `CERT_FIELD_REGEX` - regex for secret fields to parse.
- `CRL_FIELD_REGEX` - regex for CRL fields to parse.
- `KEY_FIELD_REGEX` - regex for private key fields to inventory without certificate parse-failed metrics.
- `KEYSTORE_FIELD_REGEX` - regex for JKS/keystore/truststore fields to inventory without parsing.
- `VAULT_OWNER_MAP` - comma-separated `service=owner` map for `vault_secret_inventory_present`, for example `dcpay-cew-bff=broker`.
- `VAULT_DEFAULT_OWNER` - owner label when service is not mapped. Default: `unknown`.
- `LOG_LEVEL` - Python logging level. Default: `INFO`.

Private keys such as `cert.key`, `tls.key` and `private.key` are inventoried as `type="private_key"` and are not exported as certificate parse failures. JKS, truststore and keystore values are inventoried as `type="keystore"`; parsing them requires a separate Java keystore reader and password handling, so they are intentionally not decoded by this exporter yet.

## Run Locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="$TOKEN"
export VAULT_KV_MOUNTS="app,secret,test"

python app.py
```

Check metrics:

```bash
curl http://localhost:9108/metrics
```

## Build Docker Image

```bash
docker build -t vault-kv-cert-exporter:latest .
```

## Build tar.gz Archive

```powershell
.\scripts\build-tar.ps1
```

The archive is written to `dist/vault-exporter.tar.gz`. GitHub Actions also builds the same archive on pushes to `main`, pull requests, and manual workflow runs.

## Run In Docker

```bash
docker run --rm -p 9108:9108 \
  -e VAULT_ADDR="https://vault.example.com" \
  -e VAULT_TOKEN="$TOKEN" \
  -e VAULT_KV_MOUNTS="app,secret,test" \
  vault-kv-cert-exporter:latest
```

## Docker Compose Example

```yaml
services:
  vault-kv-cert-exporter:
    image: vault-kv-cert-exporter:latest
    ports:
      - "9108:9108"
    environment:
      VAULT_ADDR: "https://vault.example.com"
      VAULT_TOKEN: "${VAULT_TOKEN}"
      VAULT_KV_MOUNTS: "app,secret,test"
      SCRAPE_INTERVAL_SECONDS: "300"
```

## Kubernetes Deployment Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault-kv-cert-exporter
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vault-kv-cert-exporter
  template:
    metadata:
      labels:
        app: vault-kv-cert-exporter
    spec:
      containers:
        - name: exporter
          image: vault-kv-cert-exporter:latest
          ports:
            - name: metrics
              containerPort: 9108
          env:
            - name: VAULT_ADDR
              value: "https://vault.example.com"
            - name: VAULT_KV_MOUNTS
              value: "app,secret,test"
            - name: VAULT_KUBERNETES_ROLE
              value: "vault-kv-cert-exporter"
```

## Vault Policy Example

The exporter needs list access to metadata and read access to data for every scanned KV v2 mount:

```hcl
path "app/metadata/*" {
  capabilities = ["list"]
}

path "app/data/*" {
  capabilities = ["read"]
}
```

Repeat the same pattern for each mount from `VAULT_KV_MOUNTS`.

## Check Whether `database` Is KV v2

Use this before adding `database` to `VAULT_KV_MOUNTS`:

```bash
curl -sS -H "X-Vault-Token: $TOKEN" "$VAULT_ADDR/v1/sys/mounts/database" | jq .
```

If the response contains `"type": "kv"` and `"options": {"version": "2"}`, start the exporter with:

```bash
export VAULT_KV_MOUNTS="app,secret,test,database"
```

If `database` is KV v1 or a database secrets engine, do not add it to this exporter. KV v1 needs different API paths and database secrets engines do not store certificate files in KV v2 metadata/data format.

## Alert Examples

CRL expiry alerts:

```promql
vault_crl_days_until_next_update <= 30
vault_crl_days_until_next_update <= 7
vault_crl_days_until_next_update <= 3
vault_crl_days_until_next_update <= 2
vault_crl_days_until_next_update <= 1
```

Certificate expiry alerts can use the same thresholds:

```promql
vault_certificate_days_until_expiry <= 30
vault_certificate_days_until_expiry <= 7
vault_certificate_days_until_expiry <= 3
vault_certificate_days_until_expiry <= 2
vault_certificate_days_until_expiry <= 1
```
