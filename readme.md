# Scan Deduplicator for secureCodeBox

> WARN: This is a highly unstable experiment at the momemt.

Deduplicates scans which were already executed too recently.

This allows to build up setups with cascading scans where you have "discovery" scans which are executed often, e.g. every hour, which discover targets. (e.g.)

This allows to build up setups with cascading scans which perform "discovery" scans very often, but then only trigger compute heavy subsequent scans in a less frequent interval. E.g. scan for hosts in a network every 10m, port-scan identified hosts every 1h and only trigger resource intensive nuclei / zap scans every week.

## Deployment

```bash
kubectl create namespace scan-deduplicator || true
kubectl create --namespace scan-deduplicator secret generic scan-deduplicator-cache-credentials --from-literal="password=$(uuidgen)" || true
kubectl apply --namespace scan-deduplicator -f deploy/
```
