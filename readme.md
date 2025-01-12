# Scan Deduplicator for secureCodeBox

> WARN: This is a highly unstable experiment at the moment.

Deduplicates scans which were already executed too recently.

This allows to build up setups with cascading scans where you have "discovery" scans which are executed often, e.g. every hour, which discover targets. (e.g.)

This allows to build up setups with cascading scans which perform "discovery" scans very often, but then only trigger compute heavy subsequent scans in a less frequent interval. E.g. scan for hosts in a network every 10m, port-scan identified hosts every 1h and only trigger resource intensive nuclei / zap scans every week.

## How to use this

The scan-deduplicator will automatically deduplicate scans which have a `scan-deduplicator.securecodebox.io/min-time-interval` annotation set.
If a identical scan (based on a hash of the scan spec) was already started (in the same cluster & namespace), it the deduplicator will prevent it from being created on the cluster.

### Example Scan using Deduplication

```yaml
apiVersion: "execution.securecodebox.io/v1"
kind: ScheduledScan
metadata:
  name: "nmap-scanme-nmap-org"
  annotations:
    scan-deduplicator.securecodebox.io/min-time-interval: 4h
spec:
  interval: 5m # will actually only be started every 4hours, because of the deduplication
  scanSpec:
    scanType: "nmap"
    parameters:
      - "scanme.nmap.org"
```

### Using this with CascadingScans

One of the primary use cases of cascading scans is to deduplicate cascading scans.
This allows to run the discovery scans earlier in the cascade with a higher frequency and then onjly run the more expensive scans later in the cascade less often.

```yaml
apiVersion: "cascading.securecodebox.io/v1"
kind: CascadingRule
metadata:
  name: "nuclei-http"
  labels:
    securecodebox.io/invasive: non-invasive
    securecodebox.io/intensive: light
spec:
  scanAnnotations:
    scan-deduplicator.securecodebox.io/min-time-interval: 24h
  matches:
    anyOf:
      - category: "Open Port"
        attributes:
          service: "http"
          state: open
  scanSpec:
    scanType: "nuclei"
    parameters:
      # Target domain name of the finding and start a nuclei scan
      - "-u"
      - "http://{{$.hostOrIP}}:{{attributes.port}}"
---
apiVersion: "execution.securecodebox.io/v1"
kind: ScheduledScan
metadata:
  name: "nmap-local-network"
spec:
  interval: 30m
  scanSpec:
    scanType: "nmap"
    parameters:
      - -p80,8080
      - "192.168.178.0/24"
    cascades: {}
```

## Deployment (WIP)

Deploys the scan-deduplicator, including a [valkey](https://valkey.io/) instance for a persistent cache.

```bash
kubectl create namespace scan-deduplicator || true
kubectl create --namespace scan-deduplicator secret generic scan-deduplicator-cache-credentials --from-literal="password=$(uuidgen)" || true
kubectl apply --namespace scan-deduplicator -f deploy/
```
