#!/bin/bash

# Install the Operator & CRD's into the `securecodebox-system` namespace
helm --namespace securecodebox-system upgrade --install --create-namespace securecodebox-operator oci://ghcr.io/securecodebox/helm/operator

# Create a namespace for the scans to run in
kubectl create namespace scans || true

echo "Setting up secureCodeBox ScanTypes and Cascading Scans Hook"

helm --namespace scans upgrade --install nmap oci://ghcr.io/securecodebox/helm/nmap
helm --namespace scans upgrade --install nuclei oci://ghcr.io/securecodebox/helm/nuclei --set="scanner.image.repository=docker.io/securecodebox/scanner-nuclei-precooked" --set="scanner.image.tag=v3.3.6-2024-12-05" --set="nucleiTemplateCache.enabled=false"
helm --namespace scans upgrade --install cascading-scans oci://ghcr.io/securecodebox/helm/cascading-scans

echo "Setting up secureCodeBox CascadingRules"
kubectl apply --namespace scans -f ./manifests/cascading-rules.yaml

echo "Setting up secureCodeBox Scan"
kubectl apply --namespace scans -f ./manifests/scan.yaml