# Kubernetes Manifests (Raw)

This folder provides a raw-manifest fallback for deploying Lattice with:

- 1 orchestrator (`Deployment`)
- 2 workers (`StatefulSet`)
- mTLS on all gRPC links
- ephemeral worker table storage (`emptyDir`) generated at pod startup

## Prerequisites

- Kubernetes 1.28+
- `kubectl`
- images published:
  - `ghcr.io/vishwajaya01/lattice-orchestrator:latest`
  - `ghcr.io/vishwajaya01/lattice-worker:latest`

Image build recipes: `deployments/docker/README.md`

## 1) Create mTLS secret

All pods expect a secret named `lattice-mtls` with keys:

- `ca.crt`
- `orchestrator.crt`
- `orchestrator.key`
- `worker.crt`
- `worker.key`

Example:

```bash
kubectl -n lattice create secret generic lattice-mtls \
  --from-file=ca.crt=ca.crt \
  --from-file=orchestrator.crt=orchestrator.crt \
  --from-file=orchestrator.key=orchestrator.key \
  --from-file=worker.crt=worker.crt \
  --from-file=worker.key=worker.key
```

## 2) Deploy

```bash
kubectl apply -k deployments/k8s
```

## 3) Verify

```bash
kubectl -n lattice get pods,svc
kubectl -n lattice logs deploy/lattice-orchestrator
kubectl -n lattice logs statefulset/lattice-worker
```

## 4) Failover check

Kill one worker and verify orchestrator remains healthy:

```bash
kubectl -n lattice delete pod lattice-worker-0
kubectl -n lattice logs deploy/lattice-orchestrator --since=2m
```

You should observe worker removal and continued routing to the remaining worker.

## Notes

- Worker table is generated via init container using `generate-demo-table.py`.
- The current orchestrator manifest is wired for 2 workers (`worker-0`, `worker-1`).
- For a different replica count, update `deployment-orchestrator.yaml` worker args.
