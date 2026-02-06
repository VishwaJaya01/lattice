# Container Images

Build images from repo root:

```bash
docker build -f deployments/docker/Dockerfile.orchestrator -t ghcr.io/vishwajaya01/lattice-orchestrator:latest .
docker build -f deployments/docker/Dockerfile.worker -t ghcr.io/vishwajaya01/lattice-worker:latest .
```

Optional push:

```bash
docker push ghcr.io/vishwajaya01/lattice-orchestrator:latest
docker push ghcr.io/vishwajaya01/lattice-worker:latest
```

These tags are the defaults used by `deployments/k8s` and the Helm chart.
