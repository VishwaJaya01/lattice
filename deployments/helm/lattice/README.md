# Lattice Helm Chart

Deploys:

- Orchestrator (`Deployment`)
- Worker pool (`StatefulSet`)
- Headless service for deterministic worker addressing
- Demo table init container (ephemeral `emptyDir` storage)

## Install

```bash
helm upgrade --install lattice deployments/helm/lattice -n lattice --create-namespace
```

By default the chart expects an existing secret named `lattice-mtls` with keys:

- `ca.crt`
- `orchestrator.crt`
- `orchestrator.key`
- `worker.crt`
- `worker.key`

You can switch to chart-managed secret creation by setting:

```yaml
mtls:
  create: true
  existingSecret: ""
  caCrt: |
    -----BEGIN CERTIFICATE-----
    ...
  orchestratorCrt: |
    ...
  orchestratorKey: |
    ...
  workerCrt: |
    ...
  workerKey: |
    ...
```

## Key Values

- `worker.replicaCount`: number of worker pods.
- `orchestrator.hashReplicas`: consistent-hash virtual nodes per worker.
- `orchestrator.workerHeartbeat`: worker heartbeat interval.
- `orchestrator.workerTimeout`: worker eviction timeout.
- `worker.table.chainLen` / `worker.table.chainCount`: generated demo table size.
