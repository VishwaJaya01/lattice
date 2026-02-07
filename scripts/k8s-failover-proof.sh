#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${LATTICE_K8S_NAMESPACE:-lattice}"
ORCHESTRATOR_DEPLOY="${LATTICE_K8S_ORCH_DEPLOY:-lattice-lattice-orchestrator}"
WORKER_STS="${LATTICE_K8S_WORKER_STS:-lattice-lattice-worker}"
WORKER_POD="${LATTICE_K8S_WORKER_POD:-lattice-lattice-worker-0}"
LOG_SINCE="${LATTICE_K8S_LOG_SINCE:-10m}"
PODS_PROOF="${LATTICE_K8S_PODS_PROOF:-docs/k8s-pods-proof.txt}"
LOG_PROOF="${LATTICE_K8S_LOG_PROOF:-docs/k8s-orchestrator-proof.txt}"
PROOF_WAIT_SECONDS="${LATTICE_K8S_PROOF_WAIT_SECONDS:-180}"
PROOF_POLL_SECONDS="${LATTICE_K8S_PROOF_POLL_SECONDS:-2}"

WORKER_ADDR="${WORKER_POD}.${WORKER_STS}.${NAMESPACE}.svc.cluster.local:50052"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd kubectl

mkdir -p "$(dirname "$PODS_PROOF")" "$(dirname "$LOG_PROOF")"

echo "validating cluster objects..."
kubectl -n "$NAMESPACE" get deploy "$ORCHESTRATOR_DEPLOY" >/dev/null
kubectl -n "$NAMESPACE" get sts "$WORKER_STS" >/dev/null

echo "waiting for orchestrator and worker statefulset readiness..."
kubectl -n "$NAMESPACE" rollout status "deploy/$ORCHESTRATOR_DEPLOY" --timeout=180s >/dev/null
kubectl -n "$NAMESPACE" rollout status "statefulset/$WORKER_STS" --timeout=180s >/dev/null

echo "injecting failure by deleting $WORKER_POD..."
kubectl -n "$NAMESPACE" delete pod "$WORKER_POD" --wait=false >/dev/null

echo "waiting for worker statefulset recovery..."
kubectl -n "$NAMESPACE" rollout status "statefulset/$WORKER_STS" --timeout=240s >/dev/null

echo "waiting for orchestrator remove+re-register events for $WORKER_ADDR..."
start_epoch="$(date +%s)"
while true; do
  kubectl -n "$NAMESPACE" logs "deploy/$ORCHESTRATOR_DEPLOY" --since="$LOG_SINCE" >"$LOG_PROOF"
  removed_seen=0
  registered_seen=0
  if grep -F "addr=$WORKER_ADDR" "$LOG_PROOF" | grep -Fq "worker removed"; then
    removed_seen=1
  fi
  if grep -F "addr=$WORKER_ADDR" "$LOG_PROOF" | grep -Fq "worker registered"; then
    registered_seen=1
  fi
  if [[ "$removed_seen" -eq 1 && "$registered_seen" -eq 1 ]]; then
    break
  fi

  now_epoch="$(date +%s)"
  elapsed=$((now_epoch - start_epoch))
  if (( elapsed >= PROOF_WAIT_SECONDS )); then
    echo "timed out waiting for remove+re-register logs for $WORKER_ADDR" >&2
    echo "last lines from $LOG_PROOF:" >&2
    tail -n 40 "$LOG_PROOF" >&2 || true
    exit 1
  fi
  sleep "$PROOF_POLL_SECONDS"
done

echo "capturing pod state proof..."
kubectl -n "$NAMESPACE" get pods -o wide >"$PODS_PROOF"

echo "k8s failover proof completed successfully"
echo "  pods: $PODS_PROOF"
echo "  logs: $LOG_PROOF"
