#!/usr/bin/env bash
set -euo pipefail

# Validates that admitted secure pods comply with the restricted-style requirements.
# Checks live resources in the cluster.
#
# Usage:
#   ./validate-security.sh
#   NAMESPACE=audit-zone ./validate-security.sh
#   SECURE_DIR=./secure-manifests ./validate-security.sh

NAMESPACE="${NAMESPACE:-audit-zone}"
SECURE_DIR="${SECURE_DIR:-./secure-manifests}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

failures=0

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { red "Required command not found: $1"; exit 1; }
}

blue "==> Applying secure manifests"
for f in "$SECURE_DIR"/*.yaml; do
  echo "Applying $f"
  kubectl apply -f "$f"
done

blue "==> Waiting for pods to appear"
sleep 2

pods=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')

if [[ -z "$pods" ]]; then
  echo "ERROR: No pods found in namespace $NAMESPACE"
  exit 1
fi

blue "==> Waiting for pods to become Ready"
for pod in $pods; do
  echo "Waiting for $pod"
  kubectl wait \
    --for=condition=Ready \
    pod/"$pod" \
    -n "$NAMESPACE" \
    --timeout=60s || true
done

extract_name() {
  awk '
    $1 == "name:" && prev ~ /^metadata:$/ { print $2; exit }
    { prev=$0 }
  ' "$1"
}

check_eq() {
  local actual="$1" expected="$2" msg="$3"
  if [[ "$actual" == "$expected" ]]; then
    green "PASS: $msg"
  else
    red "FAIL: $msg (expected: $expected, actual: ${actual:-<empty>})"
    failures=$((failures + 1))
  fi
}

check_nonempty() {
  local actual="$1" msg="$2"
  if [[ -n "$actual" ]]; then
    green "PASS: $msg"
  else
    red "FAIL: $msg"
    failures=$((failures + 1))
  fi
}

need_cmd kubectl
[[ -d "$SECURE_DIR" ]] || { red "Secure manifests directory not found: $SECURE_DIR"; exit 1; }

shopt -s nullglob
secure_files=("$SECURE_DIR"/*.yaml "$SECURE_DIR"/*.yml)
shopt -u nullglob
((${#secure_files[@]} > 0)) || { red "No secure manifest files found in $SECURE_DIR"; exit 1; }

blue "==> Validating live pod security settings in namespace $NAMESPACE"

for file in "${secure_files[@]}"; do
  pod="$(extract_name "$file")"
  [[ -n "$pod" ]] || pod="$(basename "$file")"

  yellow "Checking pod/$pod"

  if ! kubectl get pod "$pod" -n "$NAMESPACE" >/dev/null 2>&1; then
    red "FAIL: pod/$pod not found in namespace $NAMESPACE (apply secure manifests first)"
    failures=$((failures + 1))
    continue
  fi

  # Basic pod status information.
  phase="$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}')"
  green "INFO: pod/$pod phase = ${phase:-unknown}"

  # Validate securityContext of the first container.
  privileged="$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].securityContext.privileged}')"
  allow_pe="$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].securityContext.allowPrivilegeEscalation}')"
  run_as_non_root="$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].securityContext.runAsNonRoot}')"
  run_as_user="$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].securityContext.runAsUser}')"
  seccomp="$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].securityContext.seccompProfile.type}')"
  drop_caps="$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].securityContext.capabilities.drop[*]}')"
  hostpath_count="$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{range .spec.volumes[*]}{.hostPath.path}{"\n"}{end}' | sed '/^$/d' | wc -l | tr -d ' ')"
  image="$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].image}')"

  check_eq "$privileged" "false" "pod/$pod has privileged=false"
  check_eq "$allow_pe" "false" "pod/$pod has allowPrivilegeEscalation=false"
  check_eq "$run_as_non_root" "true" "pod/$pod has runAsNonRoot=true"

  if [[ -n "$run_as_user" ]]; then
    if [[ "$run_as_user" =~ ^[0-9]+$ ]] && (( run_as_user > 0 )); then
      green "PASS: pod/$pod has runAsUser=$run_as_user"
    else
      red "FAIL: pod/$pod has invalid runAsUser=${run_as_user:-<empty>}"
      failures=$((failures + 1))
    fi
  else
    yellow "WARN: pod/$pod does not set runAsUser explicitly; relying on image default"
  fi

  if [[ "$seccomp" == "RuntimeDefault" || "$seccomp" == "Localhost" ]]; then
    green "PASS: pod/$pod has seccompProfile.type=$seccomp"
  else
    red "FAIL: pod/$pod must set seccompProfile.type to RuntimeDefault or Localhost (actual: ${seccomp:-<empty>})"
    failures=$((failures + 1))
  fi

  if grep -qw 'ALL' <<<"$drop_caps"; then
    green "PASS: pod/$pod drops ALL Linux capabilities"
  else
    red "FAIL: pod/$pod does not drop ALL Linux capabilities (actual: ${drop_caps:-<empty>})"
    failures=$((failures + 1))
  fi

  if [[ "$hostpath_count" == "0" ]]; then
    green "PASS: pod/$pod does not use hostPath volumes"
  else
    red "FAIL: pod/$pod uses hostPath volumes"
    failures=$((failures + 1))
  fi

  green "INFO: pod/$pod image = $image"
done

if ((failures > 0)); then
  red "Security validation finished with $failures failure(s)."
  exit 1
fi

green "All security validation checks passed."
