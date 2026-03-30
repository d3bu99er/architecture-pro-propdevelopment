#!/usr/bin/env bash
set -euo pipefail

# Verifies that insecure manifests are rejected by Pod Security Admission
# and secure manifests are admitted.
#
# Expected layout:
#   ./01-create-namespace.yaml
#   ./insecure-manifests/*.yaml
#   ./secure-manifests/*.yaml
#
# Usage:
#   ./verify-admission.sh
#   NAMESPACE_FILE=./01-create-namespace.yaml ./verify-admission.sh
#   INSECURE_DIR=./insecure-manifests SECURE_DIR=./secure-manifests ./verify-admission.sh

NAMESPACE_FILE="${NAMESPACE_FILE:-./01-create-namespace.yaml}"
INSECURE_DIR="${INSECURE_DIR:-./insecure-manifests}"
SECURE_DIR="${SECURE_DIR:-./secure-manifests}"
TIMEOUT="${TIMEOUT:-60s}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

failures=0
namespace=""
created_secure_pods=()

die() {
  red "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

extract_namespace() {
  awk '
    $1 == "name:" && prev ~ /^metadata:$/ { print $2; exit }
    { prev=$0 }
  ' "$1"
}

extract_name() {
  awk '
    $1 == "name:" && prev ~ /^metadata:$/ { print $2; exit }
    { prev=$0 }
  ' "$1"
}

extract_kind() {
  awk '$1 == "kind:" { print $2; exit }' "$1"
}

cleanup() {
  set +e
  if [[ -n "$namespace" ]]; then
    for pod in "${created_secure_pods[@]:-}"; do
      kubectl delete pod "$pod" -n "$namespace" --ignore-not-found >/dev/null 2>&1 || true
    done
  fi
}
trap cleanup EXIT

need_cmd kubectl
[[ -f "$NAMESPACE_FILE" ]] || die "Namespace file not found: $NAMESPACE_FILE"
[[ -d "$INSECURE_DIR" ]] || die "Insecure manifests directory not found: $INSECURE_DIR"
[[ -d "$SECURE_DIR" ]] || die "Secure manifests directory not found: $SECURE_DIR"

namespace="$(extract_namespace "$NAMESPACE_FILE")"
[[ -n "$namespace" ]] || die "Could not determine namespace from $NAMESPACE_FILE"

blue "==> Applying namespace from $NAMESPACE_FILE"
kubectl apply -f "$NAMESPACE_FILE" >/dev/null

blue "==> Verifying insecure manifests are rejected"
shopt -s nullglob
insecure_files=("$INSECURE_DIR"/*.yaml "$INSECURE_DIR"/*.yml)
secure_files=("$SECURE_DIR"/*.yaml "$SECURE_DIR"/*.yml)
shopt -u nullglob

((${#insecure_files[@]} > 0)) || die "No insecure manifest files found in $INSECURE_DIR"
((${#secure_files[@]} > 0)) || die "No secure manifest files found in $SECURE_DIR"

for file in "${insecure_files[@]}"; do
  kind="$(extract_kind "$file")"
  name="$(extract_name "$file")"
  [[ -n "$name" ]] || name="$(basename "$file")"

  yellow "Checking insecure manifest: $(basename "$file")"
  set +e
  output="$(kubectl apply -f "$file" 2>&1)"
  rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    red "FAIL: $(basename "$file") was admitted, but should have been rejected"
    printf '%s\n' "$output"
    if [[ -n "$name" && "$kind" == "Pod" ]]; then
      kubectl delete pod "$name" -n "$namespace" --ignore-not-found >/dev/null 2>&1 || true
    fi
    failures=$((failures + 1))
    continue
  fi

  if grep -qiE 'forbidden|violates podsecurity|denied|hostpath|privileged' <<<"$output"; then
    green "PASS: $(basename "$file") was rejected as expected"
  else
    red "FAIL: $(basename "$file") failed, but not with an admission/security-style error"
    printf '%s\n' "$output"
    failures=$((failures + 1))
  fi

done

blue "==> Verifying secure manifests are admitted"
for file in "${secure_files[@]}"; do
  kind="$(extract_kind "$file")"
  name="$(extract_name "$file")"
  [[ -n "$name" ]] || name="$(basename "$file")"

  yellow "Checking secure manifest: $(basename "$file")"
  set +e
  output="$(kubectl apply -f "$file" 2>&1)"
  rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    red "FAIL: $(basename "$file") was rejected, but should have been admitted"
    printf '%s\n' "$output"
    failures=$((failures + 1))
    continue
  fi

  green "PASS: $(basename "$file") was admitted"

  if [[ "$kind" == "Pod" && -n "$name" ]]; then
    created_secure_pods+=("$name")
    set +e
    kubectl wait --for=condition=PodScheduled "pod/$name" -n "$namespace" --timeout="$TIMEOUT" >/dev/null 2>&1
    wait_rc=$?
    set -e
    if [[ $wait_rc -eq 0 ]]; then
      green "PASS: pod/$name was scheduled"
    else
      yellow "WARN: pod/$name was admitted but not confirmed scheduled within $TIMEOUT"
    fi
  fi
done

if ((failures > 0)); then
  red "Admission verification finished with $failures failure(s)."
  exit 1
fi

green "All admission checks passed."
