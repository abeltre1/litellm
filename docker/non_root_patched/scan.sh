#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

STOCK_IMAGE="docker.io/litellm/litellm-non_root:v1.104.2"
PATCHED_IMAGE="${PATCHED_IMAGE:-localhost/litellm-non_root:v1.104.2-patched}"
TRIVY_IMAGE="docker.io/aquasec/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa"
GRYPE_IMAGE="docker.io/anchore/grype@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe"
VEX="litellm-non_root-v1.104.2.openvex.json"
REPORTS="reports"
PATCHED_ARCHIVE="$REPORTS/patched.docker-archive.tar"
CA_BUNDLE="${CA_BUNDLE:-}"

build_ca_args=(--build-arg BUILD_SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt --build-arg BUILD_NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt)
scanner_ca_args=()
if [ -n "$CA_BUNDLE" ]; then
  selinux_relabel=$([ "$(podman info --format '{{.Host.Security.SELinuxEnabled}}')" = "true" ] && echo ",Z" || true)
  build_ca_args=(-v "$CA_BUNDLE:/ca-bundle.pem:ro$selinux_relabel" --build-arg BUILD_SSL_CERT_FILE=/ca-bundle.pem --build-arg BUILD_NODE_EXTRA_CA_CERTS=/ca-bundle.pem)
  scanner_ca_args=(-v "$CA_BUNDLE:/ca-bundle.pem:ro" -e SSL_CERT_FILE=/ca-bundle.pem)
fi

scanner() {
  podman run --rm --security-opt label=disable "${scanner_ca_args[@]}" -v "$PWD:/work" -w /work "$@"
}

trivy() {
  scanner -v litellm-trivy-cache:/root/.cache/trivy "$TRIVY_IMAGE" "$@"
}

grype() {
  scanner -v litellm-grype-cache:/cache -e GRYPE_DB_CACHE_DIR=/cache "$GRYPE_IMAGE" "$@"
}

smoke_test() {
  local cid
  cid=$(podman run -d --network none -e LITELLM_MASTER_KEY=sk-smoke "$PATCHED_IMAGE" --port 4000)
  for _ in $(seq 1 45); do
    if podman exec "$cid" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:4000/health/liveliness', timeout=2)" 2>/dev/null; then
      podman exec "$cid" python -c "
import io, numpy, soundfile
buf = io.BytesIO()
soundfile.write(buf, numpy.zeros(1600, dtype='float32'), 16000, format='WAV')
buf.seek(0)
data, rate = soundfile.read(buf)
assert len(data) == 1600 and rate == 16000
print('proxy is live and soundfile round-trips audio')"
      podman rm -f "$cid" >/dev/null
      return 0
    fi
    sleep 2
  done
  podman logs "$cid" | tail -40
  podman rm -f "$cid" >/dev/null
  echo "proxy did not become live" >&2
  return 1
}

mkdir -p "$REPORTS"

echo "== build $PATCHED_IMAGE"
podman build "${build_ca_args[@]}" -t "$PATCHED_IMAGE" -f Dockerfile .

echo "== installed versions of the packages the scan flagged"
podman run --rm --entrypoint sh "$PATCHED_IMAGE" -c 'apk info -v 2>/dev/null' \
  | grep -E '^(glibc-2\.44|glibc-2\.44-locale-posix|ld-linux-2\.44|libcrypt1-2\.44|libcrypto3|libssl3|python-3\.13|alsa-lib|libsndfile)-[0-9]' \
  | tee "$REPORTS/patched-packages.txt"

echo "== smoke test"
smoke_test

echo "== export $PATCHED_IMAGE for scanning"
rm -f "$PATCHED_ARCHIVE"
podman save --format docker-archive -o "$PATCHED_ARCHIVE" "$PATCHED_IMAGE"

echo "== grype: stock image, raw findings (informational)"
grype db update
grype "registry:$STOCK_IMAGE" -o table --file "$REPORTS/grype-stock.txt"
cat "$REPORTS/grype-stock.txt"

echo "== grype gate: patched image must have zero findings outside the justified ones"
grype "docker-archive:$PATCHED_ARCHIVE" -c .grype.yaml --vex "$VEX" -o json --file "$REPORTS/grype-patched.json"
grype "docker-archive:$PATCHED_ARCHIVE" -c .grype.yaml --vex "$VEX" --show-suppressed -o table --file "$REPORTS/grype-patched.txt"
cat "$REPORTS/grype-patched.txt"
python3 -c 'import json, sys; m = json.load(open(sys.argv[1]))["matches"]; print(f"{len(m)} unjustified grype findings, any severity including Unknown"); sys.exit(1 if m else 0)' "$REPORTS/grype-patched.json"

echo "== trivy gate: patched image must have zero findings outside the justified ones"
trivy image --input "$PATCHED_ARCHIVE" --scanners vuln --vex "$VEX" --show-suppressed --exit-code 1 --format table -o "$REPORTS/trivy-patched.txt"
cat "$REPORTS/trivy-patched.txt"

echo "== all gates passed; reports in $REPORTS/"
