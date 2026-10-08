#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

BASE_IMAGE="docker.io/litellm/litellm-non_root@sha256:e8dee87e7ddbf9abc174e8a7b180a690d5265cc4827458d22c5ff5e108170027"
PATCHED_IMAGE="${PATCHED_IMAGE:-localhost/litellm-non_root:v1.104.2-patched}"
TRIVY_IMAGE="docker.io/aquasec/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa"
GRYPE_IMAGE="docker.io/anchore/grype@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe"
VEX="litellm-non_root-v1.104.2.openvex.json"
REPORTS="reports"
PATCHED_ARCHIVE="$REPORTS/patched.docker-archive.tar"

scanner() {
  podman run --rm --security-opt label=disable -v "$PWD:/work" -w /work "$@"
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
      podman rm -f "$cid" >/dev/null
      echo "proxy answered /health/liveliness"
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
podman build -t "$PATCHED_IMAGE" -f Dockerfile .

echo "== installed glibc packages"
podman run --rm --entrypoint sh "$PATCHED_IMAGE" -c 'apk info -v' \
  | grep -E '^(glibc-2\.44|glibc-2\.44-locale-posix|ld-linux-2\.44|libcrypt1-2\.44)-[0-9]' \
  | tee "$REPORTS/patched-glibc-packages.txt"

echo "== smoke test"
smoke_test

echo "== export $PATCHED_IMAGE for scanning"
rm -f "$PATCHED_ARCHIVE"
podman save --format docker-archive -o "$PATCHED_ARCHIVE" "$PATCHED_IMAGE"

echo "== trivy: stock image, raw findings (informational)"
trivy image --image-src remote --scanners vuln --format table -o "$REPORTS/trivy-stock.txt" "$BASE_IMAGE"
cat "$REPORTS/trivy-stock.txt"

echo "== trivy gate: patched image must have zero findings"
trivy image --input "$PATCHED_ARCHIVE" --scanners vuln --format json -o "$REPORTS/trivy-patched.json"
trivy image --input "$PATCHED_ARCHIVE" --scanners vuln --exit-code 1 --format table -o "$REPORTS/trivy-patched.txt"
cat "$REPORTS/trivy-patched.txt"

echo "== trivy gate: stock image with VEX applied must have zero unjustified findings"
trivy image --image-src remote --scanners vuln --vex "$VEX" --show-suppressed --exit-code 1 --format table -o "$REPORTS/trivy-stock-vex.txt" "$BASE_IMAGE"
cat "$REPORTS/trivy-stock-vex.txt"

echo "== grype gate: patched image must have zero findings"
grype "docker-archive:$PATCHED_ARCHIVE" --fail-on negligible -o table --file "$REPORTS/grype-patched.txt"
cat "$REPORTS/grype-patched.txt"

echo "== grype: stock image with VEX applied (informational)"
grype "registry:$BASE_IMAGE" --vex "$VEX" --show-suppressed -o table --file "$REPORTS/grype-stock-vex.txt"
cat "$REPORTS/grype-stock-vex.txt"

echo "== all gates passed; reports in $REPORTS/"
