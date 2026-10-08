#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

BASE_IMAGE="litellm/litellm-non_root:v1.104.2@sha256:e8dee87e7ddbf9abc174e8a7b180a690d5265cc4827458d22c5ff5e108170027"
PATCHED_IMAGE="${PATCHED_IMAGE:-litellm-non_root:v1.104.2-patched}"
TRIVY_IMAGE="aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa"
GRYPE_IMAGE="anchore/grype:v0.120.1@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe"
VEX="litellm-non_root-v1.104.2.openvex.json"
REPORTS="reports"

trivy() {
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v litellm-trivy-cache:/root/.cache/trivy \
    -v "$PWD:/work" -w /work \
    "$TRIVY_IMAGE" "$@"
}

grype() {
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v litellm-grype-cache:/cache -e GRYPE_DB_CACHE_DIR=/cache \
    -v "$PWD:/work" -w /work \
    "$GRYPE_IMAGE" "$@"
}

smoke_test() {
  local cid
  cid=$(docker run -d --network none -e LITELLM_MASTER_KEY=sk-smoke "$PATCHED_IMAGE" --port 4000)
  for _ in $(seq 1 45); do
    if docker exec "$cid" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:4000/health/liveliness', timeout=2)" 2>/dev/null; then
      docker rm -f "$cid" >/dev/null
      echo "proxy answered /health/liveliness"
      return 0
    fi
    sleep 2
  done
  docker logs "$cid" | tail -40
  docker rm -f "$cid" >/dev/null
  echo "proxy did not become live" >&2
  return 1
}

mkdir -p "$REPORTS"

echo "== build $PATCHED_IMAGE"
docker build -t "$PATCHED_IMAGE" .

echo "== installed glibc packages"
docker run --rm --entrypoint sh "$PATCHED_IMAGE" -c 'apk info -v' \
  | grep -E '^(glibc-2\.44|glibc-2\.44-locale-posix|ld-linux-2\.44|libcrypt1-2\.44)-[0-9]' \
  | tee "$REPORTS/patched-glibc-packages.txt"

echo "== smoke test"
smoke_test

echo "== trivy: stock image, raw findings (informational)"
trivy image --scanners vuln --format table -o "$REPORTS/trivy-stock.txt" "$BASE_IMAGE"
cat "$REPORTS/trivy-stock.txt"

echo "== trivy gate: patched image must have zero findings"
trivy image --scanners vuln --exit-code 1 --format table -o "$REPORTS/trivy-patched.txt" "$PATCHED_IMAGE"
trivy image --scanners vuln --format json -o "$REPORTS/trivy-patched.json" "$PATCHED_IMAGE"
cat "$REPORTS/trivy-patched.txt"

echo "== trivy gate: stock image with VEX applied must have zero unjustified findings"
trivy image --scanners vuln --vex "$VEX" --show-suppressed --exit-code 1 --format table -o "$REPORTS/trivy-stock-vex.txt" "$BASE_IMAGE"
cat "$REPORTS/trivy-stock-vex.txt"

echo "== grype gate: patched image must have zero findings"
grype "docker:$PATCHED_IMAGE" --fail-on negligible -o table --file "$REPORTS/grype-patched.txt"
cat "$REPORTS/grype-patched.txt"

echo "== grype: stock image with VEX applied (informational)"
grype "docker:$BASE_IMAGE" --vex "$VEX" --show-suppressed -o table --file "$REPORTS/grype-stock-vex.txt"
cat "$REPORTS/grype-stock-vex.txt"

echo "== all gates passed; reports in $REPORTS/"
