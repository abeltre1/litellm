# CVE status for litellm-non_root v1.104.2

This directory covers `litellm/litellm-non_root:v1.104.2`, the latest upstream release, pinned to index digest `sha256:e8dee87e7ddbf9abc174e8a7b180a690d5265cc4827458d22c5ff5e108170027` (amd64 manifest `sha256:96f7723f804efd652aece0e64ff37e5fa26f6f4366c1ff083a5957dc732acd4f`, arm64 manifest `sha256:b1f2d6d3d1ba0c374cf4b9ee97d97d45a329a5f3bcb3f964751c090fb6570324`). It gives two ways to close out every finding: rebuild with the fixed packages, or accept the stock image with a machine-readable justification

| File | Purpose |
| --- | --- |
| `Dockerfile` | Patched image that upgrades glibc to the fixed release |
| `scan.sh` | Builds the patched image, smoke tests it, and gates on Trivy and Grype |
| `litellm-non_root-v1.104.2.openvex.json` | OpenVEX justification for every finding in the stock image |
| `evidence/` | Trivy 0.75.0 reports for the stock image on both architectures, raw and with the VEX applied |

## Findings in the stock image

Trivy 0.75.0 (vulnerability DB pulled 2026-10-08) reports no critical, high, or low findings on either architecture. It inventoried 52 OS packages, 199 Python packages, and 4 Node packages, and the only findings are four medium glibc CVEs, each reported once per glibc subpackage (`glibc-2.44`, `glibc-2.44-locale-posix`, `ld-linux-2.44`, `libcrypt1-2.44`), for 16 rows in total. Every one is fixed in `2.44-r8`; the image ships `2.44-r6`

| CVE | Vendor CVSS | Issue | Fixed in | VEX status |
| --- | --- | --- | --- | --- |
| CVE-2026-86805 | 7.0 | ld.so TOCTOU on `$ORIGIN` for setuid/setgid programs | 2.44-r8 | not_affected, vulnerable_code_not_in_execute_path |
| CVE-2026-95818 | 7.0 | ld.so stack overflow on `$ORIGIN` for setuid/setgid programs | 2.44-r8 | not_affected, vulnerable_code_not_in_execute_path |
| CVE-2026-8674 | 5.3 | Resolver abort on an overlong search domain in resolv.conf or LOCALDOMAIN | 2.44-r8 | not_affected, vulnerable_code_cannot_be_controlled_by_adversary |
| CVE-2026-89092 | 4.2 | nscd stack overflow on oversized DNS responses | 2.44-r8 | not_affected, vulnerable_code_not_present |

## Remediation: patched image

`Dockerfile` starts from the digest-pinned stock image and installs `>=2.44-r8` of the four glibc subpackages from the public Wolfi repository, then drops back to uid 65534. Nothing else in the image changes

A plain `apk upgrade` on top of the stock image does nothing, for two reasons. The image's only configured repository is `https://apk.cgr.dev/chainguard`, which requires Chainguard credentials, and `/etc/apk/world` pins every glibc subpackage to `=2.44-r6`, so apk will not move them even with repository access. The Dockerfile names the Wolfi repository for this one install (the image already trusts `wolfi-signing.rsa.pub`) and replaces the exact pins with `>=2.44-r8` constraints. If the fixed packages cannot be fetched, the build fails rather than producing an unpatched image

If your network mirrors Wolfi internally, point the build at the mirror with `--build-arg APK_REPOSITORY=https://your-mirror/os`. For a multi-arch image use `docker buildx build --platform linux/amd64,linux/arm64`

Run `./scan.sh` on a machine with Docker and registry access. It builds the image, prints the installed glibc versions, starts the proxy with networking disabled and waits for `/health/liveliness`, then fails unless the patched image has zero findings under both Trivy 0.75.0 and Grype v0.120.1 and the stock image has zero unjustified findings under Trivy with the VEX applied. Reports land in `reports/`. Both scanners are pinned by digest

## Justification: OpenVEX

If you deploy the stock image instead, `litellm-non_root-v1.104.2.openvex.json` states why none of the four CVEs is exploitable in it. The products are the index digest and both per-arch manifest digests, so it matches however the image is referenced, and it applies to nothing else. Each claim rests on a property of the image that anyone can re-check

The two ld.so CVEs (86805 and 95818) are only reachable when the loader runs a program with AT_SECURE set, which happens for setuid, setgid, or file-capability binaries. The image contains none on either architecture, and the container runs as uid 65534

```
docker run --rm --user 0 --network none --entrypoint sh litellm/litellm-non_root:v1.104.2 \
  -c 'find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | wc -l'
0
```

CVE-2026-89092 lives in the nscd daemon, which is not installed: there is no binary, no `/etc/nscd.conf`, and no socket

```
docker run --rm --user 0 --network none --entrypoint sh litellm/litellm-non_root:v1.104.2 -c 'find / -xdev -name "nscd*" | wc -l'
0
```

CVE-2026-8674 is triggered by the content of `/etc/resolv.conf` or the `LOCALDOMAIN` environment variable. The image does not set `LOCALDOMAIN`, and `resolv.conf` is bind-mounted by the container runtime from the platform's DNS configuration, so only the operator controls it. API callers and network peers cannot. The worst case under operator misconfiguration is a process abort

```
docker run --rm --entrypoint sh litellm/litellm-non_root:v1.104.2 -c 'grep " /etc/resolv.conf " /proc/mounts'
/dev/vda /etc/resolv.conf ext4 rw,relatime,... 0 0
```

These claims hold as long as the deployment keeps the conditions they depend on. Do not mount volumes containing setuid binaries into the container (mount them `nosuid`, and set `allowPrivilegeEscalation: false` and `runAsNonRoot: true` in Kubernetes), do not add or enable nscd, and do not set `LOCALDOMAIN` or the pod's DNS search domains from untrusted input

Apply the VEX with either scanner

```
trivy image --vex litellm-non_root-v1.104.2.openvex.json --show-suppressed --exit-code 1 litellm/litellm-non_root:v1.104.2
grype docker:litellm/litellm-non_root:v1.104.2 --vex litellm-non_root-v1.104.2.openvex.json --show-suppressed
```

With Trivy this reports 0 findings on amd64 and arm64 and lists all 16 as suppressed with their justifications; the output is in `evidence/trivy-stock-vex-amd64.txt` and `evidence/trivy-stock-vex-arm64.txt`

## What was and was not verified

The stock image scans, the in-image evidence on amd64 (by running it) and arm64 (from its exported filesystem), the Trivy VEX gate on both architectures, the offline liveness check on the stock image, and the Dockerfile lint were all run on 2026-10-08. The patched build could not be completed in the environment where this was prepared because its egress policy blocks `packages.wolfi.dev` and `apk.cgr.dev`; the build reached the `apk add` step and failed there as designed. Grype could not be run there either because `grype.anchore.io` is blocked. `scan.sh` covers both, so run it before relying on the patched image

Vulnerability databases change daily, so new findings can appear against the same digest. Re-run `scan.sh` on a schedule, and re-review the VEX whenever the base digest changes
