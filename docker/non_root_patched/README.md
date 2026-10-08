# CVE remediation for litellm-non_root v1.104.2

This directory addresses every finding in the grype scan of `litellm/litellm-non_root:v1.104.2` recorded in `evidence/grype-stock-v1.104.2.txt`: 63 matches across glibc, OpenSSL, Python, and alsa-lib. The patched image fixes 58 of them on amd64 by upgrading or removing packages. The remaining 2 on amd64 (5 on arm64) have no fix anywhere upstream and are justified in an OpenVEX document and matching grype ignore rules, each backed by evidence anyone can re-run

| File | Purpose |
| --- | --- |
| `Dockerfile` | Your Dockerfile, changed so the upgrade actually happens |
| `scan.sh` | Builds the patched image with Podman, smoke tests it, and gates on grype and Trivy |
| `litellm-non_root-v1.104.2.openvex.json` | OpenVEX justification for the findings that have no fix |
| `.grype.yaml` | grype ignore rules mirroring the OpenVEX statements |
| `evidence/` | The baseline grype run, Trivy reports for the stock image, and linkage and runtime evidence |

## Why the original Dockerfile changed nothing

The original Dockerfile built successfully, but the image it produced has exactly the same 52 packages as the stock image. Building it with Podman shows why

```
fetch https://apk.cgr.dev/chainguard/x86_64/APKINDEX.tar.gz
WARNING: ignoring authenticated repository https://apk.cgr.dev/chainguard: no HTTP_AUTH provided
OK: 212 MiB in 52 packages
```

The image's only apk repository is Chainguard's, which requires credentials, so apk skips it and still exits 0. Even with access, `/etc/apk/world` pins 14 packages to exact versions, including all four glibc packages and `libcrypto3`/`libssl3`, so `apk upgrade` would not have moved the vulnerable packages

## What the Dockerfile does now

It keeps your `FROM`, CA build arguments, and `USER nobody`, and makes three changes in one step

1. It removes `libsndfile` when the `soundfile` Python wheel bundles its own copy of the library, which is the case on amd64. Nothing in the proxy uses the system package there, and removing it also removes `alsa-lib`, `libflac`, `libogg`, `libopus`, and `libvorbis`. On arm64 the wheel bundles nothing and falls back to the system library, so it is kept
2. It removes the exact version pins from `/etc/apk/world`
3. It runs `apk upgrade` against the public Wolfi repository (`APK_REPOSITORY`, default `https://packages.wolfi.dev/os`), with your CA bundle as `SSL_CERT_FILE`. apk does honor `SSL_CERT_FILE`; this was checked through a TLS-intercepting proxy

If Wolfi cannot be reached, the build fails with `ERROR: Not continuing due to stale/unavailable repositories` (exit 99) instead of producing an unpatched image. If you mirror Wolfi internally, pass `--build-arg APK_REPOSITORY=https://your-mirror/os`

## Disposition of every finding

| Rows | Package | Vulnerabilities | Disposition |
| --- | --- | --- | --- |
| 32 | glibc-2.44, glibc-2.44-locale-posix, ld-linux-2.44, libcrypt1-2.44 | CVE-2026-8674, CVE-2026-86805, CVE-2026-89092, CVE-2026-95818, plus GHSA-fmf4-pr35-46c2, GHSA-gwqp-9qgw-c5pv, GHSA-h8x4-734c-9753, GHSA-qghr-qhfc-4hxp | Fixed: upgraded to 2.44-r8 |
| 26 | libcrypto3, libssl3 | CVE-2026-84782, CVE-2026-35189, CVE-2026-35191, CVE-2026-42772, CVE-2026-54872, CVE-2026-54873, CVE-2026-54875, CVE-2026-72897, CVE-2026-75804, CVE-2026-75805, CVE-2026-75806, CVE-2026-77696, CVE-2026-84784 | Fixed: upgraded to OpenSSL 3.6.5 |
| 3 | alsa-lib | CVE-2026-90781, CVE-2026-96674, CVE-2026-96675 | amd64: removed. arm64: not_affected, vulnerable_code_not_in_execute_path |
| 1 | python-3.13 | CVE-2025-15367 | not_affected, vulnerable_code_not_in_execute_path |
| 1 | python-3.13 | CVE-2026-12345 | not_affected, vulnerable_code_cannot_be_controlled_by_adversary |

## Evidence

### OpenSSL

OpenSSL's own changelog for 3.6.5 (released 29 Sep 2026, tag `openssl-3.6.5`, commit `c8bd5a57`) lists all 13 CVEs as fixed. Wolfi currently ships `openssl` 3.6.5-r1. grype showed no fixed version only because its database was built before that release. OpenSSL rates CVE-2026-84782 (DTLS retransmission heap disclosure) High and the other 12 Low; grype's four High ratings come from a different severity source

These had to be fixed rather than justified. Package metadata says only `apk-tools` depends on `libcrypto3`/`libssl3`, but Prisma's query and schema engines, which are not apk packages, link `libssl.so.3` and `libcrypto.so.3` directly (see `evidence/linkage-and-runtime.txt`). The query engine is how LiteLLM talks to its database, so OpenSSL 3.6 is on a live TLS path

### glibc

Both the Wolfi and Chainguard advisory feeds record all four CVEs as fixed in `2.44-r8`, and Wolfi currently ships glibc-2.44 at epoch 8. The baseline grype run reports the four GHSA advisories against the same four packages with the same fixed version, `2.44-r8`, so the upgrade clears them too. Whether they are aliases of the four CVEs was not established, since none of the advisory data available while preparing this lists them

### alsa-lib

On both architectures, only three files link `libasound.so.2`: `/usr/bin/sndfile-play`, `/usr/bin/aserver`, and `/usr/lib/libatopology.so`. `libsndfile.so.1` itself links only libm, the ogg/vorbis/FLAC/opus codec libraries, and libc. In a running proxy on amd64, after a `soundfile` write and read round trip, no process maps `libasound`, and `soundfile` loads the library bundled in its wheel rather than the system one. That is why removing the system package on amd64 is safe; the smoke test in `scan.sh` re-checks the round trip on every build. All three CVEs affect alsa-lib "through 1.2.16.1" and no fixed release exists

### Python

The image's Python is a snapshot of CPython's 3.13 branch at commit `15e701a` (2026-10-01), which is the current head of that branch, so no newer 3.13 build exists to upgrade to. The installed `poplib.py` and `tempfile.py` do not contain fixes for these two CVEs

CVE-2025-15367 is a newline injection in `poplib` that requires an application to pass user-controlled strings as POP3 commands. No module in the image's virtual environment imports `poplib`

CVE-2026-12345 is a race in `TemporaryDirectory` cleanup that requires an attacker who can modify the directory tree while it is being removed. Those directories are created by `mkdtemp` with mode 0700 and owned by the process user, so only uid 65534 or root can change them, and the container runs a single workload as uid 65534. LiteLLM's own uses (`litellm/llms/sap/credentials.py` and the skills sandbox executor) stage files the proxy writes itself; skill code runs in a separate sandbox container and cannot reach the proxy's temporary directories

### Conditions the justifications depend on

Keep running the proxy as the only workload in the container under uid 65534, do not share its temporary directory with other users or containers, and do not run untrusted code inside the proxy's container. If any of that changes, revisit the CVE-2026-12345 statement

## Running it

```
CA_BUNDLE=/path/to/your/ca-bundle.pem ./scan.sh
```

`CA_BUNDLE` is optional. When set it is mounted at `/ca-bundle.pem` for the build, as your Dockerfile expects, and given to the scanner containers so they can download their databases through a TLS-intercepting proxy. Without it the build uses the image's own CA bundle. The build needs to reach `packages.wolfi.dev` (or your mirror) and the scanners need their database hosts

The script builds the image, prints the installed versions of every package the scan flagged, starts the proxy with networking disabled and waits for `/health/liveliness`, round-trips audio through `soundfile`, then exports the image with `podman save` and scans it. It fails unless grype v0.120.1 with a freshly updated database reports zero findings beyond the justified ones, at any severity including Unknown, and Trivy 0.75.0 does the same. Both scanners are pinned by digest and run in containers, so nothing needs to be installed and no Podman socket is needed. Reports land in `reports/`, which is git-ignored and excluded from the build context because the export is about 2 GB

For a multi-arch image use `podman build --platform linux/amd64,linux/arm64 --manifest localhost/litellm-non_root:v1.104.2-patched .` (needs `qemu-user-static` for the foreign architecture)

## Notes on the scanners

The baseline grype run used grype 0.115.0 with a database it reported as 13 weeks old, which is why OpenSSL and alsa-lib showed no fixed version. `scan.sh` updates the database and uses the current grype release

grype's `--fail-on` ranks Unknown below Negligible, so `--fail-on negligible` would let the 16 Unknown-severity rows through. The gate in `scan.sh` counts every match in the JSON report instead

The VEX and the ignore rules name packages and exact versions, not image digests, because a locally built image has no registry digest for a scanner to match. If Wolfi ships a newer Python or alsa-lib, the rules stop matching and the findings reappear, which is intended: the new version needs its own review

Trivy does not report the OpenSSL, Python, or alsa-lib findings at all, only the glibc ones, so grype is the stricter gate here

Neither scanner sees the libsndfile 1.2.0 bundled inside the `soundfile` wheel, which is the copy that parses user-uploaded audio for NVIDIA Riva transcriptions on amd64. CVE-2024-50612 is recorded against libsndfile "through 1.2.2" and is in the Vorbis encoding path, which LiteLLM does not use when reading audio. libsndfile's changelog does not name CVEs, so whether CVE-2022-33064 and CVE-2022-33065 affect 1.2.0 was not established. This is outside the grype findings but worth a decision

## What was and was not verified

Run on 2026-10-08 with Podman 4.9.3. The original Dockerfile was built and its package set diffed against the stock image. The new Dockerfile was built: the `libsndfile` removal ran, the pins were removed, and the upgrade step failed closed because the build environment's egress policy blocks `packages.wolfi.dev`. A stand-in image without the upgrade passed the liveness and `soundfile` smoke test after the removal, its archive scanned under Trivy with the VEX accepted, and the Trivy gate correctly failed on the stand-in's unpatched glibc. The `.grype.yaml` rules were loaded and validated by grype v0.120.1. The linkage evidence was gathered on both architectures and the runtime evidence on amd64

Not verified there: the upgraded packages themselves and any grype scan, because `packages.wolfi.dev` and grype's database host are blocked in that environment. Run `scan.sh` before relying on the image
