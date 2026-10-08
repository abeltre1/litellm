ARG BASE_IMAGE=docker.io/litellm/litellm-non_root@sha256:e8dee87e7ddbf9abc174e8a7b180a690d5265cc4827458d22c5ff5e108170027

FROM ${BASE_IMAGE}

ARG APK_REPOSITORY=https://packages.wolfi.dev/os

USER root

RUN apk add --no-cache --repositories-file /dev/null --repository "${APK_REPOSITORY}" \
      "glibc-2.44>=2.44-r8" \
      "glibc-2.44-locale-posix>=2.44-r8" \
      "ld-linux-2.44>=2.44-r8" \
      "libcrypt1-2.44>=2.44-r8"

USER 65534
