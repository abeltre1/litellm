FROM litellm/litellm-non_root:v1.104.2

USER root

ARG BUILD_SSL_CERT_FILE=/ca-bundle.pem
ARG BUILD_NODE_EXTRA_CA_CERTS=/ca-bundle.pem
ARG APK_REPOSITORY=https://packages.wolfi.dev/os

RUN if [ -e "/app/.venv/lib/python3.13/site-packages/_soundfile_data/libsndfile_$(uname -m).so" ]; then \
      apk del --no-cache libsndfile; \
    fi && \
    sed -i -E 's/^([^=<>~]+)[=<>~].*$/\1/' /etc/apk/world && \
    SSL_CERT_FILE="${BUILD_SSL_CERT_FILE}" \
    NODE_EXTRA_CA_CERTS="${BUILD_NODE_EXTRA_CA_CERTS}" \
    apk upgrade --no-cache --repositories-file /dev/null --repository "${APK_REPOSITORY}"

USER nobody
