FROM aquasec/trivy:0.4.4 as builder

ARG TRIVY_CACHE_DIR=trivy_cache

RUN mkdir $TRIVY_CACHE_DIR && \
    trivy --quiet --download-db-only --cache-dir $TRIVY_CACHE_DIR/ && \
    tar cvfz trivy_cache.tgz $TRIVY_CACHE_DIR

FROM alpine
WORKDIR /
COPY --from=builder /usr/local/bin/trivy trivy_cache.tgz /
COPY entrypoint.sh vulcan-docker-image-trivy /
CMD ["/entrypoint.sh"]
