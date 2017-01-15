FROM alpine

RUN set -x \
    && apk update \
    && apk add --no-cache \
        openssl \
        curl \
        bash && \
  rm -rf /var/cache/apk/*
