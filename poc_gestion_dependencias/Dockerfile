ARG TRIVY_VERSION=0.76.2
FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

FROM alpine:3.23

RUN apk add --no-cache ca-certificates libstdc++ nodejs npm \
    && addgroup -S -g 1000 node \
    && adduser -S -D -u 1000 -G node -h /home/node node

WORKDIR /app

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

COPY index.js package.json ./
COPY config/ ./config/
COPY data/ ./data/
COPY src/ ./src/

RUN mkdir -p /app/output /home/node/.cache/trivy /home/node/.npm \
    && chown -R node:node /app /home/node/.cache /home/node/.npm \
    && chmod -R a+rwx /app/output /home/node/.cache/trivy /home/node/.npm

ENV HOME=/home/node \
    TRIVY_BIN=/usr/local/bin/trivy \
    TRIVY_CACHE_DIR=/home/node/.cache/trivy \
    NPM_CONFIG_CACHE=/home/node/.npm

USER node

ENTRYPOINT ["node", "index.js"]
