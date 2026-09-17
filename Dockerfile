ARG EXECUTOR_VERSION=v1.6.8

FROM alpine/git:2.49.1 AS upstream
ARG EXECUTOR_VERSION
RUN git clone --depth 1 --branch "${EXECUTOR_VERSION}" https://github.com/UsefulSoftwareCo/executor.git /executor

FROM oven/bun:1 AS source
WORKDIR /src
COPY --from=upstream /executor .
COPY executor.config.ts apps/host-selfhost/executor.config.ts
RUN bun -e 'const path = "apps/host-selfhost/package.json"; const pkg = await Bun.file(path).json(); pkg.dependencies["@executor-js/plugin-onepassword"] = "workspace:*"; await Bun.write(path, JSON.stringify(pkg, null, 2) + "\n");'

FROM oven/bun:1 AS prod-deps
WORKDIR /app
COPY --from=source /src .
RUN bun install --production --ignore-scripts --filter @executor-js/host-selfhost \
  && bun run apps/host-selfhost/scripts/package-runtime.ts

FROM oven/bun:1 AS build
WORKDIR /app
COPY --from=source /src .
RUN bun install
RUN cd apps/host-selfhost && bun run build

FROM gcr.io/distroless/cc-debian12 AS runtime
ARG EXECUTOR_VERSION
WORKDIR /app
LABEL org.opencontainers.image.source="https://github.com/brandnewbox/executor" \
      org.opencontainers.image.description="Brand New Box self-hosted Executor with 1Password support" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${EXECUTOR_VERSION}"
ENV NODE_ENV=production \
    EXECUTOR_HOST=0.0.0.0 \
    PORT=4788 \
    EXECUTOR_DATA_DIR=/data
COPY --from=prod-deps /usr/local/bin/bun /usr/local/bin/bun
COPY --from=prod-deps /app/.selfhost-runtime /app
COPY --from=prod-deps /app/node_modules/.bun/node_modules/@1password/sdk-core/nodejs/core_bg.wasm /usr/local/bin/onepassword-core_bg.wasm
COPY --from=build /app/apps/host-selfhost/dist /app/apps/host-selfhost/dist
WORKDIR /app/apps/host-selfhost
VOLUME ["/data"]
EXPOSE 4788
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 \
  CMD ["bun", "-e", "fetch('http://127.0.0.1:4788/api/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["bun", "run", "dist-server/serve.js"]
