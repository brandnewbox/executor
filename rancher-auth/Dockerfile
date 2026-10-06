# Built from the repository root: docker build --target runtime -f rancher-auth/Dockerfile .
FROM oven/bun:1.3-distroless AS runtime
WORKDIR /app
LABEL org.opencontainers.image.source="https://github.com/brandnewbox/executor" \
      org.opencontainers.image.description="Signs Executor in to Rancher with long-lived, rolling Rancher API tokens"
ENV NODE_ENV=production PORT=8080
COPY rancher-auth/src ./src
EXPOSE 8080
# distroless nonroot, numeric so Kubernetes can verify runAsNonRoot
USER 65532:65532
CMD ["src/server.ts"]
