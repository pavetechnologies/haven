# Stage 1: build the operator UI from source, so the image never ships a stale ui/dist.
FROM oven/bun:1.2-alpine AS ui
WORKDIR /ui
COPY ui/package.json ui/bun.lock ./
RUN bun install --frozen-lockfile
COPY ui ./
RUN bun run build

# Stage 2: platform runtime.
FROM oven/bun:1.2-alpine
WORKDIR /app
COPY platform/package.json ./
COPY platform/src ./src
COPY platform/scripts ./scripts
COPY --from=ui /ui/dist ./ui-dist
ENV HAVEN_DATA_DIR=/data
ENV HAVEN_PORT=19090
ENV HAVEN_UI_DIST=/app/ui-dist
EXPOSE 19090
VOLUME ["/data"]
CMD ["bun", "run", "src/index.ts"]
