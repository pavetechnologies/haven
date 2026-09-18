FROM oven/bun:1.2-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY scripts ./scripts
# Optional: build UI separately and mount/copy into /app/ui-dist, then set HAVEN_UI_DIST
ENV HAVEN_DATA_DIR=/data
ENV HAVEN_PORT=19090
ENV HAVEN_UI_DIST=/app/ui-dist
EXPOSE 19090
VOLUME ["/data"]
CMD ["bun", "run", "src/index.ts"]
