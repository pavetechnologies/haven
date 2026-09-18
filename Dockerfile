FROM oven/bun:1.2-alpine
WORKDIR /app
COPY platform/package.json ./
COPY platform/src ./src
COPY platform/scripts ./scripts
COPY ui/dist ./ui-dist
ENV HAVEN_DATA_DIR=/data
ENV HAVEN_PORT=19090
ENV HAVEN_UI_DIST=/app/ui-dist
EXPOSE 19090
VOLUME ["/data"]
CMD ["bun", "run", "src/index.ts"]
