# Dashboard image — results only, no scanner, no mongod needed.
#   docker build -f dashboard/Dockerfile -t mongo-sec-dashboard .
# Storage: mount a volume at /data and set DASH_DATA_DIR=/data so run
# history survives redeploys. Set DASHBOARD_TOKEN to a real secret.
FROM node:24-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 8901
ENV HOST=0.0.0.0 DASH_DATA_DIR=/data
CMD ["node", "dashboard/server.mjs"]
