# One-command download:  docker compose up --build   →   http://127.0.0.1:8900
# Everything runs on the user's machine. The scanner talks only to the
# targets it assesses; the app itself makes no outbound calls at runtime
# (the mongod binary for the built-in lab is fetched at BUILD time).
FROM node:24-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
RUN node scripts/warm-cache.mjs
EXPOSE 8900
ENV PORT=8900 HOST=0.0.0.0
CMD ["node", "app/server.mjs"]
