# One-command download:  docker compose up --build   →   http://127.0.0.1:8900
# Everything runs on the user's machine. The scanner talks only to the
# targets it assesses; the app itself makes no outbound calls at runtime
# (the mongod binary for the built-in lab is fetched at BUILD time).
FROM node:24-bookworm-slim
# The mongod binary mongodb-memory-server downloads (Ubuntu build) links
# libcurl/libssl/lzma, which the slim image does not ship — without these
# the lab's mongod dies on start with "libcurl.so.4: cannot open".
RUN apt-get update && apt-get install -y --no-install-recommends libcurl4 libssl3 liblzma5 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
RUN node scripts/warm-cache.mjs
EXPOSE 8900
ENV PORT=8900 HOST=0.0.0.0
CMD ["node", "app/server.mjs"]
