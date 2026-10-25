FROM node:24-alpine

WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod
COPY src ./src
# Persistent signing keys: the volume mounted on /data must belong to node.
RUN mkdir /data && chown node:node /data

ENV NODE_ENV=production PORT=4000 KEYS_FILE=/data/keys.json
EXPOSE 4000
USER node
CMD ["node", "src/server.js"]
