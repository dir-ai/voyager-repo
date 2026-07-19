# pathfinder (voyager-repo) — containerized read-only repo scout. Mount a repo and
# orient in it; nothing in the target is executed.
#   docker run --rm -v "$PWD:/repo:ro" ghcr.io/dir-ai/voyager-repo scout /repo
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --no-audit --no-fund
COPY src ./src
RUN npm run build

FROM node:22-alpine
# git is needed for the health scan (read-only).
RUN apk add --no-cache git
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY server.json LICENSE README.md ./
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["help"]
