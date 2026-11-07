# syntax=docker/dockerfile:1.7

FROM oven/bun:1.4.4-slim

WORKDIR /repo
ENV NODE_ENV=production

# Workspace manifests first so dependency install is a cached layer. teamsbot
# depends on the @centaur/* workspace packages, so they must be present for
# bun to link the `workspace:*` ranges.
COPY package.json bun.lock bunfig.toml ./
COPY patches/ patches/
COPY packages/ packages/
COPY services/teamsbot/package.json services/teamsbot/package.json
RUN --mount=type=cache,target=/root/.bun/install/cache,sharing=locked \
    bun install --filter teamsbot --production --frozen-lockfile

COPY services/teamsbot/ services/teamsbot/
WORKDIR /repo/services/teamsbot

EXPOSE 3100
ENV PORT=3100
USER bun
CMD ["bun", "src/server.ts"]
