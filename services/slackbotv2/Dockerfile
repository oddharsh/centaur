# syntax=docker/dockerfile:1.7

FROM oven/bun:1.4.4-slim

WORKDIR /repo
ENV NODE_ENV=production

# Workspace manifests first so dependency install is a cached layer. slackbotv2
# depends on the @centaur/* workspace packages, so they must be present for
# bun to link the `workspace:*` ranges.
COPY package.json bun.lock bunfig.toml ./
COPY patches/ patches/
COPY packages/ packages/
COPY services/slackbotv2/package.json services/slackbotv2/package.json
RUN --mount=type=cache,target=/root/.bun/install/cache,sharing=locked \
    bun install --filter slackbotv2 --production --frozen-lockfile

COPY services/slackbotv2/ services/slackbotv2/
# Harness config files: response-context.ts imports the baked default models
# so Slack response metadata can name the model without a hardcoded copy.
COPY harness/ harness/
WORKDIR /repo/services/slackbotv2

EXPOSE 3001
ENV PORT=3001
CMD ["bun", "src/server.ts"]
