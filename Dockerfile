FROM node:22-alpine
WORKDIR /opt/discord-auto-approve
COPY package.json package-lock.json ./
RUN apk add --no-cache su-exec && npm ci --omit=dev && mkdir -p /app/data && chown node:node /app/data
COPY bot.mjs ./
COPY anticrash ./anticrash
COPY docker-entrypoint.sh /usr/local/bin/discord-bot-entrypoint
RUN chmod 755 /usr/local/bin/discord-bot-entrypoint
WORKDIR /app
ENV DATA_DIR=/app/data
ENTRYPOINT ["/usr/local/bin/discord-bot-entrypoint"]
CMD ["node", "/opt/discord-auto-approve/bot.mjs"]
