FROM node:22-alpine
WORKDIR /opt/discord-auto-approve
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && mkdir -p /app/data && chown node:node /app/data
COPY bot.mjs ./
COPY anticrash ./anticrash
ENV DATA_DIR=/app/data
USER node
CMD ["node", "/opt/discord-auto-approve/bot.mjs"]
