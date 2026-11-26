FROM node:22-alpine
WORKDIR /app
COPY bot.mjs .
USER node
CMD ["node", "bot.mjs"]
