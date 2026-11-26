# Автоодобрение заявок в Discord

Бот одобряет все отправленные заявки на вступление на одном сервере с режимом **Apply to Join**. При запуске он обрабатывает накопившиеся заявки, затем проверяет очередь каждые 2 секунды по умолчанию. При сетевых сбоях повторяет попытки и учитывает ограничения частоты запросов Discord.

## Настройка

1. Создай приложение в [Discord Developer Portal](https://discord.com/developers/applications) и скопируй токен со вкладки **Bot**.
2. Установи приложение на нужный сервер со scope **bot** и разрешением **Kick Members**. На сервере должен быть включён **Apply to Join**. [Настройки заявок на вступление](https://support.discord.com/hc/en-us/articles/29729107418519-Server-Member-Applications)
3. Включи режим разработчика в Discord и скопируй ID сервера через его контекстное меню.
4. Скопируй `.env.example` в `.env`. Заполни `DISCORD_BOT_TOKEN` и `DISCORD_GUILD_ID`. Файл `.env` исключён из Git.

## Запуск

Требуется Node.js 22 или новее. Сначала можно проверить доступ к очереди в режиме чтения.

```sh
node --env-file=.env bot.mjs --check
node --env-file=.env bot.mjs
```

Для работы 24/7 запусти контейнер на постоянно включённом компьютере или VPS. Docker перезапустит его после сбоя или перезагрузки хоста.

```sh
docker build -t discord-auto-approve .
docker run -d --restart unless-stopped --env-file .env --name discord-auto-approve discord-auto-approve
docker logs -f discord-auto-approve
```

Запускай один экземпляр на сервер Discord. В логах отображаются ID одобренных заявок и сообщения об ошибках. HTTP 401 означает проблему с токеном. При HTTP 403 проверь, что бот установлен на сервер и у него есть разрешение **Kick Members**.

[Спецификация Discord API](https://github.com/discord/discord-api-spec/blob/main/specs/openapi.json)
