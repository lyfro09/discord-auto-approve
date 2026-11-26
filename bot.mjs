import { setTimeout as sleep } from 'node:timers/promises';

const apiBase = 'https://discord.com/api/v10';
const pageSize = 100;
const stopAntiCrash = new AbortController();
const isId = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value);

class DiscordError extends Error {
  constructor(method, status, code) {
    super(`Discord ${method}: HTTP ${status}${Number.isInteger(code) ? ` (код ${code})` : ''}`);
    this.status = status;
  }
}

function createClient(token) {
  let nextRequestAt = 0;

  return async function request(method, path, body) {
    while (true) {
      const wait = nextRequestAt - Date.now();
      if (wait > 0) await sleep(wait);

      const response = await fetch(apiBase + path, {
        method,
        headers: {
          Authorization: `Bot ${token}`,
          'Content-Type': 'application/json',
          'User-Agent': 'DiscordBot (https://github.com/lyfro09/discord-auto-approve, 1.0)',
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: 'error',
        signal: AbortSignal.timeout(15_000),
      });

      const data = await response.json().catch(error => {
        if (response.ok && response.status !== 204) throw error;
        return null;
      });

      if (response.status === 429 || response.headers.get('x-ratelimit-remaining') === '0') {
        const seconds = Number(
          data?.retry_after
          ?? response.headers.get('retry-after')
          ?? response.headers.get('x-ratelimit-reset-after')
          ?? 1,
        );
        nextRequestAt = Date.now() + (Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : 1000);
      }

      if (response.status === 429) continue;
      if (!response.ok) throw new DiscordError(method, response.status, data?.code);
      return data;
    }
  };
}

async function listPage(request, path, before) {
  const query = new URLSearchParams({ status: 'SUBMITTED', limit: String(pageSize) });
  if (before) query.set('before', before);

  const result = await request('GET', `${path}?${query}`);
  const entries = result?.guild_join_requests;
  if (Array.isArray(entries) && entries.every(entry => isId(entry?.id))) return entries;
  if (entries === undefined && result && (result.total === 0 || Object.keys(result).length === 0)) {
    return [];
  }
  throw new Error('Discord вернул неожиданный формат списка заявок.');
}

async function approvePending(request, path) {
  let before;

  do {
    const entries = await listPage(request, path, before);
    if (before && entries.some(entry => BigInt(entry.id) >= BigInt(before))) {
      throw new Error('Discord вернул повторную страницу заявок.');
    }

    for (const entry of entries) {
      if (entry.application_status !== 'SUBMITTED') continue;

      try {
        await request('PATCH', `${path}/${entry.id}`, { action: 'APPROVED' });
        console.log(`[${new Date().toISOString()}] Одобрена заявка ${entry.id}`);
      } catch (error) {
        if (![400, 404, 409].includes(error.status)) throw error;
        console.warn(`Заявка ${entry.id}: ${error.message}`);
      }
    }

    if (entries.length < pageSize) return;
    before = entries.reduce((oldest, entry) =>
      BigInt(entry.id) < BigInt(oldest) ? entry.id : oldest, entries[0].id);
  } while (before);
}

async function main() {
  const token = process.env.DISCORD_BOT_TOKEN?.trim();
  const guild = process.env.DISCORD_GUILD_ID?.trim();
  const interval = Number(process.env.POLL_INTERVAL_MS ?? 2000);
  if (!token || !isId(guild) || !Number.isInteger(interval) || interval < 1000 || interval > 60_000) {
    throw new Error('Укажи DISCORD_BOT_TOKEN, DISCORD_GUILD_ID и интервал от 1000 до 60000 мс.');
  }

  const request = createClient(token);
  const path = `/guilds/${guild}/requests`;
  if (process.argv.includes('--check')) {
    const entries = await listPage(request, path);
    console.log(`Доступ к списку есть. Заявок на первой странице: ${entries.length}.`);
    return;
  }

  const protection = process.env.ANTICRASH_ENABLED !== 'false';
  const configuredRole = process.env.DISCORD_JOIN_ROLE_ID?.trim();
  const role = isId(configuredRole) ? configuredRole : undefined;
  if (configuredRole && !role) console.error('Автовыдача при входе: укажи числовой DISCORD_JOIN_ROLE_ID.');
  if (protection || role) {
    void import('./anticrash/index.mjs')
      .then(module => module.startAntiCrash(token, stopAntiCrash.signal, {
        protection, guild, role, publishLogs: process.env.DISCORD_LOG_MESSAGES === 'true',
      }))
      .catch(error => console.error(`Антикраш не запустился: ${error.message}`));
  }

  console.log(`Бот запущен для сервера ${guild}. Интервал проверки: ${interval} мс.`);
  let retryDelay = interval;
  while (true) {
    try {
      await approvePending(request, path);
      retryDelay = interval;
    } catch (error) {
      if (error.status === 401) throw error;
      retryDelay = Math.min(retryDelay * 2, 60_000);
      console.error(`${error.message} Следующая попытка через ${retryDelay / 1000} сек.`);
    }
    await sleep(retryDelay);
  }
}

main().catch(error => {
  stopAntiCrash.abort();
  console.error(error.message);
  process.exitCode = 1;
});
