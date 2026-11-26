import { randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { AuditLogEvent as A, Client, Events, GatewayIntentBits as I, Routes } from 'discord.js';
import { commandData, handleCommand } from './commands.mjs';
import { acceptAudit, closeObservations, observe, revokeGrants } from './detect.mjs';
import { auditStart, DiscordServer, normalizeAudit, observationFor } from './discord.mjs';
import { dangerous, isId, isManager } from './policy.mjs';
import { applyQuarantine, releaseQuarantine } from './quarantine.mjs';
import { decoded, Store } from './store.mjs';
import { field, readableText, userRef } from './presentation.mjs';

const describe = error => String(error.message ?? error).slice(0, 230);

export class AntiCrash {
  constructor(client, store) {
    this.client = client;
    this.store = store;
    this.servers = new Map();
    this.auditQueues = new Map();
    this.polling = new Set();
    this.working = new Set();
    this.registered = new Set();
    this.registering = new Set();
    this.backfill = new Map();
    this.shardSession = new Map();
  }

  server(guild) {
    if (!this.servers.has(guild.id)) this.servers.set(guild.id, new DiscordServer(guild, this.store));
    return this.servers.get(guild.id);
  }

  safe(guild, context, error, log = true) {
    const message = `Антикраш ${guild} · ${context} · ${describe(error)}`;
    console.error(message);
    if (log) this.store.log(guild, {
      title: 'Ошибка антикраша', tone: 'error',
      fields: [field('Операция', context, false)],
      description: readableText(describe(error), this.client.guilds.cache.get(guild)),
    });
  }

  start() {
    const { client } = this;
    client.on(Events.ClientReady, () => {
      for (const guild of client.guilds.cache.values()) this.online(guild);
    });
    client.on(Events.ShardReady, shard => this.shardSession.set(shard, randomUUID()));
    client.on(Events.GuildAvailable, guild => {
      if (client.isReady()) this.online(guild);
    });
    client.on(Events.GuildCreate, guild => {
      if (client.isReady()) this.online(guild);
    });
    client.on(Events.GuildDelete, guild => {
      this.servers.delete(guild.id);
      this.registered.delete(guild.id);
    });
    client.on(Events.Error, error => console.error(`Антикраш Gateway: ${describe(error)}`));
    client.on(Events.ShardError, error => console.error(`Антикраш Gateway: ${describe(error)}`));
    client.on(Events.Raw, (packet, shard) => {
      const guild = packet.d?.guild_id ?? (packet.t === 'GUILD_UPDATE' ? packet.d.id : null);
      if (!guild || !client.isReady()) return;
      const server = client.guilds.cache.get(guild);
      if (!server) return;
      try { this.gateway(this.server(server), packet, shard); }
      catch (error) { this.safe(guild, 'обработка Gateway', error); }
    });
    client.on(Events.InteractionCreate, interaction => {
      if (!interaction.isChatInputCommand() || interaction.commandName !== 'anticrash' || !interaction.inGuild()) return;
      const guild = client.guilds.cache.get(interaction.guildId);
      if (guild) void handleCommand(this.store, this.server(guild), interaction)
        .catch(error => this.safe(guild.id, 'ответ на команду', error, false));
    });
    this.timer = setInterval(() => {
      try { this.tick(); }
      catch (error) { console.error(`Антикраш: ${describe(error)}`); }
    }, 5000);
    this.timer.unref();
  }

  stop() {
    clearInterval(this.timer);
    this.client.destroy();
  }

  online(guild) {
    if (!guild.available) return;
    this.store.run(`UPDATE quarantine SET phase='queued',due=0,revision=revision+1
      WHERE guild=? AND phase IN ('active','partial','absent')`, guild.id);
    void this.register(guild);
    this.tick();
  }

  async register(guild) {
    if (this.registered.has(guild.id) || this.registering.has(guild.id)) return;
    this.registering.add(guild.id);
    try {
      const route = Routes.applicationGuildCommands(this.client.user.id, guild.id);
      await this.client.rest.post(route, { body: commandData });
      this.registered.add(guild.id);
    } catch (error) {
      this.safe(guild.id, 'регистрация /anticrash', error, false);
    } finally {
      this.registering.delete(guild.id);
    }
  }

  enqueueAudit(server, entry) {
    const guild = server.guild.id;
    if (!isId(entry.id)) return Promise.resolve();
    const prior = this.auditQueues.get(guild) ?? Promise.resolve();
    const task = prior.catch(() => {}).then(async () => {
      const settings = this.store.settings(guild);
      if (settings.mode === 'off' || settings.since > entry.at) return;
      const prior = this.store.get('SELECT data FROM audit WHERE guild=? AND id=?', guild, entry.id);
      if (prior) {
        if (entry.options.webhook_channel_id) {
          const known = JSON.parse(prior.data);
          if (!known.options.webhook_channel_id) {
            known.options.webhook_channel_id = entry.options.webhook_channel_id;
            this.store.run('UPDATE audit SET data=? WHERE guild=? AND id=?', JSON.stringify(known), guild, entry.id);
          }
        }
        return;
      }
      const identity = await server.identity(entry, settings);
      acceptAudit(this.store, guild, entry, identity);
    });
    this.auditQueues.set(guild, task);
    void task.finally(() => {
      if (this.auditQueues.get(guild) === task) this.auditQueues.delete(guild);
    }).catch(() => {});
    return task;
  }

  gateway(server, packet, shard) {
    const guild = server.guild.id;
    const { t, d } = packet;
    const settings = this.store.settings(guild);
    if (settings.mode === 'off') return;
    server.facts(packet);
    const now = Date.now();

    if (t === 'GUILD_UPDATE' && d.owner_id && d.owner_id !== server.guild.ownerId) {
      settings.ownerSince = now;
      settings.managers = [];
      settings.managerSince = {};
      this.store.transaction(() => {
        this.store.saveSettings(guild, settings);
        this.store.log(guild, {
          title: 'Владелец сервера сменился', tone: 'settings',
          description: 'Прежние назначения администраторов антикраша отозваны.',
          fields: [field('Новый владелец', userRef(d.owner_id))],
        });
      });
    }

    if (t === 'GUILD_AUDIT_LOG_ENTRY_CREATE') {
      void this.enqueueAudit(server, normalizeAudit(d))
        .catch(error => this.safe(guild, 'запись Audit Log', error));
      return;
    }

    if (t === 'GUILD_MEMBER_REMOVE') {
      revokeGrants(this.store, guild, d.user.id, now);
      this.store.run(`UPDATE quarantine SET phase='absent',revision=revision+1
        WHERE guild=? AND member=? AND phase IN ('active','partial')`, guild, d.user.id);
    }
    if (t === 'GUILD_MEMBER_ADD') {
      revokeGrants(this.store, guild, d.user.id, Date.parse(d.joined_at) || now);
      this.store.run(`UPDATE quarantine SET phase='queued',revision=revision+1,due=0
        WHERE guild=? AND member=? AND phase IN ('absent','active','partial')`, guild, d.user.id);
    }
    if (t === 'GUILD_MEMBER_UPDATE') {
      const before = server.guild.members.cache.get(d.user.id);
      if (before) {
        for (const role of before.roles.cache.keys()) {
          if (role !== guild && !d.roles.includes(role) && settings.trust[`role:${role}`]) {
            revokeGrants(this.store, guild, d.user.id, now, role);
          }
        }
      }
      const q = this.store.getQuarantine(guild, d.user.id);
      if (q && q.phase === 'active' && (!d.roles.includes(q.data.quarantineRole)
        || d.roles.some(id => dangerous(server.guild.roles.cache.get(id)?.permissions.bitfield)))) {
        this.store.saveQuarantine(q, 'queued');
      }
    }
    if (t === 'CHANNEL_CREATE') {
      this.store.run(`UPDATE quarantine SET phase='queued',revision=revision+1,due=0
        WHERE guild=? AND phase='active'`, guild);
    }
    if (t === 'CHANNEL_UPDATE' && d.permission_overwrites) {
      const prior = server.guild.channels.cache.get(d.id)?.permissionOverwrites?.cache;
      for (const q of this.store.all(`SELECT member FROM quarantine WHERE guild=? AND phase='active'`, guild)) {
        const old = prior?.get(q.member);
        const next = d.permission_overwrites.find(item => item.id === q.member);
        if (BigInt(next?.allow ?? 0) !== (old?.allow.bitfield ?? 0n)
          || BigInt(next?.deny ?? 0) !== (old?.deny.bitfield ?? 0n)) {
          this.store.run(`UPDATE quarantine SET phase='queued',revision=revision+1,due=0
            WHERE guild=? AND member=? AND phase='active'`, guild, q.member);
        }
      }
    }
    if (t === 'GUILD_ROLE_UPDATE' || t === 'GUILD_ROLE_DELETE') {
      const role = d.role?.id ?? d.role_id;
      const old = server.guild.roles.cache.get(role);
      if (settings.trust[`role:${role}`] && ((!d.role) || (old && (old.rawPosition !== d.role.position
        || old.permissions.bitfield !== BigInt(d.role.permissions) || old.name !== d.role.name
        || old.color !== d.role.color || old.hoist !== d.role.hoist || old.mentionable !== d.role.mentionable)))) {
        this.store.run('UPDATE grants SET valid=0,at=? WHERE guild=? AND role=? AND at<=?', now, guild, role, now);
      }
    }
    for (const event of observationFor(server.guild, packet, settings)) {
      observe(this.store, guild, `${this.shardSession.get(shard) ?? shard}:${packet.s}:${event.type}:${event.target}`, now, event);
    }
  }

  tick() {
    for (const guild of this.client.guilds.cache.values()) {
      if (!guild.available || !this.client.isReady()) continue;
      const server = this.server(guild);
      const settings = this.store.settings(guild.id);
      void this.register(guild);
      if (!this.polling.has(guild.id) && settings.mode !== 'off') {
        this.polling.add(guild.id);
        void this.reconcile(server, settings).finally(() => this.polling.delete(guild.id));
      }
      if (!this.working.has(guild.id)) {
        this.working.add(guild.id);
        void this.work(server, settings).catch(error => this.safe(guild.id, 'очередь', error))
          .finally(() => this.working.delete(guild.id));
      }
    }
    const now = Date.now();
    this.store.run('DELETE FROM confirmation WHERE expires<=?', now);
  }

  async reconcile(server, settings) {
    const guild = server.guild.id;
    let failure;
    try {
      const cursor = this.store.get('SELECT cursor FROM control WHERE guild=?', guild)?.cursor;
      let after = this.backfill.get(guild) ?? auditStart(settings, cursor);
      this.backfill.delete(guild);
      for (let page = 0; page < 5; page++) {
        const entries = (await server.audit({ after, limit: '100' }))
          .sort((a, b) => BigInt(a.id) > BigInt(b.id) ? 1 : -1);
        if (!entries.length) break;
        for (const entry of entries) await this.enqueueAudit(server, entry);
        const last = entries.at(-1).id;
        if (BigInt(last) <= BigInt(after)) break;
        after = last;
        if (!cursor || BigInt(last) > BigInt(cursor)) {
          this.store.run(`INSERT INTO control VALUES (?,?) ON CONFLICT(guild) DO UPDATE SET cursor=excluded.cursor`, guild, last);
        }
        if (entries.length < 100) break;
        if (page === 4) this.backfill.set(guild, last);
      }
    } catch (error) {
      failure = error;
      this.safe(guild, 'чтение Audit Log', error, false);
    }
    try {
      // An inaccessible audit log is itself a reason to show unresolved events.
      if (!this.backfill.has(guild) || failure) closeObservations(this.store, guild);
    } catch (error) {
      this.safe(guild, 'сопоставление Audit Log', error);
    }
  }

  async work(server, settings) {
    const guild = server.guild.id;
    const rows = this.store.all(`SELECT * FROM quarantine WHERE guild=? AND due<=?
      AND (phase='releasing' OR (? AND phase IN ('queued','applying'))) ORDER BY id LIMIT 8`,
    guild, Date.now(), Number(settings.mode === 'active')).map(decoded);
    for (const row of rows) {
      const latest = this.store.getQuarantine(guild, row.member);
      if (!latest || latest.revision !== row.revision) continue;
      const current = this.store.settings(guild);
      try {
        if (row.phase === 'releasing') {
          if (!isManager(current, server.guild.ownerId, row.data.releasePlan.operator)) {
            this.store.saveQuarantine(row, 'release-partial');
            this.store.log(guild, {
              title: 'Снятие карантина приостановлено', tone: 'alert',
              description: 'Доступ оператора отозван. Снятие должен подтвердить действующий администратор.',
              fields: [field('Участник', userRef(row.member))], footer: `Карантин №${row.id}`,
            }, true);
            continue;
          }
          await releaseQuarantine(this.store, server, row);
        } else if (current.mode === 'active') {
          await applyQuarantine(this.store, server, row, current);
        }
      } catch (error) {
        if (error.code === 'ANTICRASH_PAUSED') continue;
        this.safe(guild, `карантин #${row.id}, повтор после сбоя`, error);
        this.store.saveQuarantine(row, row.phase, Date.now() + 15_000);
      }
    }
    await this.deliver(server, this.store.settings(guild));
  }

  async deliver(server, settings) {
    if (!settings.log) return;
    const guild = server.guild.id;
    const pending = this.store.all(`SELECT * FROM log WHERE guild=? AND status='queued' AND due<=?
      ORDER BY urgent DESC,id LIMIT 8`, guild, Date.now());
    for (const row of pending) {
      try {
        await server.send(settings, row);
        this.store.run(`UPDATE log SET status='sent',error=NULL WHERE id=?`, row.id);
      } catch (error) {
        const delay = Math.min(300_000, (2 ** Math.min(9, row.attempts)) * 5000);
        this.store.run(`UPDATE log SET attempts=attempts+1,due=?,error=? WHERE id=?`,
          Date.now() + delay, describe(error), row.id);
      }
    }
  }
}

export async function startAntiCrash(token, signal) {
  if (signal?.aborted) return;
  const path = process.env.ANTICRASH_DB_PATH || join(process.env.DATA_DIR || './data', 'anticrash.sqlite');
  let store;
  try {
    store = new Store(path);
  } catch (error) {
    throw new Error(`SQLite ${path === ':memory:' ? path : resolve(path)}: ${describe(error)}`, { cause: error });
  }
  console.log(`Антикраш: SQLite открыта (${path === ':memory:' ? path : resolve(path)}).`);
  const client = new Client({ intents: [I.Guilds, I.GuildModeration, I.GuildMembers, I.GuildVoiceStates, I.GuildWebhooks] });
  const guard = new AntiCrash(client, store);
  if (signal?.aborted) return;
  signal?.addEventListener('abort', () => guard.stop(), { once: true });
  guard.start();
  while (!signal?.aborted) {
    try {
      await client.login(token);
      return guard;
    } catch (error) {
      client.destroy();
      if (signal?.aborted) return;
      console.error(`Антикраш: подключение к Gateway не удалось. Проверь режим Server Members Intent и токен. ${describe(error)}`);
      await sleep(30_000, undefined, { signal }).catch(error => {
        if (error.name !== 'AbortError') throw error;
      });
    }
  }
}
