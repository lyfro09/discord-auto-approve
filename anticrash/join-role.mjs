import { randomUUID } from 'node:crypto';
import { AuditLogEvent as A } from 'discord.js';
import { dangerous, isId } from './policy.mjs';

class AutomaticRole {
  constructor(store, guild, role, { table, label, marker }) {
    this.store = store;
    this.guild = guild;
    this.role = role;
    this.table = table;
    this.label = label;
    this.marker = marker;
    this.enabled = isId(guild) && isId(role);
    this.status = null;
  }

  queue(member, joined) {
    this.store.run(`INSERT INTO ${this.table} (guild,member,joined,due) VALUES (?,?,?,?)
      ON CONFLICT(guild,member) DO UPDATE SET joined=excluded.joined,due=excluded.due,attempts=0,done=0
      WHERE excluded.joined>${this.table}.joined`, this.guild, member, joined, Date.now());
  }

  screeningFinished(member) {
    if (this.enabled && member.guild.id === this.guild) {
      this.store.run(`UPDATE ${this.table} SET due=0 WHERE guild=? AND member=? AND (joined=? OR joined=0) AND done=0`,
        this.guild, member.id, member.joinedTimestamp ?? -1);
    }
  }

  finish(row) {
    this.store.run(`UPDATE ${this.table} SET done=1 WHERE guild=? AND member=? AND joined=?`,
      row.guild, row.member, row.joined);
  }

  defer(row, delay, failed = false) {
    this.store.run(`UPDATE ${this.table} SET due=?,attempts=attempts+? WHERE guild=? AND member=? AND joined=? AND done=0`,
      Date.now() + delay, Number(failed), row.guild, row.member, row.joined);
  }

  matches() { return true; }

  async availableRole(server, settings) {
    if (this.role === settings.quarantine) throw new Error('Выбрана роль карантина.');
    await server.guild.members.fetchMe();
    const role = await server.guild.roles.fetch(this.role, { force: true });
    if (!role) throw new Error('Выбранная роль не найдена на сервере.');
    if (dangerous(role.permissions.bitfield)) throw new Error('У выбранной роли есть права модерации или управления.');
    if (!role.editable) throw new Error('Проверь Manage Roles и поставь роль бота выше назначаемой роли.');
    return role;
  }

  async check(server, settings) {
    try {
      const role = await this.availableRole(server, settings);
      if (this.status !== role.name) console.log(`${this.label}: роль «${role.name}» доступна.`);
      this.status = role.name;
      return role;
    } catch (error) {
      if (this.status !== error.message) console.error(`${this.label}: ${error.message}`);
      this.status = error.message;
      return null;
    }
  }

  async work(server, settings) {
    if (!this.enabled || server.guild.id !== this.guild) return;
    const rows = this.store.all(`SELECT * FROM ${this.table} WHERE guild=? AND done=0 AND due<=?
      ORDER BY due LIMIT 15`, this.guild, Date.now());
    if (!rows.length && this.status !== null) return;
    const role = await this.check(server, settings);
    if (!role) {
      for (const row of rows) this.defer(row, 60_000);
      return;
    }
    for (const row of rows) {
      try {
        const member = await server.member(row.member, true);
        if (!member || (row.joined && member.joinedTimestamp !== row.joined) || member.roles.cache.has(role.id) || !this.matches(member)) {
          this.finish(row);
          continue;
        }
        const pending = this.store.get(`SELECT joined,done FROM ${this.table} WHERE guild=? AND member=?`, row.guild, row.member);
        if (pending?.joined !== row.joined || pending.done) continue;
        const protectedMember = this.store.getQuarantine(row.guild, row.member);
        if (member.pending || protectedMember) {
          this.defer(row, 60_000);
          continue;
        }
        const reason = `${this.marker}:${randomUUID()}`;
        // The anti-crash exempts only this bot, member, role and audit operation.
        this.store.run('INSERT INTO expected VALUES (?,?,?,?,?,?,?)',
          row.guild, reason, A.MemberRoleUpdate, row.member, '$add', role.id, Date.now());
        await server.role(row.member, role.id, true, reason);
        this.finish(row);
      } catch (error) {
        if (row.attempts === 0) console.error(`${this.label}: ${error.message}`);
        this.defer(row, Math.min(300_000, 5_000 * 2 ** Math.min(6, row.attempts)), true);
      }
    }
  }
}

export class JoinRole extends AutomaticRole {
  constructor(store, guild, role) {
    super(store, guild, role, { table: 'join_role_queue', label: 'Автовыдача при входе', marker: 'auto-join-role' });
  }

  enqueue(member) {
    if (!this.enabled || member.guild.id !== this.guild || !Number.isFinite(member.joinedTimestamp)) return;
    this.queue(member.id, member.joinedTimestamp);
  }

  async work(server, settings) {
    await super.work(server, settings);
    if (!this.enabled || server.guild.id !== this.guild) return;
    this.store.run('DELETE FROM join_role_queue WHERE guild=? AND done=1 AND joined<?',
      this.guild, Date.now() - 7 * 86_400_000);
  }
}

export class TagRole extends AutomaticRole {
  constructor(store, guild, role) {
    super(store, guild, role, { table: 'tag_role_queue', label: 'Автовыдача за тег', marker: 'auto-tag-role' });
  }

  observe({ t, d }) {
    if (!this.enabled || d?.guild_id !== this.guild || !isId(d.user?.id) || d.user.bot) return;
    const { user } = d;
    if (t === 'GUILD_MEMBER_REMOVE') {
      this.store.run('DELETE FROM tag_role_queue WHERE guild=? AND member=?', this.guild, user.id);
      return;
    }
    if (!['GUILD_MEMBER_ADD', 'GUILD_MEMBER_UPDATE'].includes(t) || !Object.hasOwn(user, 'primary_guild')) return;
    const identity = user.primary_guild;
    if (identity?.identity_enabled !== true || identity.identity_guild_id !== this.guild || !identity.tag) {
      // Cancel any outstanding grant; an already assigned role stays on the member.
      this.store.run('DELETE FROM tag_role_queue WHERE guild=? AND member=?', this.guild, user.id);
      return;
    }
    if (!d.roles?.includes(this.role)) this.queue(user.id, Date.parse(d.joined_at) || 0);
  }

  matches(member) {
    const identity = member.user?.primaryGuild;
    return !member.user?.bot && identity?.identityEnabled === true
      && identity.identityGuildId === this.guild && !!identity.tag;
  }
}
