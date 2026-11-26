import { randomUUID } from 'node:crypto';
import { AuditLogEvent as A } from 'discord.js';
import { dangerous, isId } from './policy.mjs';

export class JoinRole {
  constructor(store, guild, role) {
    this.store = store;
    this.guild = guild;
    this.role = role;
    this.enabled = isId(guild) && isId(role);
    this.status = null;
  }

  enqueue(member) {
    if (!this.enabled || member.guild.id !== this.guild || !Number.isFinite(member.joinedTimestamp)) return;
    this.store.run(`INSERT INTO join_role_queue (guild,member,joined,due) VALUES (?,?,?,?)
      ON CONFLICT(guild,member) DO UPDATE SET joined=excluded.joined,due=excluded.due,attempts=0,done=0
      WHERE excluded.joined>join_role_queue.joined`, this.guild, member.id, member.joinedTimestamp, Date.now());
  }

  screeningFinished(member) {
    if (this.enabled && member.guild.id === this.guild) {
      this.store.run('UPDATE join_role_queue SET due=0 WHERE guild=? AND member=? AND joined=? AND done=0',
        this.guild, member.id, member.joinedTimestamp ?? -1);
    }
  }

  finish(row) {
    this.store.run('UPDATE join_role_queue SET done=1 WHERE guild=? AND member=? AND joined=?',
      row.guild, row.member, row.joined);
  }

  defer(row, delay, failed = false) {
    this.store.run('UPDATE join_role_queue SET due=?,attempts=attempts+? WHERE guild=? AND member=? AND joined=? AND done=0',
      Date.now() + delay, Number(failed), row.guild, row.member, row.joined);
  }

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
      if (this.status !== role.name) console.log(`Автовыдача при входе: роль «${role.name}» доступна.`);
      this.status = role.name;
      return role;
    } catch (error) {
      if (this.status !== error.message) console.error(`Автовыдача при входе: ${error.message}`);
      this.status = error.message;
      return null;
    }
  }

  async work(server, settings) {
    if (!this.enabled || server.guild.id !== this.guild) return;
    const rows = this.store.all(`SELECT * FROM join_role_queue WHERE guild=? AND done=0 AND due<=?
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
        if (!member || member.joinedTimestamp !== row.joined || member.roles.cache.has(role.id)) {
          this.finish(row);
          continue;
        }
        const pending = this.store.get('SELECT joined,done FROM join_role_queue WHERE guild=? AND member=?', row.guild, row.member);
        if (pending?.joined !== row.joined || pending.done) continue;
        const protectedMember = this.store.getQuarantine(row.guild, row.member);
        if (member.pending || protectedMember) {
          this.defer(row, 60_000);
          continue;
        }
        const reason = `auto-join-role:${randomUUID()}`;
        // The anti-crash exempts only this bot, member, role and audit operation.
        this.store.run('INSERT INTO expected VALUES (?,?,?,?,?,?,?)',
          row.guild, reason, A.MemberRoleUpdate, row.member, '$add', role.id, Date.now());
        await server.role(row.member, role.id, true, reason);
        this.finish(row);
      } catch (error) {
        if (row.attempts === 0) console.error(`Автовыдача при входе: ${error.message}`);
        this.defer(row, Math.min(300_000, 5_000 * 2 ** Math.min(6, row.attempts)), true);
      }
    }
    // The current join session is identified by its own timestamp even after cleanup.
    this.store.run('DELETE FROM join_role_queue WHERE guild=? AND done=1 AND joined<?',
      this.guild, Date.now() - 7 * 86_400_000);
  }
}
