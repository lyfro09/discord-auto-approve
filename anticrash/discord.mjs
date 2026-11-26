import { AuditLogEvent as A, ChannelType as C, PermissionFlagsBits as P, Routes } from 'discord.js';
import { bit, danger, discordTime, guildSettingsKeys, isId, snowflakeAt } from './policy.mjs';

const overwriteActions = [A.ChannelOverwriteCreate, A.ChannelOverwriteUpdate, A.ChannelOverwriteDelete];
const channelTypes = new Set([C.GuildText, C.GuildVoice, C.GuildCategory, C.GuildAnnouncement,
  C.GuildStageVoice, C.GuildForum, C.GuildMedia]);
const logTypes = new Set([C.GuildText, C.GuildAnnouncement]);

export function normalizeAudit(raw, roles = []) {
  const target = raw.target_id ?? raw.options?.channel_id ?? null;
  return {
    id: raw.id, at: discordTime(raw.id), action: raw.action_type, actor: raw.user_id ?? null,
    target, reason: raw.reason ?? null, options: { ...raw.options, roleIds: roles },
    changes: (raw.changes ?? []).map(change => ({ key: change.key, old: change.old_value, new: change.new_value })),
  };
}

export function observationFor(guild, packet, settings) {
  const { d, t } = packet;
  const result = [];
  const add = (type, target, actions, extra = {}) => {
    if (isId(target)) result.push({ type, target, actions, ...extra });
  };

  if (['CHANNEL_CREATE', 'CHANNEL_UPDATE', 'CHANNEL_DELETE'].includes(t)) {
    const kind = d.type === C.GuildCategory ? 'category' : 'channel';
    const old = guild.channels.cache.get(d.id);
    if (t === 'CHANNEL_CREATE') add(`${kind}-create`, d.id, [A.ChannelCreate]);
    if (t === 'CHANNEL_DELETE') add(`${kind}-delete`, d.id, [A.ChannelDelete]);
    if (t === 'CHANNEL_UPDATE' && old) {
      const before = new Map([...(old.permissionOverwrites?.cache.values() ?? [])].map(item => [item.id, item]));
      const after = new Map(d.permission_overwrites?.map(item => [item.id, item]) ?? []);
      let changed = false;
      let relevant = false;
      let everyone = false;
      for (const id of new Set([...before.keys(), ...after.keys()])) {
        const diff = (bit(before.get(id)?.allow?.bitfield) ^ bit(after.get(id)?.allow))
          | (bit(before.get(id)?.deny?.bitfield) ^ bit(after.get(id)?.deny));
        if (!diff) continue;
        changed = true;
        if (id === guild.id) everyone = true;
        if (diff & danger) relevant = true;
      }
      const actions = [A.ChannelUpdate, A.ChannelPositionUpdate, ...overwriteActions];
      if (everyone) add('everyone-permissions', d.id, actions);
      if (relevant) add('channel-permissions', d.id, actions);
      if (changed || old.name !== d.name || old.parentId !== (d.parent_id ?? null)
        || old.rawPosition !== d.position || (old.topic ?? null) !== (d.topic ?? null)) {
        add(`${kind}-update`, d.id, actions);
      }
    }
  }

  if (t === 'GUILD_ROLE_CREATE') add('role-create', d.role.id, [A.RoleCreate]);
  if (t === 'GUILD_ROLE_DELETE') add('role-delete', d.role_id, [A.RoleDelete]);
  if (t === 'GUILD_ROLE_UPDATE') {
    const old = guild.roles.cache.get(d.role.id);
    if (old) {
      const diff = old.permissions.bitfield ^ bit(d.role.permissions);
      if (diff & danger) add('role-permissions', d.role.id, [A.RoleUpdate], { keys: ['permissions'] });
      if (diff && d.role.id === guild.id) add('everyone-permissions', d.role.id, [A.RoleUpdate], { keys: ['permissions'] });
      if (old.rawPosition !== d.role.position) {
        add('role-hierarchy', d.role.id, [A.RoleUpdate, A.RolePositionUpdate],
          { alternateTarget: guild.id, onlyIfAmbiguous: true });
      }
      if (diff || old.name !== d.role.name || old.color !== d.role.color
        || old.hoist !== d.role.hoist || old.mentionable !== d.role.mentionable) {
        add('role-update', d.role.id, [A.RoleUpdate]);
      }
    }
  }

  if (t === 'GUILD_MEMBER_ADD' && d.user.bot) add('bot-add', d.user.id, [A.BotAdd]);
  if (t === 'GUILD_MEMBER_REMOVE') add('kick', d.user.id, [A.MemberKick, A.MemberBanAdd], { onlyIfAmbiguous: true });
  if (t === 'GUILD_BAN_ADD') add('ban', d.user.id, [A.MemberBanAdd]);
  if (t === 'GUILD_MEMBER_UPDATE') {
    const old = guild.members.cache.get(d.user.id);
    if (old) {
      const added = d.roles.filter(id => !old.roles.cache.has(id));
      const removed = [...old.roles.cache.keys()].filter(id => id !== guild.id && !d.roles.includes(id));
      if (added.length) add('role-add', d.user.id, [A.MemberRoleUpdate], { keys: ['$add'] });
      if (removed.length) add('role-remove', d.user.id, [A.MemberRoleUpdate], { keys: ['$remove'] });
      if (added.some(id => bit(guild.roles.cache.get(id)?.permissions.bitfield) & danger)) {
        add('dangerous-role', d.user.id, [A.MemberRoleUpdate], { keys: ['$add'] });
      }
      if (added.some(id => settings.trust[`role:${id}`])) {
        add('trusted-role-grant', d.user.id, [A.MemberRoleUpdate], { keys: ['$add'] });
      }
      if (removed.some(id => settings.trust[`role:${id}`])) {
        add('trusted-role-revoke', d.user.id, [A.MemberRoleUpdate], { keys: ['$remove'] });
      }
      const until = Date.parse(d.communication_disabled_until);
      if (until > Date.now() && old.communicationDisabledUntilTimestamp !== until) {
        add('timeout', d.user.id, [A.MemberUpdate], { keys: ['communication_disabled_until'] });
      }
    }
  }
  if (t === 'GUILD_UPDATE') {
    const fields = {
      owner_id: guild.ownerId, verification_level: guild.verificationLevel, name: guild.name,
      explicit_content_filter: guild.explicitContentFilter, mfa_level: guild.mfaLevel,
      system_channel_id: guild.systemChannelId, preferred_locale: guild.preferredLocale,
      rules_channel_id: guild.rulesChannelId, public_updates_channel_id: guild.publicUpdatesChannelId,
      afk_channel_id: guild.afkChannelId, afk_timeout: guild.afkTimeout, icon_hash: guild.icon,
    };
    if (Object.entries(fields).some(([key, value]) => guildSettingsKeys.has(key) && key in d
      && (d[key] ?? null) !== (value ?? null))) add('guild-settings', guild.id, [A.GuildUpdate]);
  }
  if (t === 'WEBHOOKS_UPDATE') add('webhook-update', d.channel_id,
    [A.WebhookCreate, A.WebhookUpdate, A.WebhookDelete], { webhookChannel: true });
  return result;
}

const required = [P.ViewAuditLog, P.ManageRoles];
const knownAbsent = error => error.status === 404 && [10007, 10003, 10011].includes(error.code);
const channelReady = (channel, me) => !!channel && logTypes.has(channel.type)
  && channel.permissionsFor(me).has([P.ViewChannel, P.SendMessages]);

export class DiscordServer {
  constructor(guild, store) {
    this.guild = guild;
    this.store = store;
    this.rest = guild.client.rest;
    this.bot = guild.client.user.id;
    this.roleHistory = new Map();
    this.channelHistory = new Map();
  }

  async audit(query) {
    const response = await this.rest.get(Routes.guildAuditLog(this.guild.id), { query: new URLSearchParams(query) });
    const webhookChannels = new Map((response.webhooks ?? []).map(webhook => [webhook.id, webhook.channel_id]));
    return response.audit_log_entries.map(raw => {
      const entry = normalizeAudit(raw);
      const channel = webhookChannels.get(raw.target_id);
      if (channel) entry.options.webhook_channel_id = channel;
      return entry;
    });
  }

  facts(raw) {
    const { guild } = this;
    if (raw.t === 'GUILD_ROLE_DELETE' || raw.t === 'GUILD_ROLE_UPDATE') {
      const id = raw.d.role_id ?? raw.d.role.id;
      const prior = guild.roles.cache.get(id);
      if (prior) this.roleHistory.set(id, prior.permissions.bitfield);
    }
    if (raw.t === 'CHANNEL_DELETE') this.channelHistory.set(raw.d.id, raw.d.type);
    if (this.roleHistory.size > 2000) this.roleHistory.delete(this.roleHistory.keys().next().value);
    if (this.channelHistory.size > 2000) this.channelHistory.delete(this.channelHistory.keys().next().value);
  }

  async member(id, force = false) {
    if (!isId(id) || id === this.guild.id) return null;
    try {
      return await this.guild.members.fetch({ user: id, force });
    } catch (error) {
      if (knownAbsent(error)) return null;
      throw error;
    }
  }

  async identity(entry, settings) {
    const { guild } = this;
    const hasRoleTrust = Object.keys(settings.trust).some(key => key.startsWith('role:'));
    const toFact = member => member && { joined: member.joinedTimestamp, roles: new Set(member.roles.cache.keys()) };
    const [actor, target] = await Promise.all([
      hasRoleTrust && entry.actor ? this.member(entry.actor).catch(() => 'unknown') : null,
      hasRoleTrust && entry.action === A.MemberRoleUpdate ? this.member(entry.target).catch(() => null) : null,
    ]);
    return {
      owner: guild.ownerId, bot: this.bot, actor: actor === 'unknown' ? null : toFact(actor), target: toFact(target),
      actorUnknown: actor === 'unknown',
      channelType: id => guild.channels.cache.get(id)?.type ?? this.channelHistory.get(id),
      rolePermissions: id => guild.roles.cache.get(id)?.permissions.bitfield ?? this.roleHistory.get(id) ?? 0n,
    };
  }

  memberState(member) {
    if (!member) return null;
    return {
      roles: new Set(member.roles.cache.keys()), permissions: String(member.permissions.bitfield),
      manageable: member.manageable, owner: member.id === this.guild.ownerId, self: member.id === this.bot,
      voice: member.voice.channelId,
    };
  }

  async currentMember(member) {
    return this.memberState(await this.member(member, true));
  }

  roleState(role, me) {
    return {
      permissions: String(role.permissions.bitfield), position: role.rawPosition,
      managed: role.managed, name: role.name,
      editable: !role.managed && role.id !== this.guild.id && me.permissions.has(P.ManageRoles)
        && me.roles.highest.comparePositionTo(role) > 0,
    };
  }

  channelState(channel, member, me, id) {
    const overwrite = channel.permissionOverwrites.cache.get(id);
    const own = channel.permissionsFor(me);
    return {
      id: channel.id, voice: channel.isVoiceBased(), permissions: member ? String(channel.permissionsFor(member).bitfield) : '0',
      editable: own.has([P.ViewChannel, P.ManageRoles]), canConnect: own.has(P.Connect), writable: String(own.bitfield),
      overwrite: overwrite ? { allow: String(overwrite.allow.bitfield), deny: String(overwrite.deny.bitfield) } : null,
    };
  }

  async state(id) {
    const [roles, channels, member, me] = await Promise.all([
      this.guild.roles.fetch(), this.guild.channels.fetch(),
      this.member(id, true), this.guild.members.fetchMe({ force: true }),
    ]);
    return {
      member: this.memberState(member),
      roles: new Map([...roles.values()].map(role => [role.id, this.roleState(role, me)])),
      channels: new Map([...channels.values()].filter(ch => ch && channelTypes.has(ch.type))
        .map(ch => [ch.id, this.channelState(ch, member, me, id)])),
    };
  }

  async inspect(id, step) {
    const overwrites = step.kind === 'overwrite';
    const [member, me, object] = await Promise.all([
      this.member(id, true),
      this.guild.members.fetchMe(),
      (overwrites ? this.guild.channels.fetch(step.id, { force: true }) : this.guild.roles.fetch(step.id, { force: true }))
        .catch(error => { if (knownAbsent(error)) return null; throw error; }),
    ]);
    return {
      member: this.memberState(member),
      roles: new Map(!overwrites && object ? [[step.id, this.roleState(object, me)]] : []),
      channels: new Map(overwrites && object ? [[step.id, this.channelState(object, member, me, id)]] : []),
    };
  }

  async role(member, role, add, reason) {
    const route = Routes.guildMemberRole(this.guild.id, member, role);
    if (add) await this.rest.put(route, { reason });
    else await this.rest.delete(route, { reason });
  }

  async overwrite(channel, member, value, reason) {
    const route = Routes.channelPermission(channel, member);
    if (value) await this.rest.put(route, { body: { ...value, type: 1 }, reason });
    else await this.rest.delete(route, { reason });
  }

  async disconnect(member, voice, reason) {
    const channel = await this.guild.channels.fetch(voice);
    const me = await this.guild.members.fetchMe();
    if (!channel?.permissionsFor(me).has([P.ViewChannel, P.Connect, P.MoveMembers])) {
      throw Object.assign(new Error('нужны View Channel, Connect и Move Members для отключения'), { status: 403 });
    }
    await this.rest.patch(Routes.guildMember(this.guild.id, member), { body: { channel_id: null }, reason });
  }

  async verifyOperation(marker, row, step, value) {
    const type = step.kind === 'overwrite' ? undefined : A.MemberRoleUpdate;
    const query = { limit: '100' };
    if (type) query.action_type = String(type);
    query.user_id = this.bot;
    const target = type ? row.member : step.id;
    const matches = entry => entry.reason === marker && entry.actor === this.bot && entry.target === target
      && (type ? entry.action === type
        && entry.changes.some(item => item.key === (value ? '$add' : '$remove') && item.new?.some(role => role.id === step.id))
        : overwriteActions.includes(entry.action) && entry.options.id === row.member);
    const stored = this.store.all('SELECT data FROM audit WHERE guild=? AND target=? AND actor=?',
      row.guild, target, this.bot);
    if (stored.some(record => matches(JSON.parse(record.data)))) return true;
    return (await this.audit(query)).some(matches);
  }

  async check(settings) {
    const { guild } = this;
    const me = await guild.members.fetchMe({ force: true });
    const [roles, channels] = await Promise.all([guild.roles.fetch(), guild.channels.fetch()]);
    const errors = required.filter(permission => !me.permissions.has(permission))
      .map(permission => `Боту нужно право ${Object.keys(P).find(key => P[key] === permission)}.`);
    if (me.permissions.has(P.ViewAuditLog)) {
      try { await this.audit({ limit: '1' }); }
      catch (error) { errors.push(`Audit Log недоступен: ${error.message.slice(0, 160)}`); }
    }
    const role = roles.get(settings.quarantine);
    if (!role) errors.push('Выбери роль карантина.');
    else if (!this.roleState(role, me).editable || (role.permissions.bitfield & danger)) {
      errors.push('Роль карантина должна находиться ниже роли бота и иметь только безопасные права. Управляемые роли запрещены.');
    }
    if (!channelReady(channels.get(settings.log), me)) errors.push('Выбери канал логов с View Channel и Send Messages у бота.');
    if (settings.support && (!channelReady(channels.get(settings.support), me)
      || !channels.get(settings.support).permissionsFor(me).has(P.ReadMessageHistory))) {
      errors.push('Канал связи должен быть текстовым и доступным боту для чтения и отправки сообщений.');
    }
    if (settings.support && settings.support === settings.log) errors.push('Каналы логов и связи должны быть разными.');
    if (settings.mention) {
      const mention = roles.get(settings.mention);
      if (!mention || mention.id === guild.id || mention.id === settings.quarantine
        || (!mention.mentionable && !channels.get(settings.log)?.permissionsFor(me).has(P.MentionEveryone))) {
        errors.push('Выбери отдельную доступную для упоминания роль оповещений.');
      }
    }
    const blocked = [...channels.values()].filter(channel => channel && channelTypes.has(channel.type)
      && (!channel.permissionsFor(me).has([P.ViewChannel, P.ManageRoles])
        || (channel.isVoiceBased() && !channel.permissionsFor(me).has([P.Connect, P.MoveMembers]))));
    if (blocked.length) errors.push(`Не хватает прав в каналах: ${blocked.map(channel => channel.id).join(', ')}.`);
    if ((roles.get(guild.id).permissions.bitfield & danger) !== 0n) {
      errors.push('У @everyone есть опасные разрешения. Убери их, прежде чем включать защиту.');
    }
    return errors;
  }

  async send(settings, message, urgent) {
    const channel = await this.guild.channels.fetch(settings.log);
    if (!channel?.isSendable()) throw new Error('Канал логов недоступен.');
    const mention = urgent && settings.mention;
    await channel.send({
      content: (mention ? `<@&${mention}>\n` : '') + message,
      allowedMentions: { parse: [], roles: mention ? [mention] : [] },
    });
  }
}

export function auditStart(settings, cursor) {
  // Replay a short overlap so entries written late with an earlier snowflake are picked up.
  return snowflakeAt(Math.max(settings.since - 1, cursor ? discordTime(cursor) - 35_000 : 0));
}
