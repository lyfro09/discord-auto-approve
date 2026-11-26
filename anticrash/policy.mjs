import { AuditLogEvent as A, PermissionsBitField, PermissionFlagsBits as P } from 'discord.js';

export const danger = P.Administrator | P.ManageGuild | P.ManageRoles | P.ManageChannels
  | P.ManageWebhooks | P.BanMembers | P.KickMembers | P.ModerateMembers
  | P.ManageMessages | P.ManageThreads | P.MentionEveryone | P.MoveMembers;
export const bit = value => BigInt(value ?? 0);
export const dangerous = value => (bit(value) & danger) !== 0n;
export const permissionNames = value => new PermissionsBitField(bit(value) & danger).toArray();
export const isId = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value);
export const discordTime = id => Number((BigInt(id) >> 22n) + 1420070400000n);
export const snowflakeAt = time => (BigInt(Math.max(time - 1420070400000, 0)) << 22n).toString();

const limits = {
  'channel-create': 5, 'channel-update': 5, 'channel-delete': 3,
  'category-create': 3, 'category-update': 3, 'category-delete': 2,
  'role-create': 5, 'role-update': 5, 'role-delete': 3,
  'role-permissions': 1, 'channel-permissions': 1, 'everyone-permissions': 1,
  'role-add': 5, 'role-remove': 5, 'dangerous-role': 1, 'role-hierarchy': 1,
  'trusted-role-grant': 1, 'trusted-role-revoke': 1, 'trusted-role-edit': 1,
  'ban': 4, 'kick': 4, 'timeout': 4, 'bot-add': 1,
  'webhook-create': 2, 'webhook-update': 2, 'webhook-delete': 3, 'guild-settings': 1,
};

export const eventTypes = Object.keys(limits);
export function defaultSettings() {
  return {
    mode: 'off', since: 0, managers: [], managerSince: {}, ownerSince: 0, trust: {}, trustEpoch: {},
    log: null, quarantine: null, support: null, mention: null,
    rules: Object.fromEntries(eventTypes.map(type => [
      type, { enabled: true, limit: limits[type], seconds: 15, global: 0, reaction: 'quarantine' },
    ])),
  };
}

const channelActions = {
  [A.ChannelCreate]: 'create', [A.ChannelUpdate]: 'update', [A.ChannelDelete]: 'delete',
  [A.ChannelPositionUpdate]: 'update',
};
const roleActions = { [A.RoleCreate]: 'create', [A.RoleUpdate]: 'update', [A.RoleDelete]: 'delete' };
const simpleActions = {
  [A.MemberBanAdd]: 'ban', [A.MemberKick]: 'kick', [A.MemberPrune]: 'kick', [A.BotAdd]: 'bot-add',
  [A.WebhookCreate]: 'webhook-create', [A.WebhookUpdate]: 'webhook-update', [A.WebhookDelete]: 'webhook-delete',
};
export const guildSettingsKeys = new Set([
  'owner_id', 'verification_level', 'explicit_content_filter', 'mfa_level', 'default_message_notifications',
  'system_channel_id', 'rules_channel_id', 'public_updates_channel_id', 'safety_alerts_channel_id',
  'vanity_url_code', 'features', 'afk_channel_id', 'name', 'icon_hash', 'discovery_splash_hash',
  'preferred_locale', 'premium_progress_bar_enabled', 'afk_timeout',
]);

function changedDanger(change) {
  return change && dangerous(bit(change.old) ^ bit(change.new));
}

export function classify(guildId, entry, facts) {
  const { action, target, changes, options } = entry;
  const change = key => changes.find(item => item.key === key);
  const hasTrust = role => !!facts.trustRole(role);
  const signals = new Map();
  const add = (type, weight = 1, object = target) => signals.set(type, { type, weight, target: object });
  const channelAction = channelActions[action];
  const roleAction = roleActions[action];

  if (channelAction) {
    const channelType = change('type')?.new ?? change('type')?.old ?? facts.channelType(target);
    add(`${channelType === 4 ? 'category' : 'channel'}-${channelAction}`);
    const overwrites = change('permission_overwrites');
    if (overwrites) {
      const before = new Map((overwrites.old ?? []).map(item => [item.id, item]));
      const after = new Map((overwrites.new ?? []).map(item => [item.id, item]));
      for (const id of new Set([...before.keys(), ...after.keys()])) {
        const left = before.get(id);
        const right = after.get(id);
        if (id === guildId && (bit(left?.allow) !== bit(right?.allow) || bit(left?.deny) !== bit(right?.deny))) {
          add('everyone-permissions');
        }
        if (dangerous((bit(left?.allow) ^ bit(right?.allow)) | (bit(left?.deny) ^ bit(right?.deny)))) {
          add('channel-permissions');
        }
      }
    }
  }
  if ([A.ChannelOverwriteCreate, A.ChannelOverwriteUpdate, A.ChannelOverwriteDelete].includes(action)) {
    const inheritanceUnknown = !change('allow') && !change('deny');
    if (inheritanceUnknown || changedDanger(change('allow')) || changedDanger(change('deny'))) add('channel-permissions');
    if (options.id === guildId) add('everyone-permissions');
  }
  if (roleAction) {
    add(`role-${roleAction}`);
    if (changedDanger(change('permissions'))) add('role-permissions');
    if (target === guildId && change('permissions')) add('everyone-permissions');
    if (change('position') && (dangerous(facts.rolePermissions(target)) || hasTrust(target))) add('role-hierarchy');
    if (hasTrust(target) && roleAction !== 'create') add('trusted-role-edit');
  }
  if (action === A.RolePositionUpdate) {
    const positions = options.roleIds ?? [];
    if (positions.some(id => dangerous(facts.rolePermissions(id)) || hasTrust(id))
      || (target && (dangerous(facts.rolePermissions(target)) || hasTrust(target)))) {
      add('role-hierarchy', 1, target ?? guildId);
    } else if (!positions.length && !target) {
      signals.set('role-hierarchy', { type: 'role-hierarchy', weight: 1, target: guildId, uncertain: true });
    }
    if (positions.some(hasTrust) || hasTrust(target) || (positions.length === 0 && facts.hasTrustedRoles)) {
      add('trusted-role-edit', 1, target ?? guildId);
      if (!positions.length && !target) signals.get('trusted-role-edit').uncertain = true;
    }
  }
  if (action === A.MemberRoleUpdate) {
    const added = (change('$add')?.new ?? []).map(role => role.id).filter(isId);
    const removed = (change('$remove')?.new ?? []).map(role => role.id).filter(isId);
    if (added.length) add('role-add', added.length);
    if (removed.length) add('role-remove', removed.length);
    if (added.some(id => dangerous(facts.rolePermissions(id)))) add('dangerous-role');
    if (added.some(hasTrust)) add('trusted-role-grant');
    if (removed.some(hasTrust)) add('trusted-role-revoke');
  }
  if (action === A.MemberUpdate && Date.parse(change('communication_disabled_until')?.new) > entry.at) add('timeout');
  if (action === A.GuildUpdate && changes.some(item => guildSettingsKeys.has(item.key))) add('guild-settings');
  if (simpleActions[action]) {
    const weight = action === A.MemberPrune ? Math.max(1, Number(options.members_removed) || 1) : 1;
    add(simpleActions[action], weight, target ?? (action === A.MemberPrune ? guildId : null));
  }
  return [...signals.values()];
}

export function activeTrust(settings, key, at) {
  const entry = settings.trust[key];
  return entry && entry.created <= at && (!entry.expires || entry.expires > at) ? entry : null;
}

export function trustFor(settings, actor, actorRoles, type, at) {
  const applicable = entry => entry && (entry.mode === 'immune' || entry.actions.includes(type));
  const individual = [`user:${actor}`, `bot:${actor}`].map(key => activeTrust(settings, key, at)).filter(applicable);
  const roles = [...actorRoles].map(id => activeTrust(settings, `role:${id}`, at)).filter(applicable);
  const matches = individual.length ? individual : roles;
  const thresholds = matches.filter(entry => entry.mode === 'limit').map(entry => entry.limit);
  if (thresholds.length) return { exempt: false, limit: Math.min(...thresholds) };
  return { exempt: matches.length > 0, limit: settings.rules[type].limit };
}

export const isManager = (settings, owner, actor) => actor === owner || settings.managers.includes(actor);

export function canAuthorizeGrant(settings, owner, actor, at) {
  if (!actor) return false;
  return actor === owner ? settings.ownerSince <= at
    : settings.managers.includes(actor) && (settings.managerSince[actor] ?? Number.POSITIVE_INFINITY) <= at;
}
