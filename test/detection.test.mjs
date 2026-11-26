import test from 'node:test';
import assert from 'node:assert/strict';
import { AuditLogEvent as A, PermissionFlagsBits as P } from 'discord.js';
import { commandData, handleCommand } from '../anticrash/commands.mjs';
import { acceptAudit, closeObservations, observe, setGrant } from '../anticrash/detect.mjs';
import { classify, defaultSettings, trustFor } from '../anticrash/policy.mjs';
import { Store } from '../anticrash/store.mjs';

const now = Date.now();
const guild = '101';
const actor = '102';
const owner = '103';
const notify = '104';
const role = '121';

function setup(mode) {
  const store = new Store(':memory:');
  const config = defaultSettings();
  config.mode = mode;
  config.since = now - 60_000;
  store.saveSettings(guild, config);
  return { store, config };
}
const baseIdentity = {
  owner, bot: '105', channelType: () => null, rolePermissions: id => id === role ? P.Administrator : 0n,
  actor: { roles: new Set(), joined: now - 50000 },
};
function audit(id, attributes = {}) {
  return { id: String(id), at: now - 2000, target: String(id + 100),
    actor, action: A.ChannelDelete, options: {}, changes: [], ...attributes };
}
function record(store, id, attributes, identity = baseIdentity) {
  return acceptAudit(store, guild, audit(id, attributes), identity, now);
}

test('новый сервер и off не обрабатывают события; slash-команды валидны', t => {
  const { store } = setup('off');
  t.after(() => store.close());
  assert.equal(store.settings('456').mode, 'off');
  record(store, 201);
  assert.equal(store.get('SELECT COUNT(*) n FROM audit').n, 0);
  assert.equal(commandData.name, 'anticrash');
  assert.ok(commandData.options.some(option => option.name === 'release-confirm'));
});

test('наблюдение и активный режим используют один порог; дубликаты не учитываются', t => {
  for (const mode of ['observe', 'active']) {
    const { store } = setup(mode);
    t.after(() => store.close());
    record(store, 201);
    record(store, 201);
    record(store, 202);
    assert.equal(store.get('SELECT COUNT(*) n FROM incident').n, 0);
    record(store, 203);
    const incident = store.get('SELECT * FROM incident');
    assert.equal(JSON.parse(incident.data).count, 3);
    assert.equal(JSON.parse(incident.data).reaction, mode === 'observe' ? 'would-quarantine' : 'quarantine');
    assert.equal(!!store.getQuarantine(guild, actor), mode === 'active');
    record(store, 204);
    assert.equal(store.get('SELECT COUNT(*) n FROM incident').n, 1);
    assert.equal(store.get('SELECT COUNT(*) n FROM incident_event').n, 2);
  }
});

test('общий порог распределённых действий даёт тревогу, карантин только по личному порогу', t => {
  const { store, config } = setup('active');
  t.after(() => store.close());
  config.rules['channel-delete'].global = 3;
  store.saveSettings(guild, config);
  record(store, 211);
  record(store, 212, { actor: notify });
  record(store, 213, { actor: notify });
  assert.equal(store.get('SELECT scope FROM incident').scope, 'global');
  assert.equal(store.get('SELECT COUNT(*) n FROM quarantine').n, 0);
  record(store, 214, { actor: notify });
  assert.equal(store.getQuarantine(guild, notify).phase, 'queued');
  assert.equal(store.getQuarantine(guild, actor), undefined);
});

test('запаздывающая подтверждённая запись подавляет тревогу Gateway, неоднозначные и отсутствующие записи не наказывают', t => {
  const { store, config } = setup('active');
  t.after(() => store.close());
  config.rules['channel-delete'].limit = 99;
  store.saveSettings(guild, config);
  const at = now - 30_000;
  const signal = target => ({ type: 'channel-delete', target, actions: [A.ChannelDelete] });
  observe(store, guild, 'dup', at, signal('500'));
  observe(store, guild, 'dup', at, signal('500'));
  record(store, 221, { target: '500', at: at + 10_000 });
  observe(store, guild, 'missing', at, signal('501'));
  observe(store, guild, 'ambiguous', at, signal('502'));
  record(store, 222, { target: '502', at });
  record(store, 223, { target: '502', at: at + 500, actor: notify });
  record(store, 224, { target: '503', at, actor: null });
  closeObservations(store, guild, now);
  closeObservations(store, guild, now);
  assert.equal(store.get('SELECT COUNT(*) n FROM incident_event').n, 3);
  assert.equal(store.get('SELECT COUNT(*) n FROM quarantine').n, 0);
  assert.equal(store.get('SELECT COUNT(*) n FROM observations').n, 3);
});

test('индивидуальное правило важнее роли, два ролевых лимита дают меньший порог', () => {
  const config = defaultSettings();
  const entry = { created: now - 1000, expires: null, actions: ['ban'] };
  config.trust['role:121'] = { ...entry, mode: 'limit', limit: 8 };
  config.trust['role:122'] = { ...entry, mode: 'limit', limit: 14 };
  assert.deepEqual(trustFor(config, actor, [role, '122'], 'ban', now), { exempt: false, limit: 8 });
  config.trust[`user:${actor}`] = { ...entry, mode: 'allow' };
  assert.deepEqual(trustFor(config, actor, [role, '122'], 'ban', now), { exempt: true, limit: 4 });
  assert.deepEqual(trustFor(config, actor, [role], 'channel-delete', now), { exempt: false, limit: 3 });
  config.trust[`user:${actor}`].expires = now;
  assert.equal(trustFor(config, actor, [role], 'ban', now).limit, 8);
});

test('доверенная роль требует авторизованной выдачи, редактирование и повторный вход сбрасывают иммунитет', t => {
  const { store, config } = setup('active');
  t.after(() => store.close());
  config.trust[`role:${role}`] = { mode: 'immune', created: now - 50000, actions: [], expires: null };
  config.trustEpoch[role] = now - 50000;
  config.rules['dangerous-role'].reaction = 'log';
  config.rules.ban.limit = 1;
  store.saveSettings(guild, config);
  const membership = { roles: new Set([role]), joined: now - 45000 };
  const grant = { action: A.MemberRoleUpdate, target: notify, changes: [{ key: '$add', new: [{ id: role }] }] };
  record(store, 230, { ...grant, at: now - 40000 }, { ...baseIdentity, target: membership });
  assert.equal(store.get('SELECT valid FROM grants WHERE member=?', notify).valid, 0);
  record(store, 231, { ...grant, actor: owner, at: now - 35000 }, { ...baseIdentity, target: membership });
  assert.equal(store.get('SELECT valid FROM grants WHERE member=?', notify).valid, 1);
  record(store, 232, { action: A.MemberBanAdd, actor: notify, at: now - 30000 }, { ...baseIdentity, actor: membership });
  assert.equal(store.getQuarantine(guild, notify), undefined);
  record(store, 233, { action: A.MemberBanAdd, actor: notify, at: now - 25000 },
    { ...baseIdentity, actor: { ...membership, joined: now - 26000 } });
  assert.ok(store.getQuarantine(guild, notify));
  setGrant(store, guild, actor, role, config.trustEpoch[role], membership.joined, now - 22000, true);
  record(store, 234, { action: A.RoleUpdate, actor: owner, target: role, at: now - 20000 });
  record(store, 235, { action: A.MemberBanAdd, at: now - 10000 }, { ...baseIdentity, actor: membership });
  assert.ok(store.getQuarantine(guild, actor));
});

test('исключаются только операции с точной меткой, субъектом и типом изменения', t => {
  const { store } = setup('observe');
  t.after(() => store.close());
  store.run('INSERT INTO expected VALUES (?,?,?,?,?,?,?)', guild, 'known', -1, '331', 'overwrite', notify, now - 5000);
  const overwrite = { action: A.ChannelOverwriteUpdate, target: '331', reason: 'known',
    options: { id: notify }, changes: [{ key: 'allow', new: String(P.ManageRoles) }] };
  record(store, 241, { ...overwrite, actor: '105' });
  assert.equal(store.get('SELECT COUNT(*) n FROM events').n, 0);
  record(store, 242, { ...overwrite, actor: '105', options: { id: '106' } });
  assert.equal(store.get('SELECT COUNT(*) n FROM events').n, 1);
});

test('классифицируются категории, @everyone, опасная роль, тайм-аут, вебхук и настройки', () => {
  const keys = (attributes) => classify(guild, audit(250, attributes), {
    ...baseIdentity, trustRole: id => id === role, hasTrustedRoles: true,
  }).map(item => item.type);
  assert.deepEqual(keys({ changes: [{ key: 'type', old: 4 }] }), ['category-delete']);
  assert.deepEqual(keys({ action: A.RoleUpdate, target: guild, changes: [{ key: 'permissions', new: String(P.ManageRoles) }] }),
    ['role-update', 'role-permissions', 'everyone-permissions']);
  assert.deepEqual(keys({ action: A.MemberRoleUpdate, changes: [{ key: '$add', new: [{ id: role }] }] }),
    ['role-add', 'dangerous-role', 'trusted-role-grant']);
  assert.deepEqual(keys({ action: A.MemberUpdate, changes: [{ key: 'communication_disabled_until', new: new Date(now + 1000).toISOString() }] }),
    ['timeout']);
  assert.deepEqual(keys({ action: A.WebhookUpdate }), ['webhook-update']);
  assert.deepEqual(keys({ action: A.GuildUpdate, changes: [{ key: 'verification_level', old: 2, new: 0 }] }), ['guild-settings']);
});

test('управление отделено от доверия, мастер оставляет наблюдение при блокере', async t => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const server = { guild: { ownerId: owner }, check: settings => settings.support ? ['Нет доступа к связи'] : [] };
  const responses = [];
  const setupInput = new Map([['log', '401'], ['quarantine', '402'], ['support', '403']]);
  const interaction = {
    guildId: guild, user: { id: actor }, deferReply: async () => {},
    editReply: async message => responses.push(message),
    options: {
      getSubcommand: () => 'setup',
      getChannel: key => setupInput.has(key) ? { id: setupInput.get(key) } : null,
      getRole: key => setupInput.has(key) ? { id: setupInput.get(key) } : null,
    },
  };
  await handleCommand(store, server, interaction);
  assert.match(responses.at(-1).embeds[0].description, /Доступ есть у владельца/);
  interaction.user.id = owner;
  await handleCommand(store, server, interaction);
  assert.equal(store.settings(guild).mode, 'observe');
  assert.match(responses.at(-1).embeds[0].description, /Нет доступа к связи/);
});
