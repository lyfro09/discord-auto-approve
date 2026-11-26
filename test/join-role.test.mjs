import test from 'node:test';
import assert from 'node:assert/strict';
import { AuditLogEvent as A, PermissionFlagsBits as P } from 'discord.js';
import { acceptAudit } from '../anticrash/detect.mjs';
import { JoinRole } from '../anticrash/join-role.mjs';
import { Store } from '../anticrash/store.mjs';

const ids = { guild: '100', role: '101', member: '102', bot: '103' };

function fixture(t) {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const role = { id: ids.role, name: 'Участник', editable: true, permissions: { bitfield: 0n } };
  const guild = { id: ids.guild, members: { fetchMe: async () => ({}) }, roles: { fetch: async () => role } };
  const member = { guild, id: ids.member, joinedTimestamp: Date.now(), pending: false, roles: { cache: new Map() } };
  const grants = [];
  const server = { guild, member: async () => member, role: async (...args) => grants.push(args) };
  return { store, role, member, grants, server, service: new JoinRole(store, ids.guild, ids.role) };
}

test('роль выдаётся один раз за вход, а антикраш распознаёт именно эту выдачу', async t => {
  const { store, member, grants, server, service } = fixture(t);
  const config = store.settings(ids.guild);
  config.mode = 'active';
  config.rules['role-add'].limit = 1;
  store.saveSettings(ids.guild, config);

  service.enqueue({ ...member, guild: { id: '200' } });
  service.enqueue(member);
  service.enqueue(member);
  await service.work(server, config);
  service.enqueue(member);
  await service.work(server, config);
  assert.equal(grants.length, 1);
  assert.deepEqual(grants[0].slice(0, 3), [ids.member, ids.role, true]);
  const [target, , , reason] = grants[0];
  acceptAudit(store, ids.guild, { id: '300', at: Date.now(), action: A.MemberRoleUpdate,
    target, actor: ids.bot, reason, options: {}, changes: [{ key: '$add', new: [{ id: ids.role }] }] },
  { owner: '104', bot: ids.bot });
  assert.equal(store.get('SELECT COUNT(*) n FROM events').n, 0);

  member.joinedTimestamp++;
  service.enqueue(member);
  await service.work(server, config);
  assert.equal(grants.length, 2);
});

test('проверка правил и действующий карантин откладывают выдачу роли', async t => {
  const { store, member, grants, server, service } = fixture(t);
  const config = store.settings(ids.guild);
  member.pending = true;
  service.enqueue(member);
  await service.work(server, config);
  assert.equal(grants.length, 0);

  member.pending = false;
  service.screeningFinished(member);
  store.queueQuarantine(ids.guild, member.id, 1, 'Тест');
  await service.work(server, config);
  assert.equal(grants.length, 0);
  store.saveQuarantine(store.getQuarantine(ids.guild, member.id), 'released');
  service.screeningFinished(member);
  await service.work(server, config);
  assert.equal(grants.length, 1);
});

test('недоступная или опасная роль остаётся в очереди без изменения прав', async t => {
  const { store, role, member, grants, server, service } = fixture(t);
  const config = store.settings(ids.guild);
  role.permissions.bitfield = P.Administrator;
  service.enqueue(member);
  await service.work(server, config);
  assert.equal(grants.length, 0);
  assert.equal(store.get('SELECT done FROM join_role_queue').done, 0);
  role.permissions.bitfield = 0n;
  role.editable = false;
  service.screeningFinished(member);
  await service.work(server, config);
  assert.equal(grants.length, 0);
  assert.equal(store.get('SELECT done FROM join_role_queue').done, 0);
});
