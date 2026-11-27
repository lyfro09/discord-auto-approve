import test from 'node:test';
import assert from 'node:assert/strict';
import { AuditLogEvent as A, PermissionFlagsBits as P } from 'discord.js';
import { acceptAudit } from '../anticrash/detect.mjs';
import { JoinRole, TagRole } from '../anticrash/join-role.mjs';
import { Store } from '../anticrash/store.mjs';

const ids = { guild: '100', role: '101', member: '102', bot: '103' };

function fixture(t) {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const role = { id: ids.role, name: 'Участник', editable: true, permissions: { bitfield: 0n } };
  const guild = { id: ids.guild, members: { fetchMe: async () => ({}), list: async () => new Map() }, roles: { fetch: async () => role } };
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


function identityPacket(member, identity, type = 'GUILD_MEMBER_UPDATE') {
  return { t: type, d: { guild_id: ids.guild, joined_at: new Date(member.joinedTimestamp).toISOString(), roles: [],
    user: { id: member.id, bot: false, primary_guild: identity } } };
}

const homeTag = { identity_guild_id: ids.guild, identity_enabled: true, tag: 'TEST' };
const memberTag = { identityGuildId: ids.guild, identityEnabled: true, tag: 'TEST' };

test('тег сравнивается по ID сервера, одна активация выдаёт награду один раз', async t => {
  const { store, member, grants, server } = fixture(t);
  const award = new TagRole(store, ids.guild, ids.role);
  const config = store.settings(ids.guild);
  award.observe(identityPacket(member, { ...homeTag, identity_guild_id: '200' }));
  award.observe(identityPacket(member, { ...homeTag, identity_enabled: false }));
  await award.work(server, config);
  assert.equal(grants.length, 0);

  member.user = { bot: false, primaryGuild: memberTag };
  award.observe(identityPacket(member, homeTag));
  award.observe(identityPacket(member, homeTag));
  await award.work(server, config);
  assert.equal(grants.length, 1);
  assert.deepEqual(grants[0].slice(0, 3), [ids.member, ids.role, true]);
  assert.match(grants[0][3], /^auto-tag-role:/);
  award.observe(identityPacket(member, homeTag));
  await award.work(server, config);
  assert.equal(grants.length, 1);

  member.user.primaryGuild = null;
  award.observe(identityPacket(member, null));
  await award.work(server, config);
  assert.equal(grants.length, 1, 'снятие тега не отзывает роль');
});

test('перед выдачей проверяется текущий тег, включая вход с уже включённым тегом', async t => {
  const { store, member, grants, server } = fixture(t);
  const award = new TagRole(store, ids.guild, ids.role);
  const config = store.settings(ids.guild);
  member.user = { bot: false, primaryGuild: null };
  award.observe(identityPacket(member, homeTag));
  await award.work(server, config);
  assert.equal(grants.length, 0);

  award.observe(identityPacket(member, null));
  member.user.primaryGuild = memberTag;
  member.joinedTimestamp += 1;
  award.observe(identityPacket(member, homeTag, 'GUILD_MEMBER_ADD'));
  member.pending = true;
  await award.work(server, config);
  assert.equal(grants.length, 0, 'кандидат сначала принимает правила');
  member.pending = false;
  award.screeningFinished(member);
  await award.work(server, config);
  assert.equal(grants.length, 1);
});


test('одноразовый обход охватывает текущих участников, продолжает с сохранённой страницы и не запускается снова', async t => {
  const { store, member, grants, server } = fixture(t);
  const config = store.settings(ids.guild);
  member.user = { bot: false, primaryGuild: memberTag };
  const onNextPage = { ...member, id: '3000' };
  const alreadyAssigned = { ...member, id: '3001', roles: { cache: new Map([[ids.role, {}]]) } };
  const otherTag = { ...member, id: '3002', user: { primaryGuild: { ...memberTag, identityGuildId: '200' } } };
  const page = new Map([[member.id, member]]);
  for (let i = 1000; i < 1999; i++) {
    page.set(String(i), { ...otherTag, id: String(i) });
  }
  const paged = [];
  server.guild.members.list = async ({ after }) => {
    paged.push(after);
    if (after === '0') return page;
    assert.equal(after, '1998');
    return new Map([onNextPage, alreadyAssigned, otherTag].map(item => [item.id, item]));
  };
  const found = new Map([member, onNextPage, alreadyAssigned, otherTag].map(item => [item.id, item]));
  server.member = async id => found.get(id);
  await new TagRole(store, ids.guild, ids.role).work(server, config);
  assert.deepEqual(grants.map(item => item[0]), [member.id]);
  assert.equal(store.get('SELECT done FROM tag_role_scan').done, 0);
  await new TagRole(store, ids.guild, ids.role).work(server, config);
  assert.deepEqual(grants.map(item => item[0]), [member.id, onNextPage.id]);
  assert.equal(store.get('SELECT done FROM tag_role_scan').done, 1);
  await new TagRole(store, ids.guild, ids.role).work(server, config);
  assert.deepEqual(paged, ['0', '1998']);
  assert.equal(grants.length, 2);
});
