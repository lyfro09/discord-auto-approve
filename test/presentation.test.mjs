import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DiscordServer } from '../anticrash/discord.mjs';
import { embedFor, field, logCard, logMessage, targetRef, userRef } from '../anticrash/presentation.mjs';
import { Store } from '../anticrash/store.mjs';

const guildId = '1575296477960474684';
const actor = '689455808000000000';
const alertRole = '1575297000000000000';
const log = '1575297100000000000';
const at = Date.parse('2026-11-26T20:01:00Z');

test('карточка показывает русские блоки, локальное время Discord и позволяет упомянуть только роль оповещений', () => {
  const card = {
    title: 'Изменение порядка ролей',
    tone: 'alert',
    at,
    description: 'Discord не указал, какие роли переставили.',
    fields: [field('Исполнитель', userRef(actor)), field('Цель', targetRef('role-hierarchy', guildId, guildId))],
    footer: 'Инцидент №1',
  };

  const payload = logMessage(card, alertRole, true);
  assert.equal(payload.content, `<@&${alertRole}>`);
  assert.deepEqual(payload.allowedMentions, { parse: [], roles: [alertRole] });
  const embed = payload.embeds[0];
  assert.equal(embed.title, card.title);
  assert.equal(embed.timestamp, '2026-11-26T20:01:00.000Z');
  assert.equal(embed.fields[0].value, `<@${actor}>`);
  assert.equal(embed.fields[1].value, 'Этот сервер');
  const fallback = logMessage(card, null, false);
  assert.equal(fallback.embeds, undefined);
  assert.match(fallback.content, /Инцидент №1/);
  assert.deepEqual(fallback.allowedMentions, { parse: [], roles: [] });
});

test('для удалённого канала используется безопасное имя из Audit Log, поля ограничены размером Discord', () => {
  const entry = { changes: [{ key: 'name', old: '🛠️ <@everyone> **канал**' }] };
  assert.match(targetRef('channel-delete', log, guildId, entry), /канал/);
  assert.doesNotMatch(targetRef('channel-delete', log, guildId, entry), /<@everyone>/);
  const embed = embedFor({ title: 'a'.repeat(500), description: 'b'.repeat(5400),
    fields: Array.from({ length: 37 }, () => field('Имя', 'v'.repeat(1300))) });
  assert.ok(embed.title.length <= 256);
  assert.ok(embed.description.length <= 4096);
  assert.ok(embed.fields.length <= 25);
  assert.ok(embed.fields.every(item => item.value.length <= 1024));
  assert.ok(embed.title.length + embed.description.length
    + embed.fields.reduce((total, item) => total + item.name.length + item.value.length, 0) <= 6000);
});

test('миграция сохраняет старые записи и отправляет их в читаемом виде', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'discord-presentation-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'state.sqlite');
  let store = new Store(path);
  store.db.exec('ALTER TABLE log DROP COLUMN presentation; PRAGMA user_version=1');
  const original = `Настройки · оператор ${actor} · режим active`;
  store.run('INSERT INTO log (guild,at,body,urgent) VALUES (?,?,?,?)', guildId, at, original, 0);
  store.close();

  store = new Store(path);
  t.after(() => store.close());
  const legacy = store.get('SELECT * FROM log');
  assert.equal(legacy.body, original);
  assert.equal(logCard(legacy).description, `Настройки · оператор <@${actor}> · режим active`);

  store.log(guildId, { title: 'Режим защиты изменён', fields: [field('Оператор', userRef(actor))] });
  const fresh = store.get('SELECT * FROM log ORDER BY id DESC LIMIT 1');
  const sent = [];
  const channel = { isSendable: () => true, permissionsFor: () => ({ has: () => true }),
    send: async message => sent.push(message) };
  const server = new DiscordServer({ id: guildId, client: { user: { id: actor } },
    members: { me: {} }, channels: { fetch: async () => channel } }, store);
  await server.send({ log, mention: alertRole }, fresh);
  assert.equal(sent[0].content, undefined);
  assert.equal(sent[0].embeds[0].title, 'Режим защиты изменён');
});
