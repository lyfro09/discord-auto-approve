import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PermissionFlagsBits as P, PermissionsBitField } from 'discord.js';
import { applyQuarantine, previewRelease, releaseQuarantine } from '../anticrash/quarantine.mjs';
import { Store } from '../anticrash/store.mjs';

const guild = '101';
const actor = '102';
const owner = '103';
const admin = '110';
const ordinary = '111';
const marker = '112';
const main = '130';
const support = '131';
const voice = '132';
const permission = value => String(value);

class Fixture {
  constructor() {
    this.guild = { id: guild, ownerId: owner };
    this.member = { roles: new Set([guild, admin, ordinary]), voice, manageable: true, owner: false };
    this.roles = new Map([
      [guild, this.makeRole(P.ViewChannel, false)],
      [admin, this.makeRole(P.Administrator, true)],
      [ordinary, this.makeRole(P.ViewChannel | P.SendMessages, true)],
      [marker, this.makeRole(0n, true)],
    ]);
    this.overwrites = new Map([[main, { allow: String(P.ViewChannel), deny: '0' }]]);
    this.operations = [];
    this.reasons = new Set();
    this.interrupt = false;
  }

  makeRole(permissions, editable) { return { permissions: String(permissions), editable, position: 1, managed: false, name: 'role' }; }
  async currentMember() {
    if (!this.member) return null;
    const permissions = [...this.member.roles].reduce((mask, id) => mask | BigInt(this.roles.get(id).permissions), 0n);
    return { ...this.member, roles: new Set(this.member.roles), permissions: String(permissions) };
  }
  async state() {
    const member = await this.currentMember();
    const base = BigInt(member?.permissions ?? 0);
    const full = !!(base & P.Administrator);
    return { member, roles: this.roles,
      channels: new Map([main, support, voice].map(id => {
        const current = this.overwrites.get(id) ?? null;
        const defaults = id === support ? 0n : P.ViewChannel | P.SendMessages | P.Connect;
        const effective = full ? PermissionsBitField.All : (defaults & ~BigInt(current?.deny ?? 0)) | BigInt(current?.allow ?? 0);
        return [id, { id, editable: true, voice: id === voice, canConnect: true,
          writable: permission(PermissionsBitField.All), permissions: permission(effective), overwrite: current }];
      })),
    };
  }
  async inspect() { return this.state(); }
  async role(member, role, add, reason) {
    this.operations.push([role, add]);
    this.reasons.add(reason);
    if (add) this.member.roles.add(role);
    else this.member.roles.delete(role);
    if (this.interrupt) {
      this.interrupt = false;
      throw new Error('response lost');
    }
  }
  async overwrite(channel, member, value, reason) {
    this.operations.push([channel, value]);
    this.reasons.add(reason);
    if (value) this.overwrites.set(channel, value);
    else this.overwrites.delete(channel);
  }
  async disconnect() { this.member.voice = null; }
  async verifyOperation(reason) { return this.reasons.has(reason); }
}

function enqueue(store) {
  const settings = store.settings(guild);
  settings.mode = 'active';
  settings.quarantine = marker;
  settings.support = support;
  store.saveSettings(guild, settings);
  store.queueQuarantine(guild, actor, 1, 'тест');
  return settings;
}

test('карантин снимает Administrator первым, перекрывает явное разрешение и оставляет канал связи', async t => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const settings = enqueue(store);
  const adapter = new Fixture();
  const before = structuredClone(adapter.overwrites.get(main));
  await applyQuarantine(store, adapter, store.getQuarantine(guild, actor), settings);
  const applied = store.getQuarantine(guild, actor);
  assert.equal(applied.phase, 'active');
  assert.deepEqual(adapter.operations.slice(0, 2), [[admin, false], [marker, true]]);
  assert.equal(adapter.member.voice, null);
  assert.ok(BigInt(adapter.overwrites.get(main).deny) & P.ViewChannel);
  assert.ok(BigInt(adapter.overwrites.get(support).allow) & P.SendMessages);
  assert.deepEqual(applied.data.snapshot.roles, [guild, admin, ordinary]);
  store.queueQuarantine(guild, actor, 2, 'повтор');
  const repeated = store.getQuarantine(guild, actor);
  assert.deepEqual(repeated.data.snapshot.channels[main], before);
  assert.deepEqual(JSON.parse(repeated.incidents), [1, 2]);

  const preview = await previewRelease(adapter, repeated);
  assert.equal(preview.find(step => step.key === `role:${admin}`).dangerous, true);
  repeated.data.releasePlan = { keys: preview.filter(step => !step.dangerous && !step.skip).map(step => step.key),
    skipped: ['Administrator не подтверждён'], operator: owner, reason: 'проверено' };
  store.saveQuarantine(repeated, 'releasing');
  await releaseQuarantine(store, adapter, repeated);
  assert.deepEqual(adapter.overwrites.get(main), before);
  assert.equal(adapter.overwrites.has(support), false);
  assert.deepEqual([...adapter.member.roles], [guild, ordinary]);
  assert.equal(store.getQuarantine(guild, actor), undefined);
});

test('роль выше бота оставляет частичный карантин и реальные права видны в записанном результате', async t => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const settings = enqueue(store);
  const adapter = new Fixture();
  adapter.roles.get(admin).editable = false;
  await applyQuarantine(store, adapter, store.getQuarantine(guild, actor), settings);
  const row = store.getQuarantine(guild, actor);
  assert.equal(row.phase, 'partial');
  assert.match(row.data.blocked.join(' '), /иерархии|Administrator/);
  assert.match(row.data.blocked.join(' '), /Остался доступ/);
  assert.ok(adapter.member.roles.has(admin));
});

test('прерванное применение продолжается из файла SQLite, повторный вход не перезаписывает снимок', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'anticrash-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'data.sqlite');
  let store = new Store(file);
  const settings = enqueue(store);
  const adapter = new Fixture();
  adapter.interrupt = true;
  await assert.rejects(applyQuarantine(store, adapter, store.getQuarantine(guild, actor), settings), /response lost/);
  const snapshot = store.getQuarantine(guild, actor).data.snapshot;
  store.close();
  store = new Store(file);
  t.after(() => store.close());
  const row = store.getQuarantine(guild, actor);
  assert.equal(row.phase, 'applying');
  await applyQuarantine(store, adapter, row, settings);
  assert.equal(store.getQuarantine(guild, actor).phase, 'active');
  assert.equal(adapter.operations.filter(([role]) => role === admin).length, 1);
  adapter.member.roles = new Set([guild, ordinary]);
  adapter.overwrites.clear();
  await applyQuarantine(store, adapter, store.getQuarantine(guild, actor), settings);
  assert.equal(store.getQuarantine(guild, actor).phase, 'active');
  assert.deepEqual(store.getQuarantine(guild, actor).data.snapshot, snapshot);
  assert.equal(adapter.member.roles.has(marker), true);
});

test('снятие перепроверяет ручные изменения прав и роли после просмотра', async t => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const settings = enqueue(store);
  const adapter = new Fixture();
  await applyQuarantine(store, adapter, store.getQuarantine(guild, actor), settings);
  const row = store.getQuarantine(guild, actor);
  const preview = await previewRelease(adapter, row);
  row.data.releasePlan = { keys: preview.filter(step => !step.skip).map(step => step.key), skipped: [],
    operator: owner, reason: 'явное подтверждение' };
  store.saveQuarantine(row, 'releasing');
  adapter.roles.get(admin).permissions = String(P.ManageGuild);
  const external = { allow: String(P.SendMessages), deny: String(P.ViewChannel) };
  adapter.overwrites.set(main, external);
  await releaseQuarantine(store, adapter, row);
  assert.equal(store.getQuarantine(guild, actor).phase, 'release-partial');
  assert.deepEqual(adapter.overwrites.get(main), external);
  assert.equal(adapter.member.roles.has(admin), false);
  assert.equal(adapter.member.roles.has(marker), false);
});
