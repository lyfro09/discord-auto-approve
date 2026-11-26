import { randomUUID } from 'node:crypto';
import { AuditLogEvent as A, PermissionFlagsBits as P } from 'discord.js';
import { bit, danger, dangerous, isManager, permissionNames } from './policy.mjs';

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const has = (value, mask) => (bit(value) & mask) === mask;
const permanent = error => [400, 403, 404].includes(error.status);
const summary = error => `${error.message ?? error}`.slice(0, 220);
export const roleSignature = role => role && [role.permissions, role.position, role.managed, role.name];
const supportAccess = P.ViewChannel | P.SendMessages | P.ReadMessageHistory;

export function restrictedOverwrite(current, support, voice, canConnect = false, deniedSupport = 0n) {
  const allow = bit(current?.allow);
  const deny = bit(current?.deny);
  const mask = support ? supportAccess : P.ViewChannel | (voice && canConnect ? P.Connect : 0n);
  const allowed = support ? (allow | mask) & ~deniedSupport : allow & ~mask;
  const denied = support ? (deny & ~mask) | deniedSupport : deny | mask;
  return { allow: String(allowed), deny: String(denied) };
}

function addStep(row, key, current, desired, meta) {
  const existing = row.data.steps[key];
  if (existing?.state === 'planned') return existing;
  if (same(current, desired)) return existing;
  const rollback = existing?.state === 'applied' && same(current, existing.desired)
    ? existing.rollback : current;
  const step = { ...meta, signature: existing?.signature ?? meta.signature, original: existing ? existing.original : current, before: current, desired, rollback,
    state: 'planned', release: null, marker: null };
  row.data.steps[key] = step;
  return step;
}

function rememberMarker(store, row, step, field, direction) {
  const marker = `anticrash:${row.id}:${randomUUID()}`;
  step[field] = marker;
  const overwrite = step.kind === 'overwrite';
  store.transaction(() => {
    store.run('INSERT INTO expected VALUES (?,?,?,?,?,?,?)', row.guild, marker,
      overwrite ? -1 : A.MemberRoleUpdate, overwrite ? step.id : row.member,
      overwrite ? 'overwrite' : direction ? '$add' : '$remove', overwrite ? row.member : step.id, Date.now());
    store.saveQuarantine(row);
  });
}

function readStep(state, step) {
  if (step.kind === 'overwrite') return state.channels.get(step.id)?.overwrite ?? null;
  return state.member.roles.has(step.id);
}

async function editStep(adapter, row, step, value, reason) {
  if (step.kind === 'overwrite') await adapter.overwrite(step.id, row.member, value, reason);
  else await adapter.role(row.member, step.id, value, reason);
}

function blockedStep(state, step) {
  if (step.kind === 'overwrite') {
    const channel = state.channels.get(step.id);
    if (!channel) return `канал ${step.id} удалён`;
    if (!channel.editable) return `в канале ${step.id} нужны View Channel и Manage Roles`;
    return null;
  }
  const role = state.roles.get(step.id);
  if (!role) return `роль ${step.id} удалена`;
  if (step.kind === 'marker' && step.desired && dangerous(role.permissions)) return 'У роли карантина появились опасные права.';
  if (!role.editable || !state.member?.manageable) {
    return `роль ${step.id} управляемая или находится вне иерархии бота. Проверь Manage Roles и порядок ролей`;
  }
  return null;
}

async function applyStep(store, adapter, row, state, step, errors) {
  if (step.state !== 'planned') return;
  const current = readStep(state, step);
  if (!step.marker && same(current, step.desired)) {
    step.state = 'unchanged';
    return;
  }
  if (step.marker && same(current, step.desired)) {
    step.state = await adapter.verifyOperation(step.marker, row, step, step.desired) ? 'applied' : 'uncertain';
    if (step.state === 'uncertain') errors.push(`${step.id}: изменение совпало с планом, но Audit Log не подтвердил операцию бота`);
    return;
  }
  if (!same(current, step.before)) {
    step.state = 'conflict';
    errors.push(`${step.id}: состояние изменилось после снимка. Проверь вручную`);
    return;
  }
  const blocker = blockedStep(state, step);
  if (blocker) {
    step.state = 'failed';
    errors.push(blocker);
    return;
  }
  rememberMarker(store, row, step, 'marker', step.desired);
  try {
    await editStep(adapter, row, step, step.desired, step.marker);
    step.state = 'applied';
  } catch (error) {
    if (!permanent(error)) throw error;
    step.state = 'failed';
    errors.push(`${step.id}: ${summary(error)}`);
  }
}

function verification(state, row) {
  if (!state.member) return ['Участник отсутствует на сервере. Ограничения будут проверены после входа.'];
  const errors = [];
  if (!state.member.roles.has(row.data.quarantineRole)) errors.push('Роль карантина отсутствует. Проверь её иерархию и Manage Roles.');
  if (dangerous(state.member.permissions)) {
    errors.push(`Остались права сервера: ${permissionNames(state.member.permissions).join(', ')}. Сними неподконтрольные роли или измени @everyone.`);
  }
  const visible = [];
  let accessibleSupport = !row.data.support;
  for (const channel of state.channels.values()) {
    if (channel.id === row.data.support) {
      accessibleSupport = has(channel.permissions, supportAccess);
      if (dangerous(channel.permissions)) errors.push(`В канале связи остались права: ${permissionNames(channel.permissions).join(', ')}.`);
    }
    else if (has(channel.permissions, P.ViewChannel)) visible.push(channel.id);
  }
  if (visible.length) errors.push(`Остался доступ к каналам: ${visible.join(', ')}. Проверь Administrator, доступ бота и переопределения.`);
  if (!accessibleSupport) errors.push(`Канал связи ${row.data.support} недоступен участнику. Проверь настройки канала.`);
  if (state.member.voice && state.member.voice !== row.data.support) {
    errors.push(`Участник остаётся в голосовом канале ${state.member.voice}. Отключи вручную или проверь Move Members.`);
  }
  return errors;
}

export async function applyQuarantine(store, adapter, row, settings) {
  const state = await adapter.state(row.member);
  const errors = [];
  if (!state.member) {
    if (row.phase !== 'absent') store.log(row.guild, `Карантин #${row.id}: участник ${row.member} вне сервера, ждём повторного входа.`, true);
    store.saveQuarantine(row, 'absent');
    return;
  }
  if (!row.data.snapshot) {
    row.data = {
      snapshot: {
        member: row.member, roles: [...state.member.roles], reason: row.reason, at: Date.now(),
        incidents: JSON.parse(row.incidents), channels: Object.fromEntries([...state.channels].map(([id, ch]) => [id, ch.overwrite])),
      },
      quarantineRole: settings.quarantine, support: settings.support, steps: {}, blocked: [],
    };
  }
  if (state.member.owner || state.member.self) {
    row.data.blocked = ['Участник является владельцем или самим ботом. Владелец может изменить доступ вручную.'];
    store.saveQuarantine(row, 'partial');
    store.log(row.guild, `Карантин #${row.id} частичный. ${row.data.blocked[0]}`, true);
    return;
  }

  for (const id of state.member.roles) {
    const role = state.roles.get(id);
    if (id !== row.guild && id !== row.data.quarantineRole && dangerous(role?.permissions)) {
      addStep(row, `role:${id}`, true, false, { kind: 'role', id, signature: roleSignature(role),
        originallyHeld: row.data.snapshot.roles.includes(id) });
    }
  }
  const mark = row.data.quarantineRole;
  if (mark) {
    const markerRole = state.roles.get(mark);
    if (markerRole && !dangerous(markerRole.permissions)) {
      addStep(row, `role:${mark}`, state.member.roles.has(mark), true,
        { kind: 'marker', id: mark, signature: roleSignature(markerRole) });
    } else errors.push('Роль карантина отсутствует или получила опасные права. Исправь роль, указанную для этого карантина.');
  }
  for (const channel of state.channels.values()) {
    if (channel.id === row.data.support && has(channel.permissions, supportAccess)
      && !dangerous(channel.permissions)) continue;
    if (channel.id !== row.data.support && has(channel.overwrite?.deny, P.ViewChannel)
      && !has(channel.overwrite?.allow, P.ViewChannel)) continue;
    const support = channel.id === row.data.support;
    const deniedSupport = support ? bit(channel.permissions) & bit(channel.writable) & danger : 0n;
    const next = restrictedOverwrite(channel.overwrite, support, channel.voice, channel.canConnect, deniedSupport);
    addStep(row, `channel:${channel.id}`, channel.overwrite, next, { kind: 'overwrite', id: channel.id });
  }
  store.saveQuarantine(row, 'applying');

  const phases = ['role', 'marker', 'overwrite'];
  const steps = Object.values(row.data.steps);
  for (const kind of phases) for (const step of steps.filter(item => item.kind === kind)) {
    if (store.settings(row.guild).mode !== 'active') {
      throw Object.assign(new Error('активный режим выключен'), { code: 'ANTICRASH_PAUSED' });
    }
    if (step.state !== 'planned') continue;
    if (step.kind === 'marker' && dangerous(state.roles.get(step.id)?.permissions)) {
      errors.push('Опасная роль карантина пропущена.');
      step.state = 'failed';
    } else {
      // Additional checks use the current member overwrites and role definitions.
      const current = await adapter.inspect(row.member, step);
      if (!current.member) {
        store.saveQuarantine(row, 'absent');
        return;
      }
      await applyStep(store, adapter, row, current, step, errors);
    }
    store.saveQuarantine(row);
  }

  if (store.settings(row.guild).mode !== 'active') {
    throw Object.assign(new Error('активный режим выключен'), { code: 'ANTICRASH_PAUSED' });
  }
  const voice = (await adapter.currentMember(row.member))?.voice;
  if (voice && voice !== row.data.support) {
    try {
      await adapter.disconnect(row.member, voice, `anticrash:${row.id}:disconnect`);
    } catch (error) {
      if (!permanent(error)) throw error;
      errors.push(`Голосовой канал ${voice}: ${summary(error)}`);
    }
  }
  const final = await adapter.state(row.member);
  if (!final.member) {
    store.saveQuarantine(row, 'absent');
    return;
  }
  const remaining = verification(final, row);
  const uncertain = steps.filter(step => step.state === 'uncertain')
    .map(step => `${step.id}: происхождение изменения не подтверждено. При снятии проверь вручную.`);
  row.data.blocked = [...new Set([...errors, ...remaining, ...uncertain])];
  const phase = row.data.blocked.length ? 'partial' : 'active';
  store.transaction(() => {
    store.saveQuarantine(row, phase);
    store.log(row.guild,
      `Карантин #${row.id} · инциденты ${row.incidents} · ${row.member} · ${phase === 'active' ? 'активен, права проверены' : 'частичный'}\n`
      + `Причина: ${row.reason}\nВыполнено операций: ${steps.filter(step => step.state === 'applied').length}.\n`
      + row.data.blocked.join('\n'), phase === 'partial');
  });
}

export async function previewRelease(adapter, row) {
  const state = await adapter.state(row.member);
  const entries = [];
  for (const [key, step] of Object.entries(row.data.steps ?? {})) {
    const label = `${step.kind === 'overwrite' ? 'Права в канале' : 'Роль'} ${step.id}`;
    let skip;
    if (step.state !== 'applied' || step.release?.status === 'applied') continue;
    if (step.kind !== 'overwrite' && !state.member) skip = 'участник вне сервера';
    else if (step.kind === 'role' && step.rollback && !step.originallyHeld) skip = 'роль получена после исходного снимка';
    else if (step.kind !== 'overwrite' && !same(roleSignature(state.roles.get(step.id)), step.signature)) skip = 'роль изменена или удалена';
    else if (!same(readStep(state, step), step.desired)) skip = 'состояние изменил другой администратор';
    else skip = blockedStep(state, step);
    const change = step.kind === 'overwrite' ? (step.rollback
      ? `вернуть allow=${step.rollback.allow}, deny=${step.rollback.deny}` : 'удалить персональное переопределение')
      : step.rollback ? 'вернуть роль' : 'снять роль';
    entries.push({ key, label, skip, change, dangerous: step.kind === 'role' && step.rollback
      && dangerous(state.roles.get(step.id)?.permissions) });
  }
  return entries;
}

const isReleaseAuthorized = (store, adapter, row) =>
  isManager(store.settings(row.guild), adapter.guild.ownerId, row.data.releasePlan.operator);

export async function releaseQuarantine(store, adapter, row) {
  const errors = [];
  const plan = row.data.releasePlan;
  for (const key of plan.keys) {
    const step = row.data.steps[key];
    if (step.release?.status === 'applied') continue;
    if (!isReleaseAuthorized(store, adapter, row)) {
      errors.push('Оператор больше не имеет доступа к снятию');
      break;
    }
    const state = await adapter.inspect(row.member, step);
    const current = step.kind === 'overwrite' || state.member ? readStep(state, step) : null;
    if (same(current, step.rollback) && step.releaseMarker) {
      if (await adapter.verifyOperation(step.releaseMarker, row, step, step.rollback)) {
        step.release = { status: 'applied' };
      } else {
        step.release = { status: 'uncertain' };
        errors.push(`${step.id}: восстановление не подтверждено Audit Log.`);
      }
      store.saveQuarantine(row);
      continue;
    }
    let skip = !state.member && step.kind !== 'overwrite' ? 'участник вне сервера' : blockedStep(state, step);
    if (!skip && step.kind !== 'overwrite' && !same(roleSignature(state.roles.get(step.id)), step.signature)) {
      skip = 'роль изменилась после предварительного просмотра';
    }
    if (!skip && !same(current, step.desired)) skip = 'состояние изменилось после предварительного просмотра';
    if (skip) {
      errors.push(`${step.id}: ${skip}`);
      step.release = { status: 'skipped', reason: skip };
      store.saveQuarantine(row);
      continue;
    }

    rememberMarker(store, row, step, 'releaseMarker', step.rollback);
    try {
      await editStep(adapter, row, step, step.rollback, step.releaseMarker);
      step.release = { status: 'applied' };
    } catch (error) {
      if (!permanent(error)) throw error;
      step.release = { status: 'failed', reason: summary(error) };
      errors.push(`${step.id}: ${summary(error)}`);
    }
    store.saveQuarantine(row);
  }
  row.data.releaseErrors = errors;
  const phase = errors.length ? 'release-partial' : 'released';
  store.transaction(() => {
    store.saveQuarantine(row, phase);
    store.log(row.guild,
      `Карантин #${row.id} · участник ${row.member} · ${errors.length ? 'снят частично' : 'снят'} · оператор ${plan.operator}.\n`
      + `Причина: ${plan.reason}. Пропущено при просмотре: ${plan.skipped.join(', ') || '0'}.\n${errors.join('\n')}`,
    !!errors.length || !!plan.skipped.length);
  });
}
