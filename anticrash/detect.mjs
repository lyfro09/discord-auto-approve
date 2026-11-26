import { AuditLogEvent as A } from 'discord.js';
import { activeTrust, canAuthorizeGrant, classify, isId, trustFor } from './policy.mjs';

export const matchWindow = 20_000;
const checkAfter = 24_000;
const latestAutomaticAction = 120_000;

export function setGrant(store, guild, member, role, epoch, joined, at, valid) {
  store.run(`INSERT INTO grants VALUES (?,?,?,?,?,?,?) ON CONFLICT(guild,member,role)
    DO UPDATE SET epoch=excluded.epoch, joined=excluded.joined, at=excluded.at, valid=excluded.valid
    WHERE excluded.at>=grants.at`, guild, member, role, epoch, joined ?? 0, at, Number(valid));
}

export function revokeGrants(store, guild, member, at, role = null) {
  store.run(`UPDATE grants SET valid=0, at=? WHERE guild=? AND member=? AND at<=?
    AND (? IS NULL OR role=?)`, at, guild, member, at, role, role);
}

function applyTrustChanges(store, settings, guild, entry, identity) {
  if (entry.action === A.MemberRoleUpdate && entry.target) {
    for (const change of entry.changes.filter(item => ['$add', '$remove'].includes(item.key))) {
      for (const role of change.new ?? []) {
        if (!activeTrust(settings, `role:${role.id}`, entry.at)) continue;
        const epoch = settings.trustEpoch[role.id] ?? 0;
        const authorized = change.key === '$add' && entry.at >= epoch
          && identity.target?.roles.has(role.id) && Number.isFinite(identity.target?.joined) && identity.target.joined <= entry.at
          && canAuthorizeGrant(settings, identity.owner, entry.actor, entry.at);
        setGrant(store, guild, entry.target, role.id, epoch, identity.target?.joined, entry.at, authorized);
      }
    }
  }

  const roleEdit = [A.RoleUpdate, A.RoleDelete, A.RolePositionUpdate].includes(entry.action);
  if (!roleEdit) return;

  const editedRoles = entry.action === A.RolePositionUpdate
    ? Object.keys(settings.trustEpoch)
    : [entry.target];
  let changed = false;
  for (const role of editedRoles) {
    if (!activeTrust(settings, `role:${role}`, entry.at)) continue;
    const epoch = settings.trustEpoch[role] ?? 0;
    if (epoch > entry.at) continue;
    settings.trustEpoch[role] = entry.at + 1;
    store.log(guild, `Доверие к участникам роли ${role} приостановлено после изменения роли. Проверь роль и подтверди держателей командой /anticrash trust-confirm.`, true);
    changed = true;
  }
  if (changed) store.saveSettings(guild, settings);
}

function trustedRoles(store, guild, settings, entry, actor) {
  if (!actor) return [];
  return store.all(`SELECT role,epoch,joined FROM grants
    WHERE guild=? AND member=? AND valid=1 AND at<=?`, guild, entry.actor, entry.at)
    .filter(grant => grant.joined === actor.joined && actor.roles.has(grant.role)
      && grant.epoch === settings.trustEpoch[grant.role])
    .map(grant => grant.role);
}

function expectedOperation(store, guild, entry, bot) {
  if (entry.actor !== bot || !entry.reason || !entry.target) return false;
  const expected = store.get(`SELECT * FROM expected
    WHERE guild=? AND reason=? AND target=? AND (action=? OR action=-1)`,
  guild, entry.reason, entry.target, entry.action);
  if (!expected || Math.abs(entry.at - expected.at) > matchWindow * 2) return false;
  if (expected.kind === 'overwrite') {
    return [A.ChannelOverwriteCreate, A.ChannelOverwriteUpdate, A.ChannelOverwriteDelete].includes(entry.action)
      && expected.subject === entry.options.id;
  }
  if (expected.kind === 'disconnect') return entry.action === A.MemberDisconnect;
  const changes = entry.changes.filter(item => ['$add', '$remove'].includes(item.key));
  return changes.length === 1 && changes[0].key === expected.kind
    && changes[0].new?.length === 1 && changes[0].new[0].id === expected.subject;
}

function threshold(store, guild, settings, signal, entry, identity, decision, scope, count, limit) {
  const rule = settings.rules[signal.type];
  const confirmed = scope === 'actor' && isId(entry.actor) && isId(signal.target);
  const authorizedTrustChange = confirmed && signal.type.startsWith('trusted-role-')
    && canAuthorizeGrant(settings, identity.owner, entry.actor, entry.at);
  let reaction = rule.reaction;
  if (scope === 'global' && reaction === 'quarantine') reaction = 'alert';
  if (scope === 'unknown') reaction = 'alert';
  if (reaction === 'quarantine' && (entry.actor === identity.owner || entry.actor === identity.bot || authorizedTrustChange)) {
    reaction = 'alert';
  }
  if (reaction === 'quarantine' && (decision.stale || decision.problem)) reaction = 'alert';
  const effective = reaction === 'quarantine' && settings.mode === 'observe' ? 'would-quarantine' : reaction;

  const { id, first } = store.incident(guild, {
    type: signal.type, scope: confirmed ? entry.actor : scope, actor: entry.actor, target: signal.target,
    at: entry.at, audit: entry.id,
    data: { count, limit, seconds: rule.seconds, reaction: effective, mode: settings.mode, confirmed },
  }, rule.seconds * 1000);

  let q;
  if (effective === 'quarantine' && confirmed) {
    q = store.queueQuarantine(guild, entry.actor, id, `${signal.type}, ${count}/${limit} за ${rule.seconds} с`);
  }
  if (first) {
    const details = {
      quarantine: `карантин #${q} в очереди`, 'would-quarantine': 'в наблюдении назначил бы карантин',
      log: 'запись в журнале', alert: 'тревога',
    };
    store.log(guild, [
      `Инцидент #${id} · ${signal.type} · ${new Date(entry.at).toISOString()}`,
      `Исполнитель: ${entry.actor ?? 'не подтверждён'}. Цель: ${signal.target ?? 'не подтверждена'}.`,
      `Действий: ${count}, порог: ${limit} за ${rule.seconds} с. Реакция: ${details[effective]}.`,
      scope === 'global' ? 'Суммарный порог по серверу.' : '',
      decision.stale ? 'Запись получена после окна автоматической реакции.' : '',
      decision.problem ?? '',
    ].filter(Boolean).join('\n'), effective === 'alert' || effective === 'quarantine');
  }
  return id;
}

export function acceptAudit(store, guild, entry, identity, now = Date.now()) {
  const settings = store.settings(guild);
  if (settings.mode === 'off' || entry.at < settings.since) return;
  return store.transaction(() => {
    const saved = store.run('INSERT OR IGNORE INTO audit VALUES (?,?,?,?,?,?,?)',
      guild, entry.id, entry.at, entry.action, entry.target, entry.actor, JSON.stringify(entry));
    if (!saved.changes) return;
    if (expectedOperation(store, guild, entry, identity.bot)) {
      if (entry.action === A.MemberRoleUpdate) {
        // A restored trusted role is reauthorized explicitly by the server owner.
        const removed = entry.changes.find(item => item.key === '$remove');
        for (const role of removed?.new ?? []) revokeGrants(store, guild, entry.target, entry.at, role.id);
      }
      return;
    }

    const facts = {
      ...identity,
      trustRole: role => activeTrust(settings, `role:${role}`, entry.at),
      hasTrustedRoles: Object.keys(settings.trust).some(key => key.startsWith('role:') && activeTrust(settings, key, entry.at)),
    };
    const signals = classify(guild, entry, facts);
    applyTrustChanges(store, settings, guild, entry, identity);
    const roles = trustedRoles(store, guild, settings, entry, identity.actor);
    const incidents = [];
    for (const signal of signals) {
      const rule = settings.rules[signal.type];
      if (!rule.enabled) continue;
      const authorization = trustFor(settings, entry.actor, roles, signal.type, entry.at);
      const confirmed = isId(entry.actor) && isId(signal.target);
      const excluded = authorization.exempt || !confirmed || identity.actorUnknown || signal.uncertain;
      store.run('INSERT INTO events VALUES (?,?,?,?,?,?,?,?)', guild, entry.id, signal.type,
        entry.actor, signal.target, entry.at, signal.weight, Number(!!excluded));
      if (authorization.exempt && confirmed) continue;
      const anchor = store.get('SELECT MAX(at) AS at FROM events WHERE guild=? AND kind=?',
        guild, signal.type).at;
      const cutoff = Math.max(settings.since, anchor - rule.seconds * 1000);
      const decision = { stale: now - entry.at > latestAutomaticAction || entry.at < cutoff };
      if (identity.actorUnknown) decision.problem = 'Не удалось проверить доверие по ролям исполнителя.';
      if (signal.uncertain) decision.problem = 'В Audit Log недостаточно данных об изменении иерархии.';
      if (!confirmed) decision.problem = 'Audit Log не указал однозначного исполнителя или объект.';
      if (decision.problem) {
        incidents.push(threshold(store, guild, settings, signal, entry, identity, decision,
          'unknown', signal.weight, authorization.limit));
        continue;
      }
      const totals = store.get(`SELECT COALESCE(SUM(weight),0) AS total,
        COALESCE(SUM(CASE WHEN actor=? THEN weight ELSE 0 END),0) AS personal,
        COUNT(DISTINCT actor) AS actors
        FROM events WHERE guild=? AND kind=? AND exempt=0 AND actor IS NOT NULL AND target IS NOT NULL AND at>=?`,
      entry.actor, guild, signal.type, cutoff);
      if (totals.personal >= authorization.limit) {
        incidents.push(threshold(store, guild, settings, signal, entry, identity, decision,
          'actor', totals.personal, authorization.limit));
      }
      if (rule.global && totals.total >= rule.global && totals.actors > 1) {
        incidents.push(threshold(store, guild, settings, signal, entry, identity, decision,
          'global', totals.total, rule.global));
      }
    }
    return incidents;
  });
}

export function observe(store, guild, id, at, observation) {
  const settings = store.settings(guild);
  const rule = settings.rules[observation.type];
  if (settings.mode === 'off' || !rule?.enabled || at < settings.since) return;
  store.run('INSERT OR IGNORE INTO observations (guild,id,at,target,data) VALUES (?,?,?,?,?)',
    guild, id, at, observation.target, JSON.stringify(observation));
}

export function closeObservations(store, guild, now = Date.now()) {
  const settings = store.settings(guild);
  const due = store.all('SELECT * FROM observations WHERE guild=? AND done=0 AND at<=? ORDER BY at LIMIT 200',
    guild, now - checkAfter);
  for (const row of due) store.transaction(() => {
    store.run('UPDATE observations SET done=1 WHERE guild=? AND id=?', guild, row.id);
    const observation = JSON.parse(row.data);
    const rule = settings.rules[observation.type];
    if (settings.mode === 'off' || row.at < settings.since || !rule?.enabled) return;

    const target = observation.alternateTarget ?? row.target;
    const records = observation.webhookChannel
      ? store.all('SELECT * FROM audit WHERE guild=? AND action IN (50,51,52) AND at BETWEEN ? AND ?',
        guild, row.at - matchWindow, row.at + matchWindow)
      : store.all('SELECT * FROM audit WHERE guild=? AND target IN (?,?) AND at BETWEEN ? AND ?',
        guild, row.target, target, row.at - matchWindow, row.at + matchWindow);
    const matches = records.filter(item => {
      const entry = JSON.parse(item.data);
      if (observation.webhookChannel && entry.options.channel_id !== row.target
        && entry.options.webhook_channel_id !== row.target
        && !entry.changes.some(change => change.key === 'channel_id' && [change.new, change.old].includes(row.target))) return false;
      return observation.actions.includes(item.action)
        && (!observation.keys?.length || entry.changes.some(change => observation.keys.includes(change.key)));
    });
    if (matches.length === 1 && isId(matches[0].actor)) return;
    if (observation.onlyIfAmbiguous && matches.length === 0) return;
    const problem = matches.length > 1 ? 'Найдено несколько записей Audit Log.' : 'Подтверждение в Audit Log отсутствует.';
    threshold(store, guild, settings, observation, { ...row, actor: null, id: `gateway:${row.id}` }, {},
      { problem }, 'unknown', 1, rule.limit);
  });
}
