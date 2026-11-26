import { AttachmentBuilder, ChannelType as C, MessageFlags, SlashCommandBuilder } from 'discord.js';
import { randomUUID } from 'node:crypto';
import { activeTrust, defaultSettings, eventTypes, isManager } from './policy.mjs';
import { setGrant } from './detect.mjs';
import { previewRelease } from './quarantine.mjs';
import { decoded } from './store.mjs';

const choices = values => values.map(value => ({ name: value, value }));
const text = (sub, name, description, required = true, length = 300) =>
  sub.addStringOption(option => option.setName(name).setDescription(description).setRequired(required).setMaxLength(length));
const number = (sub, name, description, min, max, required = false) =>
  sub.addIntegerOption(option => option.setName(name).setDescription(description).setMinValue(min).setMaxValue(max).setRequired(required));
const select = (sub, name, description, values, required = true) =>
  sub.addStringOption(option => option.setName(name).setDescription(description).setRequired(required).addChoices(...choices(values)));
const flag = (sub, name, description, required = false) =>
  sub.addBooleanOption(option => option.setName(name).setDescription(description).setRequired(required));
const user = (sub, description) =>
  sub.addUserOption(option => option.setName('user').setDescription(description).setRequired(true));
const role = (sub, name, description, required = true) =>
  sub.addRoleOption(option => option.setName(name).setDescription(description).setRequired(required));
const channel = (sub, name, description, required = true) =>
  sub.addChannelOption(option => option.setName(name).setDescription(description)
    .addChannelTypes(C.GuildText, C.GuildAnnouncement).setRequired(required));

const command = new SlashCommandBuilder().setName('anticrash').setDescription('Управление защитой сервера');
const sub = (name, description, build = x => x) =>
  command.addSubcommand(option => build(option.setName(name).setDescription(description)));

sub('status', 'Режим, каналы, права бота и ожидающие операции');
sub('setup', 'Мастер настройки каналов, роли и проверки прав', option => {
  channel(option, 'log', 'Канал журналирования');
  role(option, 'quarantine', 'Роль карантина');
  channel(option, 'support', 'Канал связи со стаффом', false);
  role(option, 'mention', 'Роль для срочных оповещений', false);
  return option;
});
sub('mode', 'Выбрать режим работы', option => select(option, 'value', 'Режим', ['off', 'observe', 'active']));
sub('rules', 'Показать текущие настройки и пороги по умолчанию');
sub('rule', 'Изменить отдельное правило', option => {
  text(option, 'event', 'Тип события из /anticrash rules', true, 40);
  flag(option, 'enabled', 'Включено');
  number(option, 'limit', 'Порог на исполнителя', 1, 10000);
  number(option, 'seconds', 'Окно подсчёта в секундах', 1, 3600);
  number(option, 'global', 'Общий порог по серверу, 0 отключает', 0, 10000);
  return select(option, 'reaction', 'Действие при срабатывании', ['log', 'alert', 'quarantine'], false);
});
sub('manager', 'Владелец назначает или отзывает администратора защиты', option =>
  flag(user(option, 'Администратор'), 'enabled', 'Разрешить управление антикрашем', true));
sub('trust-list', 'Показать доверенные записи и сроки');
sub('trust-set', 'Добавить или изменить доверенную запись', option => {
  select(option, 'kind', 'Тип записи', ['user', 'bot', 'role']);
  text(option, 'id', 'ID пользователя, бота или роли', true, 20);
  select(option, 'mode', 'Область доверия', ['allow', 'limit', 'immune']);
  text(option, 'comment', 'Комментарий для журнала');
  text(option, 'events', 'Типы через запятую для allow или limit', false, 1000);
  number(option, 'limit', 'Порог для режима limit', 1, 10000);
  return number(option, 'minutes', 'Срок в минутах, 0 бессрочно', 0, 525600);
});
sub('trust-remove', 'Удалить доверенную запись', option =>
  text(select(option, 'kind', 'Тип записи', ['user', 'bot', 'role']), 'id', 'ID записи', true, 20));
sub('trust-confirm', 'Подтвердить нынешних держателей доверенной роли', option => {
  role(option, 'role', 'Роль для проверки');
  flag(option, 'confirm', 'Подтверждаю проверку и доверие существующим держателям', true);
  return option.addUserOption(field => field.setName('user').setDescription('Один участник, иначе все текущие держатели'));
});
sub('quarantine', 'Ручной карантин с фиксацией причины', option =>
  text(user(option, 'Участник'), 'reason', 'Причина помещения в карантин'));
sub('retry', 'Повторить проверку и применение действующего карантина', option => user(option, 'Участник'));
sub('quarantines', 'Показать открытые карантины', option => number(option, 'page', 'Страница', 1, 500));
sub('release', 'Предварительный просмотр снятия карантина', option =>
  text(user(option, 'Участник'), 'reason', 'Причина снятия карантина'));
sub('release-confirm', 'Снять карантин по предварительному просмотру', option =>
  flag(text(option, 'code', 'Код предварительного просмотра', true, 36),
    'dangerous', 'Отдельно подтверждаю возврат перечисленных опасных ролей'));
sub('incidents', 'Показать журнал инцидентов', option => number(option, 'page', 'Страница', 1, 500));
sub('incident', 'Показать детали инцидента и реакцию', option => number(option, 'id', 'Номер', 1, 2_000_000_000, true));
sub('logs', 'Показать записи журнала и состояние доставки', option => number(option, 'page', 'Страница', 1, 500));
export const commandData = command.toJSON();

const timestamp = at => new Date(at).toISOString();
const modeName = { off: 'выключен', observe: 'наблюдение', active: 'активная защита' };
const phaseNames = {
  queued: 'в очереди', applying: 'применяется', active: 'активен, ограничения проверены', partial: 'частичный',
  absent: 'участник вне сервера', releasing: 'снимается', 'release-partial': 'снят частично', released: 'снят',
};
const rowPage = (options, size) => ((options.getInteger('page') ?? 1) - 1) * size;
const label = (id, fallback = 'нет') => id ?? fallback;
const managerMessage = 'Доступ есть у владельца и назначенных им администраторов антикраша.';
const requiredId = string => {
  if (!/^[1-9][0-9]{0,19}$/.test(string)) throw new Error('Укажи числовой ID Discord.');
  return string;
};

function setMode(settings, mode) {
  if (settings.mode !== mode) settings.since = Date.now();
  settings.mode = mode;
}

async function respond(interaction, value) {
  if (value.length <= 1900) {
    await interaction.editReply({ content: value, allowedMentions: { parse: [] } });
  } else {
    await interaction.editReply({
      content: 'Полный результат в текстовом файле.',
      files: [new AttachmentBuilder(Buffer.from(value, 'utf8'), { name: 'anticrash.txt' })],
    });
  }
}

function recordChange(store, guild, settings, actor, description) {
  store.transaction(() => {
    store.saveSettings(guild, settings);
    store.log(guild, `Настройки · оператор ${actor} · ${description}`);
  });
}

async function managerAction(store, server, interaction, name, settings) {
  const { options, guildId: guild } = interaction;
  const actor = interaction.user.id;
  const input = key => options.getString(key);
  const log = description => recordChange(store, guild, settings, actor, description);
  const guard = () => {
    const saved = store.settings(guild);
    if (!isManager(saved, server.guild.ownerId, actor)) throw new Error(managerMessage);
    if (JSON.stringify(saved) !== JSON.stringify(settingsBefore)) throw new Error('Настройки изменились. Повтори команду.');
  };
  const settingsBefore = structuredClone(settings);

  switch (name) {
    case 'status': {
      const current = await server.check(settings);
      const pending = store.get(`SELECT COUNT(*) AS count FROM quarantine
        WHERE guild=? AND phase!='released'`, guild).count;
      return [`Режим: ${modeName[settings.mode]}. Открытые карантины: ${pending}.`,
        `Логи: ${label(settings.log)}. Роль: ${label(settings.quarantine)}. Связь: ${label(settings.support)}. Оповещения: ${label(settings.mention)}.`,
        `Администраторы антикраша: ${settings.managers.join(', ') || 'только владелец'}.`,
        current.length ? current.join('\n') : 'Проверки активной защиты пройдены.'].join('\n');
    }
    case 'setup': {
      settings.log = options.getChannel('log', true).id;
      settings.quarantine = options.getRole('quarantine', true).id;
      settings.support = options.getChannel('support')?.id ?? null;
      settings.mention = options.getRole('mention')?.id ?? null;
      const errors = await server.check(settings);
      guard();
      if (settings.mode === 'off' || errors.length) setMode(settings, 'observe');
      log(`мастер настройки, режим ${settings.mode}, лог ${settings.log}, карантин ${settings.quarantine}, связь ${settings.support}, упоминание ${settings.mention}.`);
      return errors.length ? `Сохранено. Режим наблюдения. Исправь:\n${errors.join('\n')}`
        : 'Настройки сохранены. Для включения активной защиты используй /anticrash mode value:active.';
    }
    case 'mode': {
      const value = input('value');
      const errors = value === 'active' ? await server.check(settings) : [];
      if (value === 'active') guard();
      setMode(settings, errors.length ? 'observe' : value);
      if (settings.mode !== settingsBefore.mode) {
        store.run('DELETE FROM control WHERE guild=?', guild);
        if (settings.mode === 'off' || settingsBefore.mode === 'off') {
          store.run('DELETE FROM grants WHERE guild=?', guild);
        }
      }
      log(`режим ${settings.mode}`);
      return errors.length ? `Режим наблюдения. Для активной защиты исправь:\n${errors.join('\n')}`
        : `Режим: ${modeName[settings.mode]}.`;
    }
    case 'rules': {
      const defaults = defaultSettings().rules;
      return ['Событие | включено | порог / окно | общий порог | реакция | исходный порог',
        ...eventTypes.map(type => {
          const rule = settings.rules[type];
          return `${type} | ${rule.enabled ? 'да' : 'нет'} | ${rule.limit} / ${rule.seconds} с | ${rule.global || 'выкл.'} | ${rule.reaction} | ${defaults[type].limit} / 15 с`;
        })].join('\n');
    }
    case 'rule': {
      const type = input('event');
      if (!eventTypes.includes(type)) throw new Error('Неизвестное событие. Смотри /anticrash rules.');
      const rule = settings.rules[type];
      Object.assign(rule, {
        enabled: options.getBoolean('enabled') ?? rule.enabled,
        limit: options.getInteger('limit') ?? rule.limit,
        seconds: options.getInteger('seconds') ?? rule.seconds,
        global: options.getInteger('global') ?? rule.global,
        reaction: input('reaction') ?? rule.reaction,
      });
      log(`правило ${type}: ${JSON.stringify(rule)}`);
      return `Правило ${type}: ${rule.enabled ? 'включено' : 'выключено'}, ${rule.limit} за ${rule.seconds} с, общий порог ${rule.global || 'выкл.'}, реакция ${rule.reaction}.`;
    }
    case 'manager': {
      if (actor !== server.guild.ownerId) throw new Error('Назначать администраторов защиты может только владелец сервера.');
      const target = options.getUser('user', true);
      if (target.bot) throw new Error('Для управления настройками выбери аккаунт человека.');
      const permitted = options.getBoolean('enabled', true);
      if (permitted && !await server.member(target.id, true)) throw new Error('Пользователь должен быть на сервере.');
      guard();
      const managers = new Set(settings.managers);
      if (permitted) {
        if (!managers.has(target.id)) settings.managerSince[target.id] = Date.now();
        managers.add(target.id);
      } else {
        delete settings.managerSince[target.id];
        managers.delete(target.id);
      }
      settings.managers = [...managers];
      log(`администратор ${target.id}: ${permitted ? 'назначен' : 'отозван'}`);
      return permitted ? 'Доступ выдан.' : 'Доступ отозван.';
    }
    case 'trust-list': {
      return Object.entries(settings.trust).map(([id, entry]) =>
        `${id} · ${entry.mode}${entry.limit ? ' ' + entry.limit : ''} · ${entry.actions.join(', ') || 'все'} · ${entry.expires ? timestamp(entry.expires) : 'бессрочно'} · ${entry.comment}`
        + (id.startsWith('role:') ? ' · число подтверждений: ' + store.get(`SELECT COUNT(*) AS count FROM grants
          WHERE guild=? AND role=? AND epoch=? AND valid=1`, guild, id.slice(5), settings.trustEpoch[id.slice(5)] ?? 0).count : '')
      ).join('\n') || 'Доверенных записей нет.';
    }
    case 'trust-set':
    case 'trust-remove': {
      const kind = input('kind');
      const id = requiredId(input('id'));
      const key = `${kind}:${id}`;
      if (name === 'trust-remove') {
        delete settings.trust[key];
        if (kind === 'role') delete settings.trustEpoch[id];
        log(`удалено доверие ${key}`);
        return 'Запись удалена.';
      }
      if (kind === 'role') {
        const role = await server.guild.roles.fetch(id, { force: true });
        if (!role || id === guild) throw new Error('Выбери существующую роль. @everyone исключена из доверенных ролей.');
      } else {
        const member = await server.member(id, true);
        if (!member || member.user.bot !== (kind === 'bot')) throw new Error('Тип записи должен совпадать с типом участника сервера.');
      }
      guard();
      const mode = input('mode');
      const actions = [...new Set((input('events') ?? '').split(',').map(item => item.trim()).filter(Boolean))];
      const limit = options.getInteger('limit');
      if (mode !== 'immune' && (!actions.length || actions.some(type => !eventTypes.includes(type)))) {
        throw new Error('Перечисли события из /anticrash rules через запятую.');
      }
      if (mode === 'limit' && (!limit || actions.some(type => limit < settings.rules[type].limit))) {
        throw new Error('Укажи повышенный лимит, который не ниже общего порога для каждого выбранного события.');
      }
      const now = Date.now();
      const minutes = options.getInteger('minutes') ?? 0;
      if (kind === 'role') settings.trustEpoch[id] = now;
      settings.trust[key] = { mode, actions, limit: mode === 'limit' ? limit : null,
        created: now, expires: minutes ? now + minutes * 60_000 : null, comment: input('comment') };
      log(`доверие ${key} · ${mode} · ${actions.join(', ') || 'все'} · ${input('comment')}`);
      return kind === 'role' ? 'Запись сохранена. Для существующих держателей используй /anticrash trust-confirm.'
        : 'Запись сохранена.';
    }
    case 'trust-confirm': {
      const role = options.getRole('role', true).id;
      const target = options.getUser('user');
      if (settings.mode === 'off') throw new Error('Для подтверждения сначала включи наблюдение.');
      if (!options.getBoolean('confirm', true) || !activeTrust(settings, `role:${role}`, Date.now())) throw new Error('Требуется действующая запись и явное подтверждение.');
      const members = target ? [await server.member(target.id, true)] : [...(await server.guild.members.fetch()).values()];
      guard();
      const now = Date.now();
      const eligible = members.filter(member => member?.roles.cache.has(role));
      if (!activeTrust(settings, `role:${role}`, now)) throw new Error('Срок доверенной роли истёк.');
      store.transaction(() => {
        for (const member of eligible) setGrant(store, guild, member.id, role, settings.trustEpoch[role], member.joinedTimestamp, now, true);
        store.log(guild, `Доверенная роль ${role}: оператор ${actor} подтвердил ${eligible.length} держателей.`);
      });
      return `Подтверждено участников: ${eligible.length}.`;
    }
    case 'quarantine': {
      if (settings.mode !== 'active') throw new Error('Для ручного карантина нужен активный режим.');
      const target = options.getUser('user', true).id;
      if (target === server.guild.ownerId || target === server.bot) throw new Error('Владелец сервера и сам бот исключены.');
      if (!await server.member(target, true)) throw new Error('Участник должен находиться на сервере.');
      guard();
      return store.transaction(() => {
        const at = Date.now();
        const { id } = store.incident(guild, { type: 'manual', scope: target, actor, target, at, audit: randomUUID(),
          data: { confirmed: true, reaction: 'quarantine', reason: input('reason') } }, 0);
        const q = store.queueQuarantine(guild, target, id, input('reason'), actor);
        store.run(`UPDATE quarantine SET phase='queued',due=0 WHERE id=? AND phase IN ('partial','absent')`, q);
        store.log(guild, `Инцидент #${id} · ручной карантин #${q} · оператор ${actor} · участник ${target} · ${input('reason')}`, true);
        return `Карантин #${q} поставлен в очередь. Инцидент #${id}.`;
      });
    }
    case 'retry': {
      const target = options.getUser('user', true).id;
      const row = store.getQuarantine(guild, target);
      if (!row || !['active', 'partial', 'absent'].includes(row.phase) || settings.mode !== 'active') {
        throw new Error('Для повтора нужен незакрытый карантин и активный режим.');
      }
      store.transaction(() => {
        store.saveQuarantine(row, 'queued');
        store.log(guild, `Карантин #${row.id}: повторная проверка назначена оператором ${actor}.`);
      });
      return `Карантин #${row.id} поставлен в очередь.`;
    }
    case 'quarantines': {
      return store.all(`SELECT id,member,phase,data FROM quarantine WHERE guild=? AND phase!='released'
        ORDER BY id DESC LIMIT 10 OFFSET ?`, guild, rowPage(options, 10)).map(decoded).map(row =>
        `#${row.id} · ${row.member} · ${phaseNames[row.phase]}\n${(row.data.releaseErrors ?? row.data.blocked ?? []).join('\n')}`
      ).join('\n') || 'Записей на странице нет.';
    }
    case 'release': {
      const target = options.getUser('user', true).id;
      const row = store.getQuarantine(guild, target);
      if (!row || ['queued', 'applying', 'releasing'].includes(row.phase)) throw new Error('Нет готового к снятию карантина.');
      const entries = await previewRelease(server, row);
      guard();
      if (store.getQuarantine(guild, target)?.revision !== row.revision) throw new Error('Карантин изменился. Запроси просмотр повторно.');
      const code = randomUUID();
      store.run('INSERT INTO confirmation VALUES (?,?,?,?,?)', code, guild, actor, Date.now() + 300_000,
        JSON.stringify({ id: row.id, target, revision: row.revision, entries, reason: input('reason') }));
      return [
        `Снятие карантина #${row.id} · участник ${target} · причина: ${input('reason')}`,
        ...entries.map(entry => `${entry.label} · ${entry.skip ? 'пропуск: ' + entry.skip
          : entry.dangerous ? entry.change + ' (только при dangerous:True)' : entry.change}`),
        `Подтверждение в течение 5 минут. /anticrash release-confirm code:${code}`,
      ].join('\n');
    }
    case 'release-confirm': {
      const code = input('code');
      const confirmation = decoded(store.get('SELECT * FROM confirmation WHERE id=? AND guild=? AND actor=? AND expires>?',
        code, guild, actor, Date.now()));
      if (!confirmation) throw new Error('Код недействителен или истёк. Запроси новый просмотр.');
      const { data } = confirmation;
      const row = store.getQuarantine(guild, data.target);
      if (!row || row.id !== data.id || row.revision !== data.revision) throw new Error('Карантин изменился. Запроси новый просмотр.');
      const dangerous = options.getBoolean('dangerous') === true;
      const skipped = data.entries.filter(entry => entry.skip || (entry.dangerous && !dangerous));
      row.data.releasePlan = { keys: data.entries.filter(entry => !skipped.includes(entry)).map(entry => entry.key),
        operator: actor, reason: data.reason, skipped: skipped.map(entry => `${entry.label}: ${entry.skip ?? 'опасная роль без отдельного подтверждения'}`) };
      store.transaction(() => {
        store.run('DELETE FROM confirmation WHERE id=?', code);
        store.saveQuarantine(row, 'releasing');
        store.log(guild, `Карантин #${row.id}: оператор ${actor} подтвердил снятие. Причина: ${data.reason}. Опасные роли: ${dangerous ? 'подтверждены по списку' : 'пропущены'}.`);
      });
      return `Снятие карантина #${row.id} добавлено в очередь. Пропущено изменений: ${skipped.length}.`;
    }
    case 'incidents':
      return store.all('SELECT id,kind,actor,target,last FROM incident WHERE guild=? ORDER BY id DESC LIMIT 15 OFFSET ?',
        guild, rowPage(options, 15)).map(row => `#${row.id} · ${row.kind} · ${label(row.actor, 'неизвестен')} → ${label(row.target)} · ${timestamp(row.last)}`)
        .join('\n') || 'Инцидентов на странице нет.';
    case 'incident': {
      const id = options.getInteger('id', true);
      const incident = decoded(store.get('SELECT * FROM incident WHERE guild=? AND id=?', guild, id));
      if (!incident) throw new Error('Инцидент не найден.');
      const events = store.all('SELECT * FROM incident_event WHERE incident=? ORDER BY at DESC LIMIT 80', id).map(decoded);
      const quarantines = store.all(`SELECT q.id,q.phase,q.data FROM quarantine q,json_each(q.incidents) j
        WHERE q.guild=? AND j.value=?`, guild, id).map(decoded);
      return [
        `Инцидент #${id} · ${incident.kind} · ${timestamp(incident.first)}`,
        ...events.map(item => `${timestamp(item.at)} · ${label(item.actor, 'неизвестен')} → ${label(item.target)} · ${JSON.stringify(item.data)}`),
        ...quarantines.map(row => `Карантин #${row.id} · ${phaseNames[row.phase]} · ${(row.data.blocked ?? []).join(' ')}`),
      ].join('\n');
    }
    case 'logs':
      return store.all('SELECT at,body,status,error FROM log WHERE guild=? ORDER BY id DESC LIMIT 10 OFFSET ?',
        guild, rowPage(options, 10)).map(row => `${timestamp(row.at)} [${row.status}] ${row.body}${row.error ? '\nОшибка доставки: ' + row.error : ''}`)
        .join('\n\n') || 'Записей на странице нет.';
    default:
      throw new Error('Неизвестная команда антикраша.');
  }
}

export async function handleCommand(store, server, interaction) {
  await interaction.deferReply({ flags: MessageFlags.Ephemeral });
  try {
    const settings = store.settings(interaction.guildId);
    if (!isManager(settings, server.guild.ownerId, interaction.user.id)) throw new Error(managerMessage);
    await respond(interaction, await managerAction(store, server, interaction, interaction.options.getSubcommand(), settings));
  } catch (error) {
    await respond(interaction, `Ошибка. ${error.message.slice(0, 450)}`);
  }
}
