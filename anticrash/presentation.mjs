import { escapeMarkdown, PermissionsBitField } from 'discord.js';
import { isId } from './policy.mjs';

const colors = {
  info: 0x5865f2, settings: 0x4a8bc2, observe: 0x9b73df,
  alert: 0xe9a43a, quarantine: 0xe17055, success: 0x35aa88, error: 0xd65362,
};

export const modeName = { off: 'Выключена', observe: 'Наблюдение', active: 'Активная защита' };
export const eventName = {
  'channel-create': 'Создание каналов', 'channel-update': 'Изменение каналов', 'channel-delete': 'Удаление каналов',
  'category-create': 'Создание категорий', 'category-update': 'Изменение категорий', 'category-delete': 'Удаление категорий',
  'role-create': 'Создание ролей', 'role-update': 'Изменение ролей', 'role-delete': 'Удаление ролей',
  'role-permissions': 'Изменение прав роли', 'channel-permissions': 'Изменение прав канала',
  'everyone-permissions': 'Изменение прав @everyone', 'role-add': 'Выдача ролей', 'role-remove': 'Снятие ролей',
  'dangerous-role': 'Выдача опасной роли', 'role-hierarchy': 'Изменение порядка ролей',
  'trusted-role-grant': 'Выдача доверенной роли', 'trusted-role-revoke': 'Снятие доверенной роли',
  'trusted-role-edit': 'Изменение доверенной роли', ban: 'Баны участников', kick: 'Исключение участников',
  timeout: 'Тайм-ауты участников', 'bot-add': 'Добавление бота',
  'webhook-create': 'Создание вебхуков', 'webhook-update': 'Изменение вебхуков', 'webhook-delete': 'Удаление вебхуков',
  'guild-settings': 'Изменение настроек сервера', manual: 'Ручной карантин',
};
export const reactionName = {
  log: 'Запись в журнале', alert: 'Тревога', quarantine: 'Карантин',
  'would-quarantine': 'Карантин в активном режиме',
};
export const userRef = id => isId(id) ? `<@${id}>` : 'Не определён';
export const roleRef = id => isId(id) ? `<@&${id}>` : 'Не выбрана';
export const channelRef = id => isId(id) ? `<#${id}>` : 'Не выбран';
export const timestamp = at => `<t:${Math.floor(at / 1000)}:f>`;
export const literal = value => escapeMarkdown(String(value).replaceAll('<', '‹'));
export const field = (name, value, inline = true) => ({ name, value, inline });

export function targetRef(type, target, guild, entry) {
  if (!isId(target)) return 'Не определена';
  if (target === guild) return type === 'everyone-permissions' ? '`@everyone`' : 'Этот сервер';
  const nameChange = entry?.changes?.find(item => item.key === 'name');
  const name = nameChange?.new ?? nameChange?.old;
  if (type.startsWith('channel-') || type.startsWith('category-') || type === 'everyone-permissions') {
    if (type.endsWith('-delete')) {
      return name ? `**${literal(name)}**` : type === 'category-delete' ? 'Удалённая категория' : 'Удалённый канал';
    }
    return channelRef(target);
  }
  if (type.startsWith('webhook-')) return name ? `**${literal(name)}**` : 'Вебхук';
  if (type === 'role-delete') return name ? `**${literal(name)}**` : 'Удалённая роль';
  if (['role-create', 'role-update', 'role-permissions', 'role-hierarchy', 'trusted-role-edit'].includes(type)) {
    return roleRef(target);
  }
  return userRef(target);
}

const shorten = (value, size) => {
  const text = String(value);
  if (text.length <= size) return text;
  const cut = text.slice(0, size - 1);
  const lastTag = cut.lastIndexOf('<');
  return (lastTag > cut.lastIndexOf('>') ? cut.slice(0, lastTag) : cut).replace(/[\uD800-\uDBFF]$/, '') + '…';
};

function permissionList(value) {
  try {
    return new PermissionsBitField(BigInt(value)).toArray().join(', ') || 'нет';
  } catch {
    return 'недоступны';
  }
}

export function readableText(value, guild) {
  return String(value)
    .replace(/\b[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z\b/g, date => timestamp(Date.parse(date)))
    .replace(/(исполнитель|оператор|участник)[: ]+(\d{17,20})\b/gi, (_, label, id) => `${label} ${userRef(id)}`)
    .replace(/\b(user|bot|role):(\d{17,20})\b/g, (_, kind, id) => kind === 'role' ? roleRef(id) : userRef(id))
    .replace(/(в канале|логи:|канал(?: связи)?|лог|связь)[: ]+(\d{17,20})\b/gi, (_, label, id) => `${label} ${channelRef(id)}`)
    .replace(/(роль|карантин|упоминание)[: ]+(\d{17,20})\b/gi, (_, label, id) => `${label} ${roleRef(id)}`)
    .replace(/(каналах?: )([\d, ]{17,})/gi, (_, label, ids) => label + ids.split(',').map(id => channelRef(id.trim())).join(', '))
    .replace(/\b(?:allow)=(\d+), deny=(\d+)/g,
      (_, allow, deny) => `разрешить: ${permissionList(allow)}; запретить: ${permissionList(deny)}`)
    .replace(/<[@#][@&]?\d+>|\b\d{17,20}\b/g, id => {
      if (id.startsWith('<')) return id;
      if (guild?.id === id) return 'этот сервер';
      if (guild?.channels?.cache?.has(id)) return channelRef(id);
      if (guild?.roles?.cache?.has(id)) return roleRef(id);
      if (guild?.members?.cache?.has(id)) return userRef(id);
      return 'объект недоступен';
    });
}

export function cardText(card) {
  return [card.title, card.description, ...(card.fields ?? []).map(item => `${item.name}: ${item.value}`),
    card.footer].filter(Boolean).join('\n');
}

export function logCard(row, guild) {
  if (row.presentation) return JSON.parse(row.presentation);
  const title = row.body.startsWith('Инцидент #') ? 'Инцидент'
    : row.body.startsWith('Карантин #') ? 'Карантин' : 'Журнал антикраша';
  return { title, description: readableText(row.body, guild), tone: row.urgent ? 'alert' : 'info', at: row.at };
}

export function embedFor(card) {
  const embed = { title: shorten(card.title, 240), color: colors[card.tone] ?? colors.info };
  if (card.description) embed.description = shorten(card.description, 3900);
  if (card.footer) embed.footer = { text: shorten(card.footer, 180) };
  if (Number.isFinite(card.at)) embed.timestamp = new Date(card.at).toISOString();
  let remaining = 5900 - embed.title.length - (embed.description?.length ?? 0) - (embed.footer?.text.length ?? 0);
  const fields = [];
  for (const item of (card.fields ?? []).slice(0, 25)) {
    if (item.value == null || item.value === '') continue;
    const name = shorten(item.name, 240);
    if (remaining <= name.length + 8) break;
    const value = shorten(item.value, Math.min(1000, remaining - name.length));
    fields.push({ name, value, inline: item.inline ?? true });
    remaining -= name.length + value.length;
  }
  if (fields.length) embed.fields = fields;
  return embed;
}

export function logMessage(card, role, withEmbed) {
  const mention = isId(role) ? roleRef(role) : '';
  const allowedMentions = { parse: [], roles: mention ? [role] : [] };
  return withEmbed
    ? { ...(mention && { content: mention }), embeds: [embedFor(card)], allowedMentions }
    : { content: shorten([mention, cardText(card)].filter(Boolean).join('\n'), 2000), allowedMentions };
}
