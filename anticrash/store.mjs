import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { defaultSettings } from './policy.mjs';
import { cardText } from './presentation.mjs';

const migrations = [`
  CREATE TABLE settings (guild TEXT PRIMARY KEY, data TEXT NOT NULL);
  CREATE TABLE control (guild TEXT PRIMARY KEY, cursor TEXT NOT NULL);
  CREATE TABLE audit (guild TEXT NOT NULL, id TEXT NOT NULL, at INTEGER NOT NULL,
    action INTEGER NOT NULL, target TEXT, actor TEXT, data TEXT NOT NULL, PRIMARY KEY(guild,id));
  CREATE INDEX audit_match ON audit(guild,action,target,at);
  CREATE TABLE observations (guild TEXT NOT NULL, id TEXT NOT NULL, at INTEGER NOT NULL,
    target TEXT NOT NULL, data TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(guild,id));
  CREATE INDEX observations_due ON observations(guild,done,at);
  CREATE TABLE events (guild TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL, actor TEXT,
    target TEXT, at INTEGER NOT NULL, weight INTEGER NOT NULL, exempt INTEGER NOT NULL,
    PRIMARY KEY(guild,id,kind));
  CREATE INDEX events_window ON events(guild,kind,at,actor);
  CREATE TABLE incident (id INTEGER PRIMARY KEY, guild TEXT NOT NULL, kind TEXT NOT NULL, scope TEXT NOT NULL,
    actor TEXT, target TEXT, first INTEGER NOT NULL, last INTEGER NOT NULL, data TEXT NOT NULL);
  CREATE INDEX incident_lookup ON incident(guild,kind,scope,last);
  CREATE TABLE incident_event (incident INTEGER NOT NULL REFERENCES incident(id), audit TEXT NOT NULL,
    at INTEGER NOT NULL, actor TEXT, target TEXT, data TEXT NOT NULL, PRIMARY KEY(incident,audit));
  CREATE TABLE log (id INTEGER PRIMARY KEY, guild TEXT NOT NULL, at INTEGER NOT NULL,
    body TEXT NOT NULL, urgent INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
    attempts INTEGER NOT NULL DEFAULT 0, due INTEGER NOT NULL DEFAULT 0, error TEXT);
  CREATE INDEX log_due ON log(guild,status,due);
  CREATE TABLE grants (guild TEXT NOT NULL, member TEXT NOT NULL, role TEXT NOT NULL,
    epoch INTEGER NOT NULL, joined INTEGER NOT NULL, at INTEGER NOT NULL,
    valid INTEGER NOT NULL, PRIMARY KEY(guild,member,role));
  CREATE TABLE quarantine (id INTEGER PRIMARY KEY, guild TEXT NOT NULL, member TEXT NOT NULL, at INTEGER NOT NULL,
    incidents TEXT NOT NULL, reason TEXT NOT NULL, operator TEXT, phase TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL, due INTEGER NOT NULL DEFAULT 0);
  CREATE UNIQUE INDEX quarantine_open ON quarantine(guild,member) WHERE phase != 'released';
  CREATE INDEX quarantine_work ON quarantine(guild,phase,due);
  CREATE TABLE expected (guild TEXT NOT NULL, reason TEXT NOT NULL, action INTEGER NOT NULL,
    target TEXT NOT NULL, kind TEXT, subject TEXT, at INTEGER NOT NULL, PRIMARY KEY(guild,reason));
  CREATE TABLE confirmation (id TEXT PRIMARY KEY, guild TEXT NOT NULL, actor TEXT NOT NULL,
    expires INTEGER NOT NULL, data TEXT NOT NULL);
`, `ALTER TABLE log ADD COLUMN presentation TEXT;`, `
  CREATE TABLE join_role_queue (
    guild TEXT NOT NULL, member TEXT NOT NULL, joined INTEGER NOT NULL, due INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, done INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(guild,member)
  );
  CREATE INDEX join_role_due ON join_role_queue(guild,done,due);
`, `
  CREATE TABLE tag_role_queue (
    guild TEXT NOT NULL, member TEXT NOT NULL, joined INTEGER NOT NULL, due INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, done INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(guild,member)
  );
  CREATE INDEX tag_role_due ON tag_role_queue(guild,done,due);
`, `
  CREATE TABLE tag_role_scan (
    guild TEXT NOT NULL, role TEXT NOT NULL, cursor TEXT NOT NULL, done INTEGER NOT NULL,
    PRIMARY KEY(guild,role)
  );
`];

const encode = JSON.stringify;
const parse = JSON.parse;
export const decoded = row => row && { ...row, data: parse(row.data) };

export class Store {
  constructor(path) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000');
    const version = this.db.prepare('PRAGMA user_version').get().user_version;
    if (version > migrations.length) throw new Error('База антикраша создана более новой версией бота.');
    for (let index = version; index < migrations.length; index++) {
      this.transaction(() => this.db.exec(`${migrations[index]} PRAGMA user_version=${index + 1}`));
    }
  }

  run(sql, ...args) { return this.db.prepare(sql).run(...args); }
  get(sql, ...args) { return this.db.prepare(sql).get(...args); }
  all(sql, ...args) { return this.db.prepare(sql).all(...args); }
  close() { this.db.close(); }

  transaction(callback) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = callback();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  settings(guild) {
    const data = this.get('SELECT data FROM settings WHERE guild = ?', guild)?.data;
    const defaults = defaultSettings();
    if (!data) return defaults;
    const saved = parse(data);
    const rules = Object.fromEntries(Object.entries(defaults.rules).map(([key, value]) => [
      key, { ...value, ...saved.rules?.[key] },
    ]));
    return { ...defaults, ...saved, rules };
  }

  saveSettings(guild, settings) {
    this.run('INSERT INTO settings VALUES (?,?) ON CONFLICT(guild) DO UPDATE SET data=excluded.data',
      guild, encode(settings));
  }

  log(guild, entry, urgent = false) {
    const at = Date.now();
    const card = typeof entry === 'string' ? null : { at, ...entry };
    const summary = card ? cardText(card) : entry;
    this.run('INSERT INTO log (guild,at,body,urgent,presentation) VALUES (?,?,?,?,?)',
      guild, at, summary.slice(0, 1850), Number(urgent), card ? encode(card) : null);
  }

  incident(guild, { type, scope, actor, target, at, audit, data }, window) {
    let current = this.get(`SELECT id FROM incident WHERE guild=? AND kind=? AND scope=? AND last>=?
      ORDER BY last DESC LIMIT 1`, guild, type, scope, at - window);
    const first = !current;
    if (first) {
      const { lastInsertRowid: id } = this.run(`INSERT INTO incident
        (guild,kind,scope,actor,target,first,last,data) VALUES (?,?,?,?,?,?,?,?)`,
      guild, type, scope, actor, target, at, at, encode(data));
      current = { id };
    } else {
      this.run('UPDATE incident SET last=MAX(last,?), target=?, data=? WHERE id=?',
        at, target, encode(data), current.id);
    }
    this.run('INSERT OR IGNORE INTO incident_event VALUES (?,?,?,?,?,?)',
      current.id, audit, at, actor, target, encode(data));
    return { id: current.id, first };
  }

  getQuarantine(guild, member) {
    return decoded(this.get(`SELECT * FROM quarantine WHERE guild=? AND member=? AND phase!='released'`, guild, member));
  }

  queueQuarantine(guild, member, incident, reason, operator = null) {
    const row = this.getQuarantine(guild, member);
    if (row) {
      const incidents = [...new Set([...parse(row.incidents), incident])];
      this.run('UPDATE quarantine SET incidents=? WHERE id=?', encode(incidents), row.id);
      return row.id;
    }
    return this.run(`INSERT INTO quarantine (guild,member,at,incidents,reason,operator,phase,data)
      VALUES (?,?,?,?,?,?,'queued','{}')`, guild, member, Date.now(), encode([incident]), reason, operator).lastInsertRowid;
  }

  saveQuarantine(row, phase = row.phase, due = 0) {
    row.phase = phase;
    row.revision++;
    this.run('UPDATE quarantine SET phase=?,data=?,revision=?,due=? WHERE id=?',
      phase, encode(row.data), row.revision, due, row.id);
  }
}
