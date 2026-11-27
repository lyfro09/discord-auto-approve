import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

const preload = `
import assert from 'node:assert/strict';
let calls = 0;
globalThis.fetch = async (url, options) => {
  assert.equal(options.headers.Authorization, 'Bot token-for-tests');
  const check = process.argv.includes('--check');
  calls++;
  if (options.method === 'PATCH') {
    assert.equal(check, false);
    assert.equal(new URL(url).pathname, '/api/v10/guilds/100/requests/200');
    assert.deepEqual(JSON.parse(options.body), {action:'APPROVED'});
    return Response.json({});
  }
  assert.equal(new URL(url).searchParams.get('status'), 'SUBMITTED');
  if (!check && calls === 1) return Response.json({retry_after:0.001}, {status:429});
  if (calls < 3) return Response.json({guild_join_requests:[{id:'200',application_status:'SUBMITTED'}]});
  return Response.json({}, {status:401});
};
process.on('exit', () => assert.equal(calls, process.argv.includes('--check') ? 1 : 4));
`;
function start(check) {
  const args = ['--import', `data:text/javascript,${encodeURIComponent(preload)}`, 'bot.mjs'];
  if (check) args.push('--check');
  return spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 8000,
    env: { ...process.env, DISCORD_BOT_TOKEN: 'token-for-tests', DISCORD_GUILD_ID: '100',
      POLL_INTERVAL_MS: '1000', ANTICRASH_ENABLED: 'false', DISCORD_JOIN_ROLE_ID: '', DISCORD_TAG_ROLE_ID: '' } });
}
test('автопринятие: действующая очередь, 429, одобрение и остановка на 401', () => {
  const result = start(false);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /Одобрена заявка 200/);
  assert.match(result.stderr, /HTTP 401/);
  assert.doesNotMatch(result.stderr, /AssertionError/);
});
test('--check: только чтение очереди', () => {
  const result = start(true);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Доступ к списку есть/);
});
