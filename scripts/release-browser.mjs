import {execFileSync} from 'node:child_process';
import {writeFileSync} from 'node:fs';
const git = (...args) => execFileSync('git', args, {encoding: 'utf8'}).trim();
if (process.env.WORKERS_CI !== '1' || process.env.CI !== 'true' || process.env.WORKERS_CI_BRANCH !== 'main') throw new Error('Production publication requires Cloudflare Workers Builds on main.');
const sha = git('rev-parse', 'HEAD');
if (!/^[a-f0-9]{40}$/.test(sha) || sha !== process.env.WORKERS_CI_COMMIT_SHA || git('status', '--porcelain')) throw new Error('Build must be the exact clean CI commit.');
const remote = git('ls-remote', 'origin', 'refs/heads/main').split(/\s/)[0];
if (sha !== remote) throw new Error('Build is no longer current main.');
const wrangler = (...args) => execFileSync('node', ['node_modules/wrangler/bin/wrangler.js', ...args], {encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe']});
// Empty deployments are the explicit rollback state for the first publication.
const before = wrangler('deployments', 'list', '--json');
writeFileSync('/tmp/scanner-rollback.json', before, {mode: 0o600});
console.log('Scanner rollback inventory: ' + before);
execFileSync('node', ['node_modules/wrangler/bin/wrangler.js', 'deploy', '--message', 'scanner main ' + sha], {stdio: 'inherit'});
const health = await fetch('https://scanner.mithril.fund/build.json', {cache: 'no-store'});
if (!health.ok || (await health.json()).sha !== sha) throw new Error('Published build does not match current main.');
const session = await fetch('https://scanner.mithril.fund/api/session');
if (session.status !== 401) throw new Error('Anonymous session smoke failed.');
console.log('Scanner published and anonymous smoke verified: ' + sha);
