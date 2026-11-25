// Mock tests for the abuse.ch pack — no network, no app.
//   Run: node test-plugin.mjs [bundle]      (and node test/pure.test.mjs for the pure modules)
//
// Response shapes are MEASURED against the live APIs on 2026-11-14 and trimmed to what the plugins
// read. The Auth-Key here is a placeholder: a real key never comes near this file.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const pack = (await import(process.argv[2] ? pathToFileURL(resolve(process.argv[2])).href : './dist/pack.mjs')).default;
const P = Object.fromEntries(pack.plugins.map((p) => [p.manifest.identifier.replace('run.vineyard.plugins.abusech_', ''), p]));

const ok = [];
const fail = [];
const check = (name, cond) => (cond ? ok : fail).push(name);

const KEY = { auth_key: '  test-key-not-real  ' };
const RUN = { run: { platform: 'desktop' }, signal: new AbortController().signal };

/** `refuse(type, data)`: a reason the project's type refuses the node, as the host throws it. */
function makeGraph(nodeById, refuse = () => null) {
    const createdNodes = [];
    const createdEdges = [];
    const updates = [];
    return {
        createdNodes,
        createdEdges,
        updates,
        async get(id) {
            return nodeById[id] || null;
        },
        async list(o) {
            const all = Object.values(nodeById);
            return { nodes: o?.type ? all.filter((n) => n.type === o.type) : all };
        },
        // Mirrors the host's de-dup closely enough for these tests: same type and identity value → same node.
        async createNode(d) {
            const why = refuse(d.type, d.data);
            if (why) throw new Error(why);
            const idKey = { 'threat.indicator': 'value', 'threat.malware': 'name', 'threat.tool': 'name', 'threat.file_hash': 'sha256', 'web.url': 'url', 'infrastructure.ip_address': 'ip_address', 'infrastructure.domain': 'domain_name' }[d.type];
            const existing = idKey && [...Object.values(nodeById), ...createdNodes].find((n) => n.type === d.type && n.data?.[idKey] === d.data?.[idKey]);
            if (existing) return existing;
            const n = { id: `n${createdNodes.length + 1}`, type: d.type, data: d.data };
            createdNodes.push(n);
            return n;
        },
        async updateNode(id, data) {
            updates.push({ id, data });
        },
        async createEdge(e) {
            createdEdges.push(e);
        },
    };
}

/** respond(url, body, headers) → { status, body } (body an object, serialised) or { status, text }. */
function makeNet(respond) {
    const calls = [];
    return {
        calls,
        async fetch(url, init) {
            const body = init?.body ?? '';
            const parsed = init?.headers?.['Content-Type'] === 'application/json' ? JSON.parse(body || '{}') : Object.fromEntries(new URLSearchParams(body));
            calls.push({ url, method: init?.method, headers: init?.headers ?? {}, body: parsed });
            const r = respond(url, parsed);
            const text = r.text ?? JSON.stringify(r.body ?? {});
            return { ok: r.status >= 200 && r.status < 300, status: r.status, headers: r.headers ?? {}, async text() { return text; }, async json() { return JSON.parse(text); } };
        },
    };
}
const ctxFor = ({ nodes = {}, selection = Object.keys(nodes), respond = () => ({ status: 500 }), config = KEY, params = {}, platform = 'desktop', refuse }) => {
    const graph = makeGraph(nodes, refuse);
    const net = makeNet(respond);
    const logs = [];
    const ctx = { ...RUN, run: { platform }, config, params, input: { selection }, graph, net, progress: { set() {}, log: (m) => logs.push(m) } };
    return { ctx, graph, net, logs };
};
const run = async (p, t) => {
    try {
        return await p.run(t.ctx);
    } catch (e) {
        return { error: e };
    }
};

const SHA256 = 'e16c04b0b497809f4d29765af0363feebaef76cfccb0fbdedb20cc759c0ed08d';
const MD5 = 'b61b0c762572a08eb5d216a210782cf8';
const SHA1 = 'cfbe6316f31a8f983e3bc79e323101bad73dc15e';
const fileNode = (data) => ({ id: 'f1', type: 'threat.file_hash', data });

// ================================================================ manifests
{
    const json = JSON.parse(readFileSync(join(here, 'plugins', 'abusech.manifest.json'), 'utf8'));
    const stable = (v) => JSON.stringify(v, (_k, x) => (x && typeof x === 'object' && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x));
    check('manifest: generated from this bundle (run gen-manifest.mjs)', stable(json) === stable({ ...pack, plugins: pack.plugins.map((p) => p.manifest) }));
    check('pack identifier ends in [a-z0-9_]+', /^run\.vineyard\.pluginpacks\.[a-z0-9_]+$/.test(pack.identifier));
    check('pack summary fits the card (≤250)', pack.summary.length <= 250);
    // The pack-page rules (2026-11-09): about 400 to 1,500 characters, and nothing about Vineyard
    // itself, a type-pack version included. The first draft of this page was 2,669 characters and
    // named "Infrastructure type pack 4.2.0"; the registry only checks the 16,000 limit.
    check(`pack page within the page rules (${pack.description.length} ≤ 1500, no type-pack talk)`, pack.description.length <= 1500 && !/type pack|typepack|malware_type|max_items|max_records/i.test(pack.description));
    const origins = (m) => [...new Set(m.scopes.network.map((n) => new URL(n.endpoint).origin))].sort().join(' ');
    for (const p of pack.plugins) {
        const m = p.manifest;
        check(`${m.name}: identifier ends in [a-z0-9_]+`, /^run\.vineyard\.plugins\.[a-z0-9_]+$/.test(m.identifier));
        check(`${m.name}: desktop is primary`, m.platforms.primary === 'desktop');
        check(`${m.name}: entry is the bundle`, m.platforms.web.entry === 'dist/pack.mjs' && m.platforms.desktop.entry === 'dist/pack.mjs');
        check(`${m.name}: version matches the pack`, m.version === pack.version);
        check(`${m.name}: the Auth-Key is a secret setting`, m.scopes.config.length === 1 && m.scopes.config[0].key === 'auth_key' && m.scopes.config[0].secret === true);
        // The app files settings by the set of origins a member calls: the same set everywhere is
        // what makes the one abuse.ch key a single entry instead of four.
        check(`${m.name}: same network origins as every other member`, origins(m) === origins(pack.plugins[0].manifest));
        check(`${m.name}: writes iff it produces`, (m.io.produces.length > 0) === m.scopes.graph.includes('node:create'));
        check(`${m.name}: description fits (≤1024)`, m.description.length <= 1024);
    }
    check('only SSLBL works without a key', pack.plugins.filter((p) => p.manifest.scopes.config[0].optional).map((p) => p.manifest.name).join() === 'SSLBL Certificate Check');
}

// ================================================================ no key ships with the pack
// abuse.ch keys are 48 hex characters. A 64-hex hash fixture cannot match: \b needs a non-hex
// neighbour on both sides. With ABUSECH_AUTH_KEY set (the live test's variable), the exact value is
// looked for too, and never printed.
{
    const files = [];
    const walk = (d) => {
        for (const f of readdirSync(d)) {
            if (f === 'node_modules' || f === '.git') continue;
            const p = join(d, f);
            if (statSync(p).isDirectory()) walk(p);
            else files.push(p);
        }
    };
    walk(here);
    const live = (process.env.ABUSECH_AUTH_KEY ?? '').trim();
    const hits = files.filter((f) => {
        const s = readFileSync(f, 'utf8');
        return /\b[0-9a-f]{48}\b/i.test(s) || (live && s.includes(live));
    });
    check(`no Auth-Key-shaped value in ${files.length} file(s)${live ? ' (and not the live key)' : ''}`, hits.length === 0);
    if (hits.length) console.log('  key-shaped value in:', hits.map((f) => f.slice(here.length)).join(', '));
}

// ================================================================ refusals before any request
for (const p of pack.plugins) {
    const t = ctxFor({ nodes: { f1: fileNode({ sha256: SHA256 }), c1: { id: 'c1', type: 'infrastructure.certificate', data: { fingerprint_sha256: 'a'.repeat(64), fingerprint_sha1: SHA1 } } }, platform: 'web', respond: () => ({ status: 200, body: {} }) });
    const r = await run(p, t);
    check(`${p.manifest.name}: web refuses with the CORS reason, before any request`, r.error && /desktop app/.test(r.error.message) && t.net.calls.length === 0);
}
for (const name of ['malwarebazaar', 'threatfox', 'urlhaus']) {
    const t = ctxFor({ nodes: { f1: fileNode({ sha256: SHA256 }) }, config: {}, respond: () => ({ status: 200, body: {} }) });
    const r = await run(P[name], t);
    check(`${name}: no key → names the Auth-Key, no request`, r.error && /Auth-Key is not set/.test(r.error.message) && t.net.calls.length === 0);
}

// ================================================================ MalwareBazaar
// get_info for a DCRat sample, trimmed (2026-11-14).
const mbRecord = {
    sha256_hash: SHA256,
    sha1_hash: SHA1,
    md5_hash: MD5,
    first_seen: '2026-11-06 13:55:15',
    last_seen: null,
    file_name: 'payload.exe',
    file_size: 912384,
    file_type: 'exe',
    reporter: 'abuse_ch',
    origin_country: 'NL',
    signature: 'DCRat',
    imphash: 'f34d5f2d4577ed6d9ceec516c1f5a744',
    tlsh: 'T1A5963318FDF12EA2E5AC297A6F1EB52D8A20EF7DC16226161D3DC42B29147CD41333E5',
    ssdeep: '12288:abc:def',
    tags: ['DCRat', 'exe', 'RAT'],
    yara_rules: [{ rule_name: 'DCRat_rule' }, { rule_name: 'exploit_any_poppopret' }],
};
{
    const t = ctxFor({
        nodes: { f1: fileNode({ md5: MD5, sha256: '', first_seen: '2026-11-10T00:00:00Z' }) },
        respond: () => ({ status: 200, body: { query_status: 'ok', data: [mbRecord] } }),
    });
    const r = await P.malwarebazaar.run(t.ctx);
    const call = t.net.calls[0];
    check('mb: POST form to mb-api with the trimmed key in Auth-Key', call.url === 'https://mb-api.abuse.ch/api/v1/' && call.method === 'POST' && call.headers['Auth-Key'] === 'test-key-not-real' && call.body.query === 'get_info');
    check('mb: looks up the strongest hash the node has', call.body.hash === MD5);
    check('mb: the key is never in a URL', t.net.calls.every((c) => !c.url.includes('test-key')));
    const u = t.graph.updates[0]?.data ?? {};
    check('mb: the missing SHA-256 and SHA-1 are filled', u.sha256 === SHA256 && u.sha1 === SHA1 && !('md5' in u));
    check('mb: size filled from file_size', u.size === 912384);
    // first_seen is the scanner's (VirusTotal writes it on every report, over any value): writing
    // MalwareBazaar's earlier one would make the field change back and forth on alternate runs.
    check("mb: first_seen is left to the scanner that wrote it; MalwareBazaar's is mb_first_seen", !('first_seen' in u) && u.mb_first_seen === '2026-11-06T13:55:15Z');
    check('mb: MalwareBazaar view under mb_', u.mb_signature === 'DCRat' && u.mb_tags === 'DCRat, exe, RAT' && u.mb_reporter === 'abuse_ch' && u.mb_yara === 'DCRat_rule, exploit_any_poppopret');
    check('mb: VirusTotal-vocabulary fields are left alone', !('tags' in u) && !('type_description' in u));
    check('mb: sample page link', u.mb_url === `https://bazaar.abuse.ch/sample/${SHA256}/`);
    const famNode = t.graph.createdNodes.find((n) => n.type === 'threat.malware');
    check("mb: DCRat lands on IP Classification's DcRAT, a RAT", famNode?.data.name === 'DcRAT' && famNode.data.malware_type === 'rat' && famNode.data.is_family === true);
    check("mb: linked 'classified as'", t.graph.createdEdges.some((e) => e.from === 'f1' && e.to === famNode?.id && e.label === 'classified as'));
    check('mb: a table family needs no malware list', t.net.calls.length === 1);
    check('mb: summary', /1 of 1 file\(s\) found/.test(r.summary) && r.counts.families === 1);
}
{
    // A first_seen already earlier than MalwareBazaar's stays.
    const t = ctxFor({ nodes: { f1: fileNode({ sha256: SHA256, sha1: SHA1, md5: MD5, size: 1, first_seen: '2020-01-01T00:00:00Z' }) }, respond: () => ({ status: 200, body: { query_status: 'ok', data: [{ ...mbRecord, signature: null }] } }) });
    await P.malwarebazaar.run(t.ctx);
    const u = t.graph.updates[0]?.data ?? {};
    check('mb: an earlier first_seen is kept; present hashes and size are not rewritten', !('first_seen' in u) && !('sha256' in u) && !('size' in u) && u.mb_first_seen === '2026-11-06T13:55:15Z');
    check('mb: no signature, no family', t.graph.createdNodes.length === 0 && t.graph.createdEdges.length === 0);
}
{
    // A family the project already has is linked as it stands — nothing written to it.
    const existing = { id: 'm1', type: 'threat.malware', data: { name: 'Agent Tesla', malware_type: 'stealer' } };
    const t = ctxFor({
        nodes: { f1: fileNode({ sha256: SHA256 }), m1: existing },
        selection: ['f1'],
        respond: (url, body) =>
            url.includes('threatfox')
                ? { status: 200, body: { query_status: 'ok', data: { 'win.agent_tesla': { malware_printable: 'Agent Tesla', malware_alias: 'AgenTesla,AgentTesla,Negasteal' } } } }
                : { status: 200, body: { query_status: 'ok', data: [{ ...mbRecord, signature: 'AgentTesla' }] } },
    });
    await P.malwarebazaar.run(t.ctx);
    const tf = t.net.calls.find((c) => c.url.includes('threatfox'));
    check('mb: a name outside the table fetches the ThreatFox malware list once', tf?.body.query === 'malware_list' && t.net.calls.filter((c) => c.url.includes('threatfox')).length === 1);
    check("mb: AgentTesla → ThreatFox's Agent Tesla, the existing node", t.graph.createdEdges.some((e) => e.to === 'm1' && e.label === 'classified as'));
    check('mb: the existing family is not re-created or overwritten', !t.graph.createdNodes.some((n) => n.type === 'threat.malware') && !t.graph.updates.some((u) => u.id === 'm1'));
}
{
    const t = ctxFor({ nodes: { f1: fileNode({ sha256: SHA256 }) }, respond: () => ({ status: 200, body: { query_status: 'hash_not_found' } }) });
    const r = await P.malwarebazaar.run(t.ctx);
    check('mb: hash_not_found is a real negative, nothing written', /not in MalwareBazaar — a real negative/.test(r.summary) && t.graph.updates.length === 0);
}
{
    const t = ctxFor({ nodes: { f1: fileNode({ sha256: SHA256 }) }, respond: () => ({ status: 403, body: { query_status: 'unknown_auth_key' } }) });
    const r = await run(P.malwarebazaar, t);
    check('mb: a rejected key fails the run and says where to check it', r.error && /does not recognise this abuse\.ch Auth-Key/.test(r.error.message) && /auth\.abuse\.ch/.test(r.error.message));
}
{
    // Rate limit after something was found: keep it, stop, say what was not reached.
    let n = 0;
    const t = ctxFor({
        nodes: { f1: fileNode({ sha256: SHA256 }), f2: { id: 'f2', type: 'threat.file_hash', data: { sha256: 'b'.repeat(64) } } },
        respond: () => (n++ === 0 ? { status: 200, body: { query_status: 'ok', data: [{ ...mbRecord, signature: null }] } } : { status: 429, headers: { 'retry-after': '0.001' } }),
    });
    const r = await run(P.malwarebazaar, t);
    check('mb: 429 retried three times, then the run stops and keeps what it found', !r.error && /STOPPED: mb-api\.abuse\.ch kept refusing/.test(r.summary) && /1 selected node\(s\) were not looked up/.test(r.summary) && t.net.calls.length === 5);
    let m = 0;
    const t2 = ctxFor({ nodes: { f1: fileNode({ sha256: SHA256 }) }, respond: () => (m++, { status: 429, headers: { 'retry-after': '0.001' } }) });
    const r2 = await run(P.malwarebazaar, t2);
    check('mb: 429 with nothing found fails the run instead', r2.error && /HTTP 429/.test(r2.error.message));
}

// ================================================================ ThreatFox
const tfRec = (o) => ({
    id: '2028595',
    ioc: '1.2.3.4:443',
    threat_type: 'botnet_cc',
    threat_type_desc: 'Indicator that identifies a botnet command&control server (C&C)',
    ioc_type: 'ip:port',
    ioc_type_desc: 'ip:port combination that is used for botnet Command&control (C&C)',
    malware: 'win.cobalt_strike',
    malware_printable: 'Cobalt Strike',
    malware_alias: 'Agentemis,BEACON,CobaltStrike,cobeacon',
    confidence_level: 75,
    first_seen: '2026-11-14 10:05:06 UTC',
    last_seen: null,
    reference: null,
    reporter: 'anonymous',
    tags: ['CobaltStrike'],
    ...o,
});
{
    const records = [
        tfRec({}),
        tfRec({ id: '2028600', confidence_level: 100, first_seen: '2026-11-01 00:00:00 UTC', reporter: 'crep1x' }), // same IOC, second record
        tfRec({ id: '2028601', ioc: '1.2.3.4:8443', malware: 'win.dcrat', malware_printable: 'DCRat', malware_alias: 'DarkCrystal RAT' }),
        tfRec({ id: '2028602', ioc: '11.2.3.45:80' }), // substring near-miss
        tfRec({ id: '2028603', ioc: '1.2.3.4:9000', malware: 'unknown_loader', malware_printable: 'Unknown Loader', malware_alias: null }),
    ];
    const t = ctxFor({ nodes: { ip1: { id: 'ip1', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } } }, respond: () => ({ status: 200, body: { query_status: 'ok', data: records } }) });
    const r = await P.threatfox.run(t.ctx);
    const call = t.net.calls[0];
    check('tf: JSON POST, an IP searched loosely (its IOC carries a port)', call.url === 'https://threatfox-api.abuse.ch/api/v1/' && call.body.query === 'search_ioc' && call.body.search_term === '1.2.3.4' && !call.body.exact_match);
    const inds = t.graph.createdNodes.filter((n) => n.type === 'threat.indicator');
    check('tf: one indicator per IOC, the near-miss left out', inds.map((n) => n.data.value).sort().join() === '1.2.3.4:443,1.2.3.4:8443,1.2.3.4:9000');
    const i443 = inds.find((n) => n.data.value === '1.2.3.4:443');
    check('tf: two records of one IOC are folded (earliest first seen, highest confidence, both ids)', i443?.data.valid_from === '2026-11-01T00:00:00Z' && i443.data.threatfox_confidence === 100 && i443.data.threatfox_id === '2028595, 2028600' && i443.data.threatfox_reporter === 'anonymous, crep1x');
    check("tf: ThreatFox's confidence is not written as the analyst's", !('confidence' in (i443?.data ?? {})));
    check('tf: indicator type and IOC page', i443?.data.indicator_type === 'ipv4' && /threatfox\.abuse\.ch\/ioc\/2028595\//.test(i443.data.threatfox_url));
    // threat.indicator's own description: link it to the node it identifies "with the refers_to edge".
    check('tf: each indicator refers_to the IP, as the Threat type pack prescribes', inds.every((n) => t.graph.createdEdges.some((e) => e.from === n.id && e.to === 'ip1' && e.label === 'refers_to' && e.data?.source === 'threatfox')));
    check("tf: no edge of the pack's own wording in place of refers_to", !t.graph.createdEdges.some((e) => e.label === 'listed in ThreatFox as'));
    const cs = t.graph.createdNodes.find((n) => n.data.name === 'Cobalt Strike');
    check('tf: Cobalt Strike is a Tool (c2), as IP Classification writes it', cs?.type === 'threat.tool' && cs.data.tool_type === 'c2');
    check("tf: DCRat → DcRAT", t.graph.createdNodes.some((n) => n.type === 'threat.malware' && n.data.name === 'DcRAT'));
    check("tf: indicator → family 'indicates'", t.graph.createdEdges.some((e) => e.from === i443?.id && e.to === cs?.id && e.label === 'indicates'));
    check("tf: 'Unknown Loader' makes no family node", !t.graph.createdNodes.some((n) => /unknown/i.test(String(n.data.name ?? ''))) && /name no family/.test(r.summary));
    check('tf: summary', /1 of 1 node\(s\) listed in ThreatFox, 3 indicator\(s\)/.test(r.summary));
}
{
    // Domain: exact search, and a subdomain record (what the loose search would add) is not this domain.
    const t = ctxFor({
        nodes: { d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'ApiJ4ya.org' } } },
        respond: () => ({ status: 200, body: { query_status: 'ok', data: [tfRec({ ioc: 'apij4ya.org', ioc_type: 'domain', malware: 'win.vidar', malware_printable: 'Vidar', malware_alias: null }), tfRec({ id: '9', ioc: 'hl.apij4ya.org', ioc_type: 'domain' })] } }),
    });
    await P.threatfox.run(t.ctx);
    check('tf: a domain is searched exactly, lowercased', t.net.calls[0].body.exact_match === true && t.net.calls[0].body.search_term === 'apij4ya.org');
    check('tf: a subdomain record is not the domain', t.graph.createdNodes.filter((n) => n.type === 'threat.indicator').map((n) => n.data.value).join() === 'apij4ya.org');
    check('tf: a family outside the table is a Malware, type unknown', t.graph.createdNodes.some((n) => n.type === 'threat.malware' && n.data.name === 'Vidar' && n.data.malware_type === 'unknown'));
}
{
    // A Domain under an internationalised TLD is searched, in punycode, and a record in either
    // spelling is its own. Infrastructure 4.3 takes such names; the copied 4.2 rule skipped them.
    const t = ctxFor({
        nodes: { d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'пример.рф' } } },
        respond: () => ({ status: 200, body: { query_status: 'ok', data: [tfRec({ ioc: 'xn--e1afmkfd.xn--p1ai', ioc_type: 'domain' })] } }),
    });
    const r = await P.threatfox.run(t.ctx);
    check('tf: an internationalised Domain is searched exactly, in punycode', t.net.calls[0]?.body.search_term === 'xn--e1afmkfd.xn--p1ai' && t.net.calls[0].body.exact_match === true);
    check('tf: …and its punycode record refers_to it', t.graph.createdEdges.some((e) => e.to === 'd1' && e.label === 'refers_to') && /1 of 1 node\(s\) listed/.test(r.summary) && !/skipped/.test(r.summary));
}
{
    // A neighbour IOC under an internationalised TLD becomes a Domain; a project on Infrastructure
    // 4.2 refuses it, and the run goes on with the indicator holding the value.
    const respond = (url, b) =>
        b.query === 'search_hash'
            ? { status: 200, body: { query_status: 'ok', data: [tfRec({ id: '78', ioc: 'c2.example.xn--p1ai', ioc_type: 'domain' }), tfRec({ id: '77', ioc: '5.6.7.8:443' })] } }
            : { status: 200, body: { query_status: 'no_result', data: 'Your search did not yield any results' } };
    const now = ctxFor({ nodes: { f1: fileNode({ sha256: SHA256 }) }, respond });
    await P.threatfox.run(now.ctx);
    check('tf: a neighbour domain under an internationalised TLD becomes a Domain', now.graph.createdNodes.some((n) => n.type === 'infrastructure.domain' && n.data.domain_name === 'c2.example.xn--p1ai'));
    const v42 = /^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$/;
    const old = ctxFor({ nodes: { f1: fileNode({ sha256: SHA256 }) }, respond, refuse: (type, d) => (type === 'infrastructure.domain' && !v42.test(d.domain_name) ? `infrastructure.domain: domain_name does not match: ${d.domain_name}` : null) });
    const r = await P.threatfox.run(old.ctx);
    check('tf: on a project that refuses it, the run goes on', !r.error && old.graph.createdNodes.some((n) => n.type === 'infrastructure.ip_address') && !old.graph.createdNodes.some((n) => n.type === 'infrastructure.domain'));
    check('tf: …the indicator keeps the value, and the summary says why there is no Domain', old.graph.createdNodes.some((n) => n.type === 'threat.indicator' && n.data.value === 'c2.example.xn--p1ai') && /1 indicator value\(s\) this project's types refuse kept on the indicator only/.test(r.summary));
}
{
    // File hash: its own hash IOCs, and the C2 the sample is tied to.
    const t = ctxFor({
        nodes: { f1: fileNode({ sha256: SHA256, md5: MD5 }) },
        respond: (url, b) => {
            if (b.query === 'search_hash') {
                return { status: 200, body: { query_status: 'ok', data: [tfRec({ id: '77', ioc: '5.6.7.8:443' }), tfRec({ id: '78', ioc: 'c2.example.net', ioc_type: 'domain' }), tfRec({ id: '79', ioc: 'a'.repeat(32), ioc_type: 'md5_hash' }), tfRec({ id: '80', ioc: MD5.toUpperCase(), ioc_type: 'md5_hash' })] } };
            }
            if (b.search_term === SHA256) return { status: 200, body: { query_status: 'ok', data: [tfRec({ id: '70', ioc: SHA256, ioc_type: 'sha256_hash', threat_type: 'payload' })] } };
            return { status: 200, body: { query_status: 'no_result', data: 'Your search did not yield any results' } };
        },
    });
    const r = await P.threatfox.run(t.ctx);
    const terms = t.net.calls.map((c) => c.body.search_term ?? `hash:${c.body.hash}`);
    check('tf: each hash the node carries is searched exactly, then search_hash by SHA-256', terms.join() === `${SHA256},${MD5},hash:${SHA256}` && t.net.calls.slice(0, 2).every((c) => c.body.exact_match === true));
    const assoc = t.graph.createdEdges.filter((e) => e.from === 'f1' && e.label === 'associated in ThreatFox with');
    check("tf: three indicators tied to the sample (its own md5 record is not a neighbour)", assoc.length === 3 && r.counts.associated === 3);
    const ip = t.graph.createdNodes.find((n) => n.type === 'infrastructure.ip_address');
    const indIds = new Set(t.graph.createdNodes.filter((n) => n.type === 'threat.indicator').map((n) => n.id));
    check('tf: the C2 also becomes an IP Address without its port, which its indicator refers_to', ip?.data.ip_address === '5.6.7.8' && t.graph.createdEdges.some((e) => indIds.has(e.from) && e.to === ip.id && e.label === 'refers_to'));
    check('tf: …and a domain C2 a Domain', t.graph.createdNodes.some((n) => n.type === 'infrastructure.domain' && n.data.domain_name === 'c2.example.net'));
    check('tf: an md5 IOC stays an indicator (a File Hash needs a SHA-256)', !t.graph.createdNodes.some((n) => n.type === 'threat.file_hash'));
    check("tf: the file's own record refers_to the file", t.graph.createdEdges.some((e) => indIds.has(e.from) && e.to === 'f1' && e.label === 'refers_to'));
}
{
    const many = Array.from({ length: 7 }, (_, i) => tfRec({ id: String(i), ioc: `1.2.3.4:${1000 + i}` }));
    const t = ctxFor({ nodes: { ip1: { id: 'ip1', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } } }, params: { max_records: 5 }, respond: () => ({ status: 200, body: { query_status: 'ok', data: many } }) });
    const r = await P.threatfox.run(t.ctx);
    check('tf: max_records caps indicators per node and says how many were left', t.graph.createdNodes.filter((n) => n.type === 'threat.indicator').length === 5 && /2 indicator\(s\) past max_records/.test(r.summary));
}
{
    // An existing Malware "Cobalt Strike" (as OTX writes it) is not the Tool this pack means.
    const t = ctxFor({
        nodes: { ip1: { id: 'ip1', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } }, m1: { id: 'm1', type: 'threat.malware', data: { name: 'Cobalt Strike', malware_type: 'unknown' } }, t1: { id: 't1', type: 'threat.tool', data: { name: 'Cobalt Strike', tool_type: 'c2' } } },
        selection: ['ip1'],
        respond: () => ({ status: 200, body: { query_status: 'ok', data: [tfRec({})] } }),
    });
    await P.threatfox.run(t.ctx);
    check("tf: a table family reuses the existing node of ITS kind (IP Classification's Tool)", t.graph.createdEdges.some((e) => e.to === 't1' && e.label === 'indicates') && !t.graph.createdEdges.some((e) => e.to === 'm1'));
}
// ThreatFox's win.deimos is a malware of its own; IP Classification's Deimos is the DeimosC2
// framework, a Tool. One name, two families: whichever order they arrive in, they stay two nodes.
const ip1 = { id: 'ip1', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } };
const deimosC2 = (o) => tfRec({ malware: 'win.deimos_c2', malware_printable: 'DeimosC2', malware_alias: null, ...o });
const deimos = (o) => tfRec({ malware: 'win.deimos', malware_printable: 'Deimos', malware_alias: null, ...o });
const indicatesTo = (t, from) => t.graph.createdEdges.filter((e) => e.from === from && e.label === 'indicates').map((e) => e.to);
{
    // The DeimosC2 Tool is already in the project.
    const t = ctxFor({
        nodes: { ip1, t1: { id: 't1', type: 'threat.tool', data: { name: 'Deimos', tool_type: 'c2' } } },
        selection: ['ip1'],
        respond: () => ({ status: 200, body: { query_status: 'ok', data: [deimos({})] } }),
    });
    await P.threatfox.run(t.ctx);
    const m = t.graph.createdNodes.find((n) => n.type === 'threat.malware' && n.data.name === 'Deimos');
    check("tf: win.deimos does not land on an existing DeimosC2 Tool of the same name", !t.graph.createdEdges.some((e) => e.to === 't1') && !!m && t.graph.createdEdges.some((e) => e.to === m.id && e.label === 'indicates'));
}
for (const order of [['c2', 'mal'], ['mal', 'c2']]) {
    // Both in one run, on two IOCs, nothing in the project yet.
    const recs = order.map((w, i) => (w === 'c2' ? deimosC2 : deimos)({ id: String(i + 1), ioc: `1.2.3.4:${443 + i}` }));
    const t = ctxFor({ nodes: { ip1 }, respond: () => ({ status: 200, body: { query_status: 'ok', data: recs } }) });
    const r = await P.threatfox.run(t.ctx);
    const tool = t.graph.createdNodes.find((n) => n.type === 'threat.tool' && n.data.name === 'Deimos');
    const mal = t.graph.createdNodes.find((n) => n.type === 'threat.malware' && n.data.name === 'Deimos');
    const ind = (i) => t.graph.createdNodes.find((n) => n.type === 'threat.indicator' && n.data.value === `1.2.3.4:${443 + i}`)?.id;
    const want = order.map((w) => (w === 'c2' ? tool?.id : mal?.id));
    check(`tf: win.deimos_c2 and win.deimos in one run (${order[0]} first) stay a Tool and a Malware`, !!tool && !!mal && indicatesTo(t, ind(0)).join() === want[0] && indicatesTo(t, ind(1)).join() === want[1] && r.counts.families === 2);
}
{
    // Both on ONE IOC: two families, so two 'indicates' edges (de-duplicated by node, not by name).
    const t = ctxFor({ nodes: { ip1 }, respond: () => ({ status: 200, body: { query_status: 'ok', data: [deimosC2({ id: '1' }), deimos({ id: '2' })] } }) });
    await P.threatfox.run(t.ctx);
    const ind = t.graph.createdNodes.find((n) => n.type === 'threat.indicator')?.id;
    const kinds = indicatesTo(t, ind).map((id) => t.graph.createdNodes.find((n) => n.id === id)?.type).sort();
    check("tf: one IOC with win.deimos_c2 and win.deimos indicates both families", kinds.join() === 'threat.malware,threat.tool');
}
{
    // A family the table does not know still lands on the project's own node of that name, whichever
    // kind it is: the Deimos rule is for the table's names only.
    const t = ctxFor({
        nodes: { ip1, t1: { id: 't1', type: 'threat.tool', data: { name: 'Mimikatz', tool_type: 'credential_access' } } },
        selection: ['ip1'],
        respond: () => ({ status: 200, body: { query_status: 'ok', data: [tfRec({ malware: 'win.mimikatz', malware_printable: 'Mimikatz', malware_alias: null })] } }),
    });
    await P.threatfox.run(t.ctx);
    check("tf: an unlisted family reuses the project's Tool of that name", t.graph.createdEdges.some((e) => e.to === 't1' && e.label === 'indicates') && !t.graph.createdNodes.some((n) => n.type === 'threat.malware'));
}
{
    const t = ctxFor({ nodes: { ip1: { id: 'ip1', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } } }, respond: () => ({ status: 200, body: { query_status: 'no_result', data: 'Your search did not yield any results' } }) });
    const r = await P.threatfox.run(t.ctx);
    check('tf: no_result is a real negative', /no ThreatFox record — a real negative/.test(r.summary) && t.graph.createdNodes.length === 0);
}

// ================================================================ URLhaus
{
    // /v1/url/ for an online ELF dropper, trimmed (2026-11-14).
    const urlBody = {
        query_status: 'ok',
        id: '4065683',
        urlhaus_reference: 'https://urlhaus.abuse.ch/url/4065683/',
        url: 'http://112.232.224.88:41588/i',
        url_status: 'online',
        host: '112.232.224.88',
        date_added: '2026-11-14 10:02:25 UTC',
        last_online: null,
        threat: 'malware_download',
        blacklists: { spamhaus_dbl: 'not listed', surbl: 'listed' },
        reporter: 'adliwahid',
        tags: ['elf', 'Mozi'],
        payloads: [
            { firstseen: '2026-11-14', filename: null, file_type: 'elf', response_size: '135784', response_md5: '59ce0baba11893f90527fc951ac69912', response_sha256: '4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7', signature: 'Mozi' },
            { firstseen: '2026-11-13', response_sha256: 'not-a-hash' },
        ],
    };
    const t = ctxFor({ nodes: { u1: { id: 'u1', type: 'web.url', data: { url: 'http://112.232.224.88:41588/i' } } }, respond: () => ({ status: 200, body: urlBody }) });
    const r = await P.urlhaus.run(t.ctx);
    check('uh: POST form to /v1/url/', t.net.calls[0].url === 'https://urlhaus-api.abuse.ch/v1/url/' && t.net.calls[0].body.url === 'http://112.232.224.88:41588/i' && t.net.calls[0].headers['Auth-Key'] === 'test-key-not-real');
    const u = t.graph.updates[0]?.data ?? {};
    check('uh: URL fields', u.urlhaus_status === 'online' && u.urlhaus_threat === 'malware_download' && u.urlhaus_first_seen === '2026-11-14T10:02:25Z' && u.urlhaus_tags === 'elf, Mozi' && u.urlhaus_url === 'https://urlhaus.abuse.ch/url/4065683/');
    check("uh: only the blocklists that list it ('not listed' dropped)", u.urlhaus_blacklists === 'surbl: listed');
    const f = t.graph.createdNodes.find((n) => n.type === 'threat.file_hash');
    check('uh: the payload becomes a File Hash with md5 and integer size', f?.data.sha256 === '4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7' && f.data.md5 === '59ce0baba11893f90527fc951ac69912' && f.data.size === 135784);
    check("uh: URL → payload 'served file', with when", t.graph.createdEdges.some((e) => e.from === 'u1' && e.to === f?.id && e.label === 'served file' && e.data.first_seen === '2026-11-14T00:00:00Z'));
    check('uh: a payload without a SHA-256 is skipped', t.graph.createdNodes.filter((n) => n.type === 'threat.file_hash').length === 1);
    check("uh: the payload's signature is its family", t.graph.createdEdges.some((e) => e.from === f?.id && e.label === 'classified as'));
    check('uh: summary', /1 of 1 node\(s\) found in URLhaus/.test(r.summary) && r.counts.payloads === 1);
}
{
    // /v1/host/ on a shared host: the API returns 100 of 63,227 (github.com, measured).
    const urls = Array.from({ length: 100 }, (_, i) => ({ url: `https://github.com/x/y/raw/${i}.zip`, url_status: 'online', date_added: '2026-11-14 10:15:17 UTC', threat: 'malware_download', tags: ['SmartLoader'], urlhaus_reference: `https://urlhaus.abuse.ch/url/${i}/` }));
    const t = ctxFor({ nodes: { d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'github.com' } } }, respond: () => ({ status: 200, body: { query_status: 'ok', urlhaus_reference: 'https://urlhaus.abuse.ch/host/github.com/', host: 'github.com', firstseen: '2018-05-18 14:50:13 UTC', url_count: '63227', blacklists: { spamhaus_dbl: 'not listed', surbl: 'not listed' }, urls } }) });
    const r = await P.urlhaus.run(t.ctx);
    check('uh: a host is looked up by /v1/host/', t.net.calls[0].url === 'https://urlhaus-api.abuse.ch/v1/host/' && t.net.calls[0].body.host === 'github.com');
    check('uh: host fields', t.graph.updates[0]?.data.urlhaus_url_count === 63227 && t.graph.updates[0]?.data.urlhaus_first_seen === '2018-05-18T14:50:13Z' && !('urlhaus_blacklists' in t.graph.updates[0].data));
    check("uh: 25 URLs by default, linked 'hosts'", t.graph.createdNodes.filter((n) => n.type === 'web.url').length === 25 && t.graph.createdEdges.filter((e) => e.from === 'd1' && e.label === 'hosts').length === 25);
    check('uh: the rest is counted against url_count, not the 100 returned', /63202 URL\(s\) or payload\(s\) past max_items/.test(r.summary) && t.logs.some((l) => /lists 63227 URL/.test(l)));
}
{
    // A Domain under an internationalised TLD is looked up, in punycode, not skipped as a value
    // URLhaus does not take: the node's own type took it, and URLhaus lists hosts in ASCII.
    const t = ctxFor({
        nodes: { d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'c2.example.xn--p1ai' } }, d2: { id: 'd2', type: 'infrastructure.domain', data: { domain_name: 'пример.рф' } } },
        respond: () => ({ status: 200, body: { query_status: 'no_results' } }),
    });
    const r = await P.urlhaus.run(t.ctx);
    check('uh: an internationalised Domain is looked up, in punycode', t.net.calls.map((c) => c.body.host).join() === 'c2.example.xn--p1ai,xn--e1afmkfd.xn--p1ai');
    check('uh: …and is not counted as a value URLhaus does not take', !/no value URLhaus takes/.test(r.summary));
}
{
    // /v1/payload/ by SHA-256 → the URLs that served it.
    const t = ctxFor({
        nodes: { f1: fileNode({ sha256: '4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7' }) },
        params: { max_items: 2 },
        respond: () => ({ status: 200, body: { query_status: 'ok', md5_hash: '59ce0baba11893f90527fc951ac69912', sha256_hash: '4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7', file_type: 'elf', file_size: '135784', signature: null, firstseen: '2020-09-27 22:50:05', lastseen: '2026-11-14 10:20:05', url_count: '760668', urls: [{ url_id: '1', url: 'http://1.1.1.1:1/i', url_status: 'online', urlhaus_reference: 'https://urlhaus.abuse.ch/url/1/', filename: null, firstseen: '2026-11-14' }, { url: 'http://2.2.2.2:2/i' }, { url: 'http://3.3.3.3:3/i' }] } }),
    });
    const r = await P.urlhaus.run(t.ctx);
    check('uh: a payload is looked up by sha256_hash', t.net.calls[0].url === 'https://urlhaus-api.abuse.ch/v1/payload/' && t.net.calls[0].body.sha256_hash);
    const u = t.graph.updates[0]?.data ?? {};
    check("uh: payload fields; URLhaus's first sighting is urlhaus_first_seen, not first_seen", u.urlhaus_url_count === 760668 && u.urlhaus_file_type === 'elf' && u.urlhaus_first_seen === '2020-09-27T22:50:05Z' && !('first_seen' in u) && u.md5 === '59ce0baba11893f90527fc951ac69912' && u.size === 135784);
    check("uh: URL → payload 'served file', capped at max_items", t.graph.createdEdges.filter((e) => e.to === 'f1' && e.label === 'served file').length === 2 && /760666 URL\(s\) or payload\(s\)/.test(r.summary));
}
{
    const t = ctxFor({ nodes: { ip1: { id: 'ip1', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } } }, respond: () => ({ status: 200, body: { query_status: 'no_results' } }) });
    const r = await P.urlhaus.run(t.ctx);
    check('uh: no_results is a real negative', /not in URLhaus — a real negative/.test(r.summary) && t.graph.updates.length === 0);
}

// ================================================================ SSLBL
const FEED = [
    '################################################################',
    '# abuse.ch SSLBL SSL Certificate Blacklist (SHA1 Fingerprints) #',
    '# Last updated: 2026-11-14 09:14:20 UTC                        #',
    '#',
    '# Listingdate,SHA1,Listingreason',
    `2026-11-14 08:35:11,${SHA1},QuasarRAT C&C`,
    '2026-11-14 08:34:04,d43053e6c4c7f1b6d00e860b690cdf1b964e1afa,LummaStealer C&C',
    '2026-11-13 08:34:04,1111111111111111111111111111111111111111,Malware C&C',
    '2014-05-04 08:10:26,2222222222222222222222222222222222222222,Vawtrak MITM',
    '# END (4) entries',
].join('\n');
const cert = (id, sha1) => ({ id, type: 'infrastructure.certificate', data: { fingerprint_sha256: id.padEnd(64, '0').replace(/[^0-9a-f]/g, 'a'), ...(sha1 ? { fingerprint_sha1: sha1 } : {}) } });
{
    const t = ctxFor({
        nodes: { c1: cert('c1', SHA1.toUpperCase()), c2: cert('c2', 'd43053e6c4c7f1b6d00e860b690cdf1b964e1afa'), c3: cert('c3', '1111111111111111111111111111111111111111'), c4: cert('c4', '3333333333333333333333333333333333333333'), c5: cert('c5') },
        config: {},
        respond: (url) => (url.includes('sslbl') ? { status: 200, text: FEED } : { status: 500 }),
    });
    const r = await P.sslbl.run(t.ctx);
    check('sslbl: one GET of the feed, no Auth-Key sent, nothing else without a key', t.net.calls.length === 1 && t.net.calls[0].method === 'GET' && !('Auth-Key' in t.net.calls[0].headers));
    const u1 = t.graph.updates.find((u) => u.id === 'c1')?.data ?? {};
    check('sslbl: listed certificate gets its listing (SHA-1 matched case-insensitively)', u1.sslbl_listed === '2026-11-14T08:35:11Z' && u1.sslbl_reason === 'QuasarRAT C&C');
    const q = t.graph.createdNodes.find((n) => n.data.name === 'Quasar');
    check("sslbl: QuasarRAT → IP Classification's Quasar, linked 'used as C2'", q?.type === 'threat.malware' && q.data.malware_type === 'rat' && t.graph.createdEdges.some((e) => e.from === 'c1' && e.to === q.id && e.label === 'used as C2'));
    check('sslbl: without a key the SSLBL spelling stays', t.graph.createdNodes.some((n) => n.data.name === 'LummaStealer'));
    check("sslbl: 'Malware C&C' is listed but names no family", t.graph.updates.some((u) => u.id === 'c3') && !t.graph.createdEdges.some((e) => e.from === 'c3'));
    check('sslbl: an unlisted certificate gets nothing written', !t.graph.updates.some((u) => u.id === 'c4'));
    check('sslbl: a certificate without a SHA-1 is counted and the fix named', r.counts.no_sha1 === 1 && /1 certificate\(s\) have no fingerprint_sha1/.test(r.summary) && /Shodan Host, Censys Host Lookup or VT/.test(r.summary));
    check('sslbl: summary names the list date', /3 of 4 certificate\(s\) listed by SSLBL \(list of 2026-11-14, 4 certificates\)/.test(r.summary));
}
{
    const t = ctxFor({
        nodes: { c2: cert('c2', 'd43053e6c4c7f1b6d00e860b690cdf1b964e1afa'), c6: cert('c6', '2222222222222222222222222222222222222222') },
        respond: (url) =>
            url.includes('sslbl') ? { status: 200, text: FEED } : { status: 200, body: { query_status: 'ok', data: { 'win.lumma': { malware_printable: 'Lumma Stealer', malware_alias: null } } } },
    });
    await P.sslbl.run(t.ctx);
    check("sslbl: with a key, LummaStealer → ThreatFox's Lumma Stealer", t.graph.createdNodes.some((n) => n.data.name === 'Lumma Stealer') && t.net.calls.filter((c) => c.url.includes('threatfox')).length === 1);
    check("sslbl: a MITM listing is linked 'used for MITM'", t.graph.createdEdges.some((e) => e.from === 'c6' && e.label === 'used for MITM'));
}
{
    const t = ctxFor({ nodes: { c5: cert('c5') }, respond: () => ({ status: 200, text: FEED }) });
    const r = await P.sslbl.run(t.ctx);
    check('sslbl: no certificate with a SHA-1 → nothing downloaded, and the fix named', t.net.calls.length === 0 && /None of the 1 certificate\(s\) carries a fingerprint_sha1/.test(r.summary));
}
{
    const t = ctxFor({ nodes: { c2: cert('c2', 'd43053e6c4c7f1b6d00e860b690cdf1b964e1afa') }, respond: (url) => (url.includes('sslbl') ? { status: 200, text: FEED } : { status: 403, body: { query_status: 'unknown_auth_key' } }) });
    const r = await run(P.sslbl, t);
    check('sslbl: a refused (optional) key does not fail the run', !r.error && /Auth-Key was refused/.test(r.summary) && t.graph.createdNodes.some((n) => n.data.name === 'LummaStealer'));
}

{
    // A cut copy of the list. The abuse.ch CDN served one on 2026-11-14: 524,288 bytes, the full
    // header with the same "Last updated", 6,896 of 11,261 rows and no "# END" line. Matched as it
    // stood, every certificate listed before 2021-09 read as "not listed" — a false negative.
    const cut = FEED.split('\n').slice(0, -2).join('\n'); // the last row and the END line gone
    const nodes = { c1: cert('c1', SHA1), c6: cert('c6', '2222222222222222222222222222222222222222') };
    const t = ctxFor({ nodes, config: {}, respond: () => ({ status: 200, text: cut }) });
    const r = await run(P.sslbl, t);
    check('sslbl: a list without its END line fails the run and checks nothing', !!r.error && /arrived incomplete/.test(r.error.message) && /no certificate was checked/.test(r.error.message) && t.graph.updates.length === 0 && t.graph.createdNodes.length === 0);
    const short = FEED.replace('# END (4) entries', '# END (11261) entries');
    const t2 = ctxFor({ nodes, config: {}, respond: () => ({ status: 200, text: short }) });
    const r2 = await run(P.sslbl, t2);
    check('sslbl: a list with fewer rows than its END line says fails the run', !!r2.error && /4 of 11261 rows/.test(r2.error.message) && t2.graph.updates.length === 0);
}

// ================================================================ raw results: ctx.retain
// Invariants, from the plugin raw results spec (§5, §9-1, §12):
//   - Each lookup keeps its FINAL answer, whole and as the text abuse.ch sent, on the node it looked
//     up: MalwareBazaar op "malwarebazaar", URLhaus op "urlhaus", ThreatFox one op per search
//     ("threatfox" for an IP/Domain/URL, "threatfox_<alg>" per hash and "threatfox_associated" for
//     search_hash on a File Hash), so no answer replaces another in the node's `latest` slot.
//   - A "not found" answer (HTTP 200, hash_not_found / no_result / no_results) is kept: it is a
//     finding. A key failure (401, 403, unknown_auth_key), a 5xx, a retried 429 and the shared
//     malware list are never kept. Derived nodes (indicators, payloads, URLs, families) get none.
//   - No slice and no synthetic body (analyst's decision, 2026-11-25): one request is about one
//     node in this pack, and its body is the response text unchanged.
//   - Nothing handed to retain carries the Auth-Key, the request or its URL.
//   - A refusal object or a throw from retain never fails the run, and is logged once per reason.
//   - A host without ctx.retain (every desktop build before it) runs exactly as before.
const SECRET = 'abusech-SECRET-key-0123456789';
const SECRET_CONFIG = { auth_key: SECRET };
const RESPONSE_HEADERS = { 'content-type': 'application/json', date: 'Tue, 25 Nov 2026 01:00:00 GMT', 'x-request-id': 'rq-1' };

function retainSpy(answer = async () => ({ kept: true })) {
    const calls = [];
    const fn = async (...args) => {
        calls.push(args);
        return answer(...args);
    };
    fn.calls = calls;
    return fn;
}
/** What must never reach retain: the key, its header, the request (its URL, query and form). */
const leaks = (calls) => {
    const s = JSON.stringify(calls);
    return [SECRET, 'Auth-Key', 'auth_key', '-api.abuse.ch', 'get_info', 'search_ioc', 'search_hash', 'search_term', 'malware_list'].filter((x) => s.includes(x));
};
const shapeOk = (calls) => calls.every((c) => Object.keys(c[2]).sort().join() === 'body,headers,status' && typeof c[2].body === 'string' && c[3] === undefined);
const where = (calls) => calls.map((c) => `${c[0]}:${c[1]}`).join();
const withRetain = (opts, spy = retainSpy()) => {
    const t = ctxFor({ config: SECRET_CONFIG, ...opts });
    t.ctx.retain = spy;
    return { t, spy };
};

{
    const mbBody = { query_status: 'ok', data: [{ ...mbRecord, signature: null }] };
    const respond = () => ({ status: 200, body: mbBody, headers: RESPONSE_HEADERS });
    const nodes = { f1: fileNode({ sha256: SHA256 }) };
    const { t, spy } = withRetain({ nodes, respond });
    const res = await P.malwarebazaar.run(t.ctx);
    check('retain mb: one call, on the looked-up File Hash, op malwarebazaar', where(spy.calls) === 'f1:malwarebazaar');
    check('retain mb: status, headers and the answer as the text MalwareBazaar sent', spy.calls[0]?.[2].status === 200 && spy.calls[0][2].body === JSON.stringify(mbBody) && spy.calls[0][2].headers.date === RESPONSE_HEADERS.date);
    check('retain mb: a plain {status, headers, body}, no options', shapeOk(spy.calls));
    check('retain mb: headers are a copy, not the response object', spy.calls[0]?.[2].headers !== RESPONSE_HEADERS);
    check('retain mb: no Auth-Key, request or URL handed over', leaks(spy.calls).length === 0);
    check('retain mb: the request really carried the Auth-Key', t.net.calls[0].headers['Auth-Key'] === SECRET);

    const old = ctxFor({ nodes, config: SECRET_CONFIG, respond });
    const oldRes = await P.malwarebazaar.run(old.ctx);
    check('old host: no ctx.retain, the lookup runs as before', !('retain' in old.ctx) && JSON.stringify(oldRes) === JSON.stringify(res));
    check('old host: …stages the same graph and says nothing about raw results', JSON.stringify(old.graph.updates) === JSON.stringify(t.graph.updates) && !old.logs.some((l) => /not kept/.test(l)));
    const notFn = ctxFor({ nodes, respond });
    notFn.ctx.retain = true;
    const notFnRes = await run(P.malwarebazaar, notFn);
    check('old host: a retain that is not a function is left alone', !notFnRes.error && notFnRes.counts.found === 1);
}
{
    const { t, spy } = withRetain({ nodes: { f1: fileNode({ sha256: SHA256 }) }, respond: () => ({ status: 200, body: { query_status: 'hash_not_found' } }) });
    const r = await P.malwarebazaar.run(t.ctx);
    check('retain mb: hash_not_found is kept on the hash, as evidence', where(spy.calls) === 'f1:malwarebazaar' && JSON.parse(spy.calls[0][2].body).query_status === 'hash_not_found');
    check('retain mb: …and is still counted a real negative', r.counts.not_found === 1 && t.graph.updates.length === 0);
}
{
    for (const [label, answer] of [
        ['a 401', { status: 401, body: { error: 'Unauthorized' } }],
        ['a 403 unknown_auth_key', { status: 403, body: { query_status: 'unknown_auth_key' } }],
        ['a 200 unknown_auth_key', { status: 200, body: { query_status: 'unknown_auth_key' } }],
    ]) {
        const { t, spy } = withRetain({ nodes: { f1: fileNode({ sha256: SHA256 }) }, respond: () => answer });
        await run(P.malwarebazaar, t);
        check(`retain mb: ${label} ends the run and keeps nothing`, spy.calls.length === 0);
    }
    const { t: t5, spy: s5 } = withRetain({ nodes: { f1: fileNode({ sha256: SHA256 }) }, respond: () => ({ status: 502, text: 'Bad Gateway' }) });
    const r5 = await run(P.malwarebazaar, t5);
    check('retain mb: a 5xx (no answer about the hash) is not kept', s5.calls.length === 0 && r5.counts?.failed === 1);

    let n = 0;
    const { t, spy } = withRetain({
        nodes: { f1: fileNode({ sha256: SHA256 }) },
        respond: () => (n++ === 0 ? { status: 429, body: { throttled: true }, headers: { 'retry-after': '0.001' } } : { status: 200, body: { query_status: 'hash_not_found' } }),
    });
    await P.malwarebazaar.run(t.ctx);
    check('retain mb: a retried 429 is not kept, only the final answer', t.net.calls.length === 2 && spy.calls.length === 1 && spy.calls[0][2].status === 200 && !spy.calls[0][2].body.includes('throttled'));
}
{
    // A signature outside the table makes the run fetch ThreatFox's malware list: that answer is
    // about every family, not the hash, and is not kept anywhere.
    const { t, spy } = withRetain({
        nodes: { f1: fileNode({ sha256: SHA256 }) },
        respond: (url) =>
            url.includes('threatfox')
                ? { status: 200, body: { query_status: 'ok', data: { 'win.agent_tesla': { malware_printable: 'Agent Tesla', malware_alias: 'AgentTesla' } } } }
                : { status: 200, body: { query_status: 'ok', data: [{ ...mbRecord, signature: 'AgentTesla' }] } },
    });
    await P.malwarebazaar.run(t.ctx);
    check('retain mb: the malware list fetched on the way is not kept', t.net.calls.length === 2 && where(spy.calls) === 'f1:malwarebazaar');
}
{
    // One IP, one answer listing several IOC records (two ports, a second report, a loose-search
    // near-miss): kept whole on the IP, exactly as sent; the indicators made from it get nothing.
    const body = { query_status: 'ok', data: [tfRec({}), tfRec({ id: '2028601', ioc: '1.2.3.4:8443' }), tfRec({ id: '2028602', ioc: '11.2.3.45:80' })] };
    const { t, spy } = withRetain({ nodes: { ip1 }, respond: () => ({ status: 200, body, headers: RESPONSE_HEADERS }) });
    await P.threatfox.run(t.ctx);
    check('retain tf: one call, on the looked-up IP, op threatfox', where(spy.calls) === 'ip1:threatfox');
    check('retain tf: the whole answer, every record, as ThreatFox sent it', spy.calls[0]?.[2].body === JSON.stringify(body));
    check('retain tf: indicators and families made from it get no copy', t.graph.createdNodes.length > 0 && !spy.calls.some((c) => t.graph.createdNodes.some((n) => n.id === c[0])));
    check('retain tf: shape, and no Auth-Key or request', shapeOk(spy.calls) && leaks(spy.calls).length === 0 && t.net.calls[0].headers['Auth-Key'] === SECRET);
}
{
    // A File Hash is searched once per hash and once with search_hash: each answer in its own op,
    // so the md5 answer does not replace the sha256 one.
    const { t, spy } = withRetain({
        nodes: { f1: fileNode({ sha256: SHA256, sha1: SHA1, md5: MD5 }) },
        respond: (url, b) => {
            if (b.query === 'search_hash') return { status: 200, body: { query_status: 'ok', data: [tfRec({ id: '77', ioc: '5.6.7.8:443' })] } };
            if (b.search_term === SHA256) return { status: 200, body: { query_status: 'ok', data: [tfRec({ id: '70', ioc: SHA256, ioc_type: 'sha256_hash' })] } };
            return { status: 200, body: { query_status: 'no_result', data: 'Your search did not yield any results' } };
        },
    });
    await P.threatfox.run(t.ctx);
    check('retain tf: a File Hash keeps each search under its own op, all on the file', where(spy.calls) === 'f1:threatfox_sha256,f1:threatfox_sha1,f1:threatfox_md5,f1:threatfox_associated');
    check('retain tf: the no_result answers are kept too', spy.calls.filter((c) => JSON.parse(c[2].body).query_status === 'no_result').length === 2);
    check('retain tf: every op fits the host rule', spy.calls.every((c) => /^[a-z][a-z0-9_]{0,63}$/.test(c[1])));
    check('retain tf: no Auth-Key or request in any of them', leaks(spy.calls).length === 0);
}
{
    const urlBody = { query_status: 'ok', url: 'http://112.232.224.88:41588/i', url_status: 'online', urlhaus_reference: 'https://urlhaus.abuse.ch/url/4065683/', payloads: [{ firstseen: '2026-11-14', response_sha256: '4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7', signature: null }] };
    const { t, spy } = withRetain({
        nodes: { u1: { id: 'u1', type: 'web.url', data: { url: 'http://112.232.224.88:41588/i' } }, d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'example.org' } } },
        respond: (url) => (url.endsWith('/url/') ? { status: 200, body: urlBody, headers: RESPONSE_HEADERS } : { status: 200, body: { query_status: 'no_results' } }),
    });
    await P.urlhaus.run(t.ctx);
    check('retain uh: one call per node looked up, op urlhaus, on that node', where(spy.calls) === 'u1:urlhaus,d1:urlhaus');
    check('retain uh: the URL answer whole, as sent', spy.calls[0]?.[2].body === JSON.stringify(urlBody));
    check('retain uh: no_results on the domain is kept', JSON.parse(spy.calls[1]?.[2].body ?? '{}').query_status === 'no_results');
    check('retain uh: the payload node made from it gets no copy', t.graph.createdNodes.length === 1 && !spy.calls.some((c) => c[0] === t.graph.createdNodes[0].id));
    check('retain uh: shape, and no Auth-Key or request', shapeOk(spy.calls) && leaks(spy.calls).length === 0);
}
{
    // SSLBL downloads one list about every listed certificate: nothing in it is one node's answer.
    const { t, spy } = withRetain({ nodes: { c1: cert('c1', SHA1) }, respond: (url) => (url.includes('sslbl') ? { status: 200, text: FEED } : { status: 200, body: { query_status: 'ok', data: {} } }) });
    const r = await run(P.sslbl, t);
    check('retain sslbl: the downloaded list is never kept', !r.error && t.net.calls.length >= 1 && spy.calls.length === 0);
}
{
    // A refusal is an object, not a throw — and either way the run carries on.
    const nodes = { a: fileNode({ sha256: SHA256 }), b: { id: 'b', type: 'threat.file_hash', data: { md5: MD5 } }, c: { id: 'c', type: 'threat.file_hash', data: { sha1: SHA1 } } };
    const respond = () => ({ status: 200, body: { query_status: 'ok', data: [{ ...mbRecord, signature: null }] } });
    const refuse = retainSpy(async () => ({ kept: false, reason: "over this run's raw-result budget" }));
    const { t } = withRetain({ nodes, respond }, refuse);
    const res = await run(P.malwarebazaar, t);
    check('retain refusal: the lookups still succeed', !res.error && res.counts.found === 3 && refuse.calls.length === 3);
    check('retain refusal: said once, not once per node', t.logs.filter((l) => l === "Raw malwarebazaar result not kept — over this run's raw-result budget").length === 1);

    const thrower = retainSpy(async () => {
        throw new Error('host blew up');
    });
    const { t: h } = withRetain({ nodes, respond }, thrower);
    const hres = await run(P.malwarebazaar, h);
    check('retain throw: the lookups still succeed with everything mapped', !hres.error && hres.counts.found === 3 && h.graph.updates.length === 3);
    check("retain throw: logged once, without the host's message", h.logs.filter((l) => /Raw malwarebazaar result not kept/.test(l)).length === 1 && !h.logs.some((l) => /blew up/.test(l)));
}
{
    check('pack version is 1.1.0', pack.version === '1.1.0');
}

for (const n of fail) console.log('FAIL', n);
console.log(`\n${fail.length ? 'FAIL' : 'PASS'} ${ok.length} / ${ok.length + fail.length}`);
if (fail.length) process.exit(1);
