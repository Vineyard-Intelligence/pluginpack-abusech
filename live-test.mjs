// Live check against the real abuse.ch APIs — opt-in, never part of the mock suite.
//
//   ABUSECH_AUTH_KEY=… node live-test.mjs
//
// The key is read from the environment only, sent only as the Auth-Key header, and never printed:
// nothing below logs a request header. Indicators are not hard-coded, because abuse.ch's entries
// come and go: the script asks each tracker for something recent first, then runs every plugin on
// it through the bundle with a mock graph, and prints what each plugin would have staged. A
// ThreatFox sample is confirmed by id before it is used (see liveSample).
// Low volume on purpose — about two dozen requests in all (22 on 2026-11-16), and one more for
// each ThreatFox candidate skipped.
import pack from './dist/pack.mjs';

const key = (process.env.ABUSECH_AUTH_KEY ?? '').trim();
if (!key) {
    console.log('SKIP live test: set ABUSECH_AUTH_KEY (a free key from https://auth.abuse.ch/)');
    process.exit(0);
}
const P = Object.fromEntries(pack.plugins.map((p) => [p.manifest.identifier.replace('run.vineyard.plugins.abusech_', ''), p]));

let requests = 0;
const net = {
    async fetch(url, init) {
        requests++;
        const res = await fetch(url, { method: init?.method ?? 'GET', headers: init?.headers, body: init?.body });
        const text = await res.text();
        const headers = Object.fromEntries([...res.headers.entries()].map(([k, v]) => [k.toLowerCase(), v]));
        return { ok: res.ok, status: res.status, headers, async text() { return text; }, async json() { return JSON.parse(text); } };
    },
};
const post = async (url, body, json) =>
    (await net.fetch(url, { method: 'POST', headers: { 'Auth-Key': key, 'Content-Type': json ? 'application/json' : 'application/x-www-form-urlencoded' }, body: json ? JSON.stringify(body) : new URLSearchParams(body).toString() })).json();

function graphOf(nodes) {
    const created = [];
    const edges = [];
    const updates = [];
    return {
        created,
        edges,
        updates,
        get: async (id) => nodes[id] ?? null,
        list: async () => ({ nodes: [] }),
        createNode: async (d) => {
            const n = { id: `n${created.length + 1}`, type: d.type, data: d.data };
            created.push(n);
            return n;
        },
        updateNode: async (id, data) => updates.push({ id, data }),
        createEdge: async (e) => edges.push(e),
    };
}
async function runOn(name, node, extra = {}) {
    const graph = graphOf({ [node.id]: node });
    const ctx = { run: { platform: 'desktop' }, config: { auth_key: key }, params: {}, input: { selection: [node.id] }, graph, net, progress: { set() {}, log: (m) => console.log(`    log: ${m}`) }, ...extra };
    const r = await P[name].run(ctx);
    console.log(`  ${P[name].manifest.name} on ${node.type} ${Object.values(node.data)[0]}`);
    console.log(`    summary: ${r.summary}`);
    for (const u of graph.updates) console.log(`    update: ${Object.keys(u.data).join(', ')}`);
    const byType = {};
    for (const n of graph.created) byType[n.type] = (byType[n.type] ?? 0) + 1;
    console.log(`    created: ${JSON.stringify(byType)}  edges: ${[...new Set(graph.edges.map((e) => e.label))].join(' | ')}`);
    const fam = graph.created.filter((n) => /threat\.(malware|tool)/.test(n.type)).map((n) => `${n.type.slice(7)}:${n.data.name}`);
    if (fam.length) console.log(`    families: ${fam.join(', ')}`);
    return { r, graph };
}

const failures = [];
const expect = (what, cond) => {
    if (!cond) failures.push(what);
    console.log(`    ${cond ? 'ok  ' : 'FAIL'} ${what}`);
};

// ---- pick live samples -------------------------------------------------------------------------
const TF = 'https://threatfox-api.abuse.ch/api/v1/';
const iocs = await post(TF, { query: 'get_iocs', days: 1 }, true);
const list = Array.isArray(iocs.data) ? iocs.data : [];
const mb = await post('https://mb-api.abuse.ch/api/v1/', { query: 'get_recent', selector: 'time' });
const sample = (mb.data ?? []).find((x) => x.signature) ?? (mb.data ?? [])[0];
const recent = await (await net.fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/', { method: 'GET', headers: { 'Auth-Key': key } })).json();
const urlRec = (recent.urls ?? []).find((u) => !/github/.test(u.host)) ?? (recent.urls ?? [])[0];
console.log(`samples: ThreatFox ${list.length} IOCs, MalwareBazaar ${mb.data?.length ?? 0} samples, URLhaus ${recent.urls?.length ?? 0} URLs`);

/**
 * The newest ThreatFox record of one IOC type that ThreatFox answers for by id, or null.
 *
 * get_iocs lists IOCs that ThreatFox's other queries do not answer for, at least for a while. At
 * 2026-11-16 15:29 UTC its newest ip:port, 31.77.124.14:8443 (id 2031643, then first seen 15:20
 * UTC), answered unknown_ioc_id to {query: 'ioc', id} and search_ioc found nothing for it, while
 * another IP from the same list was found by the plugin's substring search: the check failed on
 * its own sample, not on the pack. By 16:07 UTC the same id answered again, with a first_seen of
 * 16:00:22 UTC, and search_ioc found it. So each candidate is confirmed by id, one request each,
 * before a plugin runs on it; named families first, as before, and at most three candidates per
 * type to keep the volume low.
 *
 * MEASURED 2026-11-16 16:07 UTC: {query: 'ioc', id} answers with the record itself, with no query_status
 * and no data wrapper, when ThreatFox has the IOC. A query_status is the answer for one it does
 * not have; the wrapped {query_status: 'ok', data} form is taken too, in case that changes.
 */
async function liveSample(type) {
    const ofType = list.filter((x) => x.ioc_type === type && x.ioc && x.id != null);
    const isNamed = (x) => !String(x.malware).startsWith('unknown');
    const candidates = [...ofType.filter(isNamed), ...ofType.filter((x) => !isNamed(x))].slice(0, 3);
    if (!candidates.length) {
        console.log(`  ThreatFox ${type}: no record in the last day, so its checks do not run`);
        return null;
    }
    for (const c of candidates) {
        let why;
        try {
            const res = await post(TF, { query: 'ioc', id: /^\d+$/.test(String(c.id)) ? Number(c.id) : c.id }, true);
            const status = res?.query_status;
            const rec = status === 'ok' ? (Array.isArray(res.data) ? res.data[0] : res.data) : status === undefined ? res : null;
            if (rec && String(rec.id) === String(c.id) && rec.ioc === c.ioc) {
                console.log(`  ThreatFox ${type} sample: ${c.ioc} (id ${c.id}), confirmed by id`);
                return c;
            }
            if (rec) why = `not confirmed: id ${c.id} answers ${rec.ioc ?? 'a record with no IOC'}`;
            else if (/^(unknown_ioc_id|no_results?|not_found)$/.test(String(status))) why = `withdrawn: {query: 'ioc'} answered ${status}`;
            else why = `not confirmed: {query: 'ioc'} answered ${status}`;
        } catch (e) {
            why = `not confirmed: ${e instanceof Error ? e.message : String(e)}`;
        }
        console.log(`  skipped ThreatFox ${type} candidate ${c.ioc} (id ${c.id}), ${why}`);
    }
    const what = `found a ThreatFox ${type} sample ThreatFox answers for, within ${candidates.length} candidate(s)`;
    failures.push(what);
    console.log(`    FAIL ${what}`);
    return null;
}
const ipRec = await liveSample('ip:port');
const domRec = await liveSample('domain');
const shaRec = await liveSample('sha256_hash');

// ---- MalwareBazaar ---------------------------------------------------------------------------
if (sample) {
    const { r, graph } = await runOn('malwarebazaar', { id: 'f1', type: 'threat.file_hash', data: { sha256: sample.sha256_hash } });
    expect('MalwareBazaar found the recent sample', r.counts.found === 1 && graph.updates[0]?.data.mb_first_seen);
    const { r: r2 } = await runOn('malwarebazaar', { id: 'f2', type: 'threat.file_hash', data: { md5: sample.md5_hash } });
    expect('MalwareBazaar finds it by md5 too, and fills the SHA-256', r2.counts.found === 1);
}

// ---- ThreatFox -------------------------------------------------------------------------------
if (ipRec) {
    const ip = ipRec.ioc.replace(/:\d+$/, '');
    const { r, graph } = await runOn('threatfox', { id: 'ip1', type: 'infrastructure.ip_address', data: { ip_address: ip } });
    expect('ThreatFox lists the IP', r.counts.listed === 1 && graph.created.some((n) => n.type === 'threat.indicator' && n.data.value.startsWith(`${ip}:`)));
    expect('…and its indicator refers_to the IP', graph.edges.some((e) => e.label === 'refers_to' && e.to === 'ip1'));
}
if (domRec) {
    const { r } = await runOn('threatfox', { id: 'd1', type: 'infrastructure.domain', data: { domain_name: domRec.ioc } });
    expect('ThreatFox lists the domain', r.counts.listed === 1);
}
if (shaRec) {
    const { r } = await runOn('threatfox', { id: 'f3', type: 'threat.file_hash', data: { sha256: shaRec.ioc } });
    expect('ThreatFox lists the sha256 IOC', r.counts.listed === 1);
}
{
    const { r } = await runOn('threatfox', { id: 'ip0', type: 'infrastructure.ip_address', data: { ip_address: '192.0.2.123' } });
    expect('a documentation address has no record (a real negative)', r.counts.not_listed === 1);
}

// ---- URLhaus ---------------------------------------------------------------------------------
if (urlRec) {
    const { r, graph } = await runOn('urlhaus', { id: 'u1', type: 'web.url', data: { url: urlRec.url } });
    expect('URLhaus knows the URL', r.counts.found === 1 && graph.updates[0]?.data.urlhaus_status);
    const host = urlRec.host;
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host);
    const { r: r2 } = await runOn('urlhaus', { id: 'h1', type: isIp ? 'infrastructure.ip_address' : 'infrastructure.domain', data: isIp ? { ip_address: host } : { domain_name: host } });
    expect('URLhaus knows its host', r2.counts.found === 1 && r2.counts.urls >= 1);
}

// ---- SSLBL -----------------------------------------------------------------------------------
{
    // The newest C&C row and the OLDEST row: a cut copy of the list (the CDN served one on
    // 2026-11-14) keeps the newest and loses the oldest, so checking only the newest hid it.
    const feed = await (await net.fetch('https://sslbl.abuse.ch/blacklist/sslblacklist.csv', { method: 'GET' })).text();
    const rows = feed.split('\n').map((l) => l.trim()).filter((l) => /^\d{4}-[^,]*,[0-9a-f]{40},/.test(l));
    const sha1 = rows.find((l) => / C&C$/.test(l))?.split(',')[1];
    const oldest = rows.at(-1)?.split(',')[1];
    if (sha1) {
        const node = { id: 'c1', type: 'infrastructure.certificate', data: { fingerprint_sha256: '0'.repeat(64), fingerprint_sha1: sha1 } };
        const { r } = await runOn('sslbl', node);
        expect('SSLBL lists the certificate, with a family', r.counts.listed === 1 && r.counts.families === 1);
        const { r: r2 } = await runOn('sslbl', node, { config: {} });
        expect('…and works without a key', r2.counts.listed === 1);
    }
    if (oldest) {
        const { r } = await runOn('sslbl', { id: 'c0', type: 'infrastructure.certificate', data: { fingerprint_sha256: '1'.repeat(64), fingerprint_sha1: oldest } }, { config: {} });
        expect('…and the oldest row of the list too', r.counts.listed === 1);
    }
}

console.log(`\n${requests} request(s)`);
console.log(failures.length ? `LIVE FAIL: ${failures.join('; ')}` : 'LIVE PASS');
if (failures.length) process.exit(1);
