// Request plumbing and manifest fragments every abuse.ch plugin shares.
import type { ConfigValue, GraphNode, GraphScope, HostContext, NetworkScope, PluginManifest, TypeRef } from './sdk';

export const MB_API = 'https://mb-api.abuse.ch/api/v1/';
export const TF_API = 'https://threatfox-api.abuse.ch/api/v1/';
export const UH_API = 'https://urlhaus-api.abuse.ch/v1/';
export const SSLBL_FEED = 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv';

export const INFRA = 'run.vineyard.typepacks.infrastructure';
export const THREAT = 'run.vineyard.typepacks.threat';
export const infra = (name: string, category = 'infrastructure'): TypeRef => ({ typepack: INFRA, category, name });
export const threat = (name: string): TypeRef => ({ typepack: THREAT, category: 'threat', name });

// PLATFORM: desktop only, MEASURED 2026-11-14. None of the four hosts sends an
// `access-control-allow-*` header, on a real answer or on a preflight, and the three APIs answer the
// preflight with 401: a browser sends OPTIONS without the Auth-Key, so it can never pass. The
// desktop shell writes the missing headers (and promotes the failed preflight) for origins a pack
// declares. `refuseOnWeb` says so before any request instead of leaving a bare "Failed to fetch".
export const PLATFORMS: PluginManifest['platforms'] = {
    primary: 'desktop',
    web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
    desktop: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
};

// ONE NETWORK LIST FOR EVERY MEMBER, on purpose. abuse.ch issues one Auth-Key for all its platforms,
// and the app files a pack's settings by the set of origins a member calls (config-slot.ts): four
// members with four different origin sets would ask for the same key four times, and a key fixed in
// one would stay wrong in the other three. With one list they share one slot, so the key is typed
// once. What it costs is breadth — each member may also reach the other abuse.ch APIs — and every
// destination is still an abuse.ch host the install gate names.
export const NETWORK: NetworkScope[] = [
    { endpoint: MB_API, methods: ['POST'], purpose: 'Look up file hashes in MalwareBazaar.' },
    {
        endpoint: TF_API,
        methods: ['POST'],
        purpose: "Search ThreatFox for indicators, and read its malware list to match family names to ThreatFox's.",
    },
    { endpoint: UH_API, methods: ['POST'], purpose: 'Look up URLs, hosts and payload hashes in URLhaus.' },
    { endpoint: SSLBL_FEED, methods: ['GET'], purpose: 'Download the SSLBL SSL Certificate Blacklist (no Auth-Key sent).' },
];

const KEY_LABEL = 'abuse.ch Auth-Key';
export const KEY_CONFIG: ConfigValue = { key: 'auth_key', label: KEY_LABEL, type: 'string', secret: true, optional: false };
/** SSLBL is CC0 and needs no key; with one, its family names are matched to ThreatFox's. */
export const KEY_CONFIG_OPTIONAL: ConfigValue = { ...KEY_CONFIG, optional: true };

export const GRAPH_SCOPES: GraphScope[] = ['node:read', 'node:create', 'node:update', 'edge:create'];
export const LIFECYCLE: NonNullable<PluginManifest['lifecycle']> = {
    persistence: 'opt-in',
    controls: ['progress', 'cancel'],
    progress: 'determinate',
};

// ---- errors ----------------------------------------------------------------------------------

/**
 * A condition that ends the whole run — a missing or rejected key, a rate limit that outlasted the
 * backoff. Not one item's problem, so no item is retried past it.
 *
 * Each plugin catches it and decides: before anything was found it rethrows (a failed task that
 * names the cause); after, it stops and RETURNS, because the host discards everything a thrown run
 * staged (runner.ts) and the lookups already answered are worth keeping. The summary then says
 * which nodes were not reached.
 */
export class StopRun extends Error {}

/** One request that failed without an answer (network error, 5xx, a body that is not JSON). */
export class ItemFailed extends Error {}

export const abortErr = (): Error => new Error('cancelled');

/** A wait that Cancel can cut short. */
export const sleep = (ms: number, signal?: AbortSignal): Promise<void> =>
    new Promise((resolve, reject) => {
        const timer = setTimeout(done, ms);
        function done() {
            signal?.removeEventListener('abort', onAbort);
            resolve();
        }
        function onAbort() {
            clearTimeout(timer);
            reject(abortErr());
        }
        signal?.addEventListener('abort', onAbort, { once: true });
    });

export function refuseOnWeb(ctx: HostContext): void {
    if (ctx.run?.platform && ctx.run.platform !== 'desktop') {
        throw new Error('abuse.ch sends no CORS headers, so this pack only works in the VINEYARD desktop app');
    }
    if (!ctx.net?.fetch) throw new Error('This plugin was not granted its network permission');
}

/** The analyst's Auth-Key, trimmed, or '' when none is set. Never logged, never put in a URL. */
export function authKey(ctx: HostContext): string {
    const k = ctx.config?.auth_key;
    return typeof k === 'string' ? k.trim() : '';
}

export function requireKey(ctx: HostContext): string {
    const k = authKey(ctx);
    if (!k) {
        throw new Error(
            `${KEY_LABEL} is not set. MalwareBazaar, ThreatFox and URLhaus refuse requests without one since 2025-06-30; it is free at https://auth.abuse.ch/ — paste it into this plugin's settings.`,
        );
    }
    return k;
}

/** 429 backoff: 10 s, 20 s, 40 s, or `Retry-After` — capped, so one header cannot park a run. */
const backoffMs = (attempt: number, retryAfterSec: number): number =>
    Math.min(60_000, Number.isFinite(retryAfterSec) && retryAfterSec > 0 ? retryAfterSec * 1000 : 10_000 * 2 ** attempt);

export type Body = { form: Record<string, string> } | { json: Record<string, unknown> };

/**
 * One POST to an abuse.ch API with the Auth-Key header, decoded.
 *
 * Status handling is MEASURED (2026-11-14): no key → 401 `{"error": "Unauthorized"}`; a wrong key →
 * 403 `{"query_status": "unknown_auth_key"}`; a miss is a 200 whose `query_status` says so
 * ("hash_not_found", "no_result", "no_results"), which the caller reads. Both key failures end the
 * run: every later request would get the same answer.
 */
export async function abusePost(ctx: HostContext, url: string, body: Body, key: string): Promise<any> {
    return (await abusePostRaw(ctx, url, body, key)).json;
}

/** The final answer of one abusePost, as keep() hands it over: nothing about the request. */
export interface RawAnswer {
    status: number;
    headers: Record<string, string>;
    text: string;
}

/**
 * abusePost, with the answer it decoded. Only the FINAL response leaves here: a 429 that was
 * waited out says nothing about the indicator and is never returned in place of the answer, and
 * an answer that ends the run (a missing or wrong key) or fails the item is thrown, not returned,
 * so it can never be kept as evidence about a node.
 */
export async function abusePostRaw(ctx: HostContext, url: string, body: Body, key: string): Promise<{ json: any; raw: RawAnswer }> {
    const headers: Record<string, string> = { 'Auth-Key': key, Accept: 'application/json' };
    let payload: string;
    if ('form' in body) {
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
        payload = new URLSearchParams(body.form).toString();
    } else {
        headers['Content-Type'] = 'application/json';
        payload = JSON.stringify(body.json);
    }
    for (let attempt = 0; ; attempt++) {
        if (ctx.signal?.aborted) throw abortErr();
        let res;
        try {
            res = await ctx.net!.fetch!(url, { method: 'POST', headers, body: payload });
        } catch (e) {
            if (ctx.signal?.aborted) throw abortErr();
            throw new ItemFailed(`no answer from ${new URL(url).host} (${e instanceof Error ? e.message : String(e)})`);
        }
        if (res.status === 429) {
            if (attempt < 3) {
                const waitMs = backoffMs(attempt, Number(res.headers?.['retry-after'] ?? NaN));
                ctx.progress?.log?.(`${new URL(url).host} is rate-limiting — waiting ${Math.round(waitMs / 1000)}s`);
                await sleep(waitMs, ctx.signal);
                continue;
            }
            throw new StopRun(`${new URL(url).host} kept refusing requests (HTTP 429) after three waits`);
        }
        let text = '';
        try {
            text = await res.text();
        } catch {
            /* an unreadable body is handled with the status below */
        }
        let json: any = null;
        try {
            json = text ? JSON.parse(text) : null;
        } catch {
            json = null;
        }
        if (res.status === 401) throw new StopRun(`abuse.ch refused the request without a valid ${KEY_LABEL} (HTTP 401)`);
        if (res.status === 403 || json?.query_status === 'unknown_auth_key') {
            throw new StopRun(`abuse.ch does not recognise this ${KEY_LABEL} (${json?.query_status ?? `HTTP ${res.status}`}) — check it at https://auth.abuse.ch/`);
        }
        if (res.status < 200 || res.status >= 300) throw new ItemFailed(`${new URL(url).host} answered HTTP ${res.status}`);
        if (!json || typeof json !== 'object') throw new ItemFailed(`${new URL(url).host} answered with something that is not JSON`);
        return { json, raw: { status: res.status, headers: { ...(res.headers ?? {}) }, text } };
    }
}

/** Refusals already logged in this run, so a budget refusal over 200 nodes is one line, not 200. */
const keepNoted = new WeakMap<HostContext, Set<string>>();

/**
 * Keep one lookup's raw answer on the node it was about (plugin raw results, spec §5). Every call
 * site goes through here, for four reasons:
 *   - desktop builds before ctx.retain have none, and a bare call there is a TypeError that would
 *     fail a run that otherwise works, so the check is `typeof`, not truthiness;
 *   - only status, response headers and body are handed over, built afresh: nothing about the
 *     request (the URL, the form or JSON it posted, the Auth-Key header) can ride along on an
 *     object the host would have to trust;
 *   - the body is the response's own text, never a slice or a re-serialised parse, so what is
 *     kept is the answer abuse.ch sent and the host hashes those bytes. Each call site sends one
 *     request per looked-up node, so no answer is about more than that node (analyst's decision,
 *     2026-11-25: a slice cut from a larger answer is no longer the original and is not kept);
 *   - a refusal (over budget, a config value seen in the body) or a throw costs the raw copy,
 *     never the run: the mapped fields are already staged and are what the analyst ran this for.
 *
 * A "not found" answer (HTTP 200, query_status hash_not_found / no_result / no_results) IS kept:
 * "abuse.ch had nothing on this on this date" is itself a finding. Auth failures never get here.
 */
export async function keep(ctx: HostContext, nodeId: string, op: string, raw: RawAnswer): Promise<void> {
    if (typeof ctx.retain !== 'function') return;
    if (!(raw.status > 0)) return;
    let reason = '';
    try {
        const out = await ctx.retain(nodeId, op, { status: raw.status, headers: { ...raw.headers }, body: raw.text });
        if (out && out.kept === false) reason = typeof out.reason === 'string' && out.reason ? out.reason : 'refused';
    } catch {
        reason = 'the host could not keep it';
    }
    if (!reason) return;
    let noted = keepNoted.get(ctx);
    if (!noted) keepNoted.set(ctx, (noted = new Set()));
    if (noted.has(`${op}\0${reason}`)) return;
    noted.add(`${op}\0${reason}`);
    ctx.progress?.log?.(`Raw ${op} result not kept — ${reason}`);
}

/** `query_status` values that mean "looked, and abuse.ch has nothing": a real negative. */
export const isMiss = (qs: unknown): boolean =>
    typeof qs === 'string' && /^(no_results?|hash_not_found|not_found)$/.test(qs);

export async function selectedOfTypes(ctx: HostContext, types: string[]): Promise<{ nodes: GraphNode[]; other: number }> {
    const nodes: GraphNode[] = [];
    let other = 0;
    for (const id of ctx.input?.selection ?? []) {
        if (ctx.signal?.aborted) throw abortErr();
        const n = await ctx.graph?.get?.(id);
        if (n && types.includes(n.type)) nodes.push(n);
        else other++;
    }
    return { nodes, other };
}

export const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

/**
 * What to say about a StopRun: rethrow when nothing was found yet, otherwise the line the summary
 * ends with. See StopRun for why the two differ.
 */
export function stopped(e: StopRun, foundSoFar: number, notReached: number): string {
    if (!foundSoFar) throw new Error(e.message);
    return `STOPPED: ${e.message}. ${notReached} selected node(s) were not looked up — run them again later`;
}
