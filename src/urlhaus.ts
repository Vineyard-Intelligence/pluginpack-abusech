// URLhaus Lookup — a URL, host or payload hash → the malware-distribution URLs and payloads around it.
import { definePlugin } from './sdk';
import type { GraphNode, HostContext, RunResult } from './sdk';
import {
    abortErr,
    abusePostRaw,
    GRAPH_SCOPES,
    infra,
    isMiss,
    ItemFailed,
    keep,
    KEY_CONFIG,
    LIFECYCLE,
    NETWORK,
    PLATFORMS,
    refuseOnWeb,
    requireKey,
    selectedOfTypes,
    StopRun,
    stopped,
    str,
    threat,
    UH_API,
} from './common';
import { abuseTime, compact, intOf, isIp, joinCapped, lookupHost, md5Of, sha256Of, URL_RE } from './convert';
import { FamilyNodes, Taxonomy } from './graph';

const TYPES = ['web.url', 'infrastructure.domain', 'infrastructure.ip_address', 'threat.file_hash'];

/** The blocklists URLhaus reports that LIST the value ("spamhaus_dbl: abused_legit_malware"); "not listed" is dropped. */
export function listedOn(bl: unknown): string | undefined {
    if (!bl || typeof bl !== 'object') return undefined;
    const parts = Object.entries(bl as Record<string, unknown>)
        .filter(([, v]) => typeof v === 'string' && v && v !== 'not listed')
        .map(([k, v]) => `${k}: ${v}`);
    return joinCapped(parts);
}

/** URLhaus's view of one URL, `urlhaus_`-prefixed: it is one tracker's record, not the URL itself. */
export function urlFields(u: any): Record<string, unknown> {
    return compact({
        urlhaus_status: str(u?.url_status),
        urlhaus_threat: str(u?.threat),
        urlhaus_first_seen: abuseTime(u?.date_added),
        urlhaus_last_online: abuseTime(u?.last_online),
        urlhaus_tags: joinCapped(Array.isArray(u?.tags) ? u.tags : []),
        urlhaus_reporter: str(u?.reporter),
        urlhaus_blacklists: listedOn(u?.blacklists),
        urlhaus_url: str(u?.urlhaus_reference),
    });
}

/** What a request needs for one node, or null when the node carries no value URLhaus takes. */
function request(node: GraphNode): { path: string; form: Record<string, string>; label: string } | null {
    const d = node.data ?? {};
    switch (node.type) {
        case 'web.url': {
            const url = str(d.url);
            return URL_RE.test(url) ? { path: 'url/', form: { url }, label: url } : null;
        }
        case 'infrastructure.domain': {
            const host = lookupHost(d.domain_name);
            return host ? { path: 'host/', form: { host }, label: host } : null;
        }
        case 'infrastructure.ip_address': {
            const host = str(d.ip_address);
            return isIp(host) ? { path: 'host/', form: { host }, label: host } : null;
        }
        case 'threat.file_hash': {
            // URLhaus indexes payloads by md5 and sha256 only.
            const sha256 = sha256Of(d.sha256);
            if (sha256) return { path: 'payload/', form: { sha256_hash: sha256 }, label: sha256 };
            const md5 = md5Of(d.md5);
            return md5 ? { path: 'payload/', form: { md5_hash: md5 }, label: md5 } : null;
        }
        default:
            return null;
    }
}

export const urlhaus = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.abusech_urlhaus',
        content_type: 'vineyard:plugin',
        name: 'URLhaus Lookup',
        version: '1.2.0',
        description:
            "Looks up each selected URL, Domain, IP Address or File Hash in abuse.ch URLhaus, the tracker of malware-distribution URLs. A URL gets urlhaus_status (online/offline), urlhaus_threat, urlhaus_first_seen, urlhaus_tags, urlhaus_reporter, urlhaus_blacklists and urlhaus_url, and each payload it served becomes a File Hash linked 'served file'. A Domain or IP Address gets urlhaus_url_count and urlhaus_first_seen, and the URLs URLhaus lists on it become URLs linked 'hosts'. A File Hash gets urlhaus_signature, urlhaus_file_type, urlhaus_first_seen, urlhaus_last_seen and urlhaus_url_count, and the URLs that served it become URLs linked 'served file'. A payload's signature becomes a Malware or Tool family linked 'classified as'. Up to max_items (default 25) URLs or payloads per node. Needs an abuse.ch Auth-Key. Desktop only.",
        icon: 'link',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                max_items: {
                    type: 'integer',
                    title: 'Max URLs or payloads per node',
                    default: 25,
                    minimum: 1,
                    maximum: 100,
                    description:
                        'URLs or payloads past this many for one node are counted, not added. A shared host or a botnet payload can have thousands (one Mozi sample: 760,668 URLs). Default 25.',
                },
            },
        },
        io: {
            consumes: [infra('url', 'web'), infra('domain'), infra('ip_address'), threat('file_hash')],
            produces: [infra('url', 'web'), threat('file_hash'), threat('malware'), threat('tool')],
        },
        scopes: { graph: GRAPH_SCOPES, network: NETWORK, config: [KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },

    async run(ctx: HostContext): Promise<RunResult> {
        refuseOnWeb(ctx);
        const { nodes, other } = await selectedOfTypes(ctx, TYPES);
        if (!nodes.length) {
            return { summary: 'Select URL, Domain, IP Address or File Hash nodes first', counts: { checked: 0, found: 0 } };
        }
        const key = requireKey(ctx);
        const cap = Math.min(100, Math.max(1, Math.floor(Number(ctx.params?.max_items) || 25)));
        const families = new FamilyNodes(ctx);
        const taxonomy = new Taxonomy(ctx, key);
        let found = 0;
        let absent = 0;
        let unusable = 0;
        let failed = 0;
        let urls = 0;
        let payloads = 0;
        let capped = 0;
        let wrote = 0;
        let stop = '';

        const classify = async (fileId: string, signature: unknown) => {
            const sig = str(signature);
            const fam = sig ? await taxonomy.resolve(sig) : null;
            if (!fam) return;
            const famId = await families.ensure(fam);
            await ctx.graph!.createEdge!({ from: fileId, to: famId, label: 'classified as', data: { source: 'urlhaus' } });
        };

        for (let i = 0; i < nodes.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const node = nodes[i];
            const req = request(node);
            if (!req) {
                unusable++;
                continue;
            }
            ctx.progress?.set?.({ percent: Math.round((i / nodes.length) * 100), message: `URLhaus: ${req.label}` });
            try {
                const answer = await abusePostRaw(ctx, UH_API + req.path, { form: req.form }, key);
                const res = answer.json;
                // The whole answer, on the node looked up: one URL, host or payload per request, so
                // the URLs or payloads it lists are that node's, not a page of other nodes'. The
                // nodes made from them are derived and get no copy (spec §5-3): the edge to this
                // node is where they came from. A no_results adds nothing to the node and is not
                // kept (keep in common.ts).
                await keep(ctx, node.id, 'urlhaus', answer);
                if (isMiss(res.query_status)) {
                    absent++;
                    continue;
                }
                if (res.query_status !== 'ok') {
                    unusable++;
                    ctx.progress?.log?.(`${req.label}: URLhaus answered ${res.query_status ?? 'nothing'}`);
                    continue;
                }
                found++;

                if (req.path === 'url/') {
                    await ctx.graph!.updateNode!(node.id, urlFields(res));
                    wrote++;
                    const list = Array.isArray(res.payloads) ? res.payloads : [];
                    capped += Math.max(0, list.length - cap);
                    for (const p of list.slice(0, cap)) {
                        const sha256 = sha256Of(p?.response_sha256);
                        if (!sha256) continue;
                        const file = await ctx.graph!.createNode!({
                            type: 'threat.file_hash',
                            data: compact({ sha256, md5: md5Of(p?.response_md5), size: intOf(p?.response_size) }),
                        });
                        await ctx.graph!.createEdge!({
                            from: node.id,
                            to: String(file.id),
                            label: 'served file',
                            data: compact({ source: 'urlhaus', first_seen: abuseTime(p?.firstseen), filename: str(p?.filename) }),
                        });
                        await classify(String(file.id), p?.signature);
                        payloads++;
                    }
                } else if (req.path === 'host/') {
                    const count = intOf(res.url_count);
                    await ctx.graph!.updateNode!(
                        node.id,
                        compact({
                            urlhaus_url_count: count,
                            urlhaus_first_seen: abuseTime(res.firstseen),
                            urlhaus_blacklists: listedOn(res.blacklists),
                            urlhaus_url: str(res.urlhaus_reference),
                        }),
                    );
                    wrote++;
                    const list = Array.isArray(res.urls) ? res.urls : [];
                    // The API returns at most 100 of a host's URLs (measured: github.com, 63,227).
                    const total = Math.max(list.length, count ?? 0);
                    if (total > cap) {
                        capped += total - cap;
                        ctx.progress?.log?.(`${req.label}: URLhaus lists ${total} URL(s); the ${cap} newest were added`);
                    }
                    for (const u of list.slice(0, cap)) {
                        const url = str(u?.url);
                        if (!URL_RE.test(url)) continue;
                        const un = await ctx.graph!.createNode!({ type: 'web.url', data: { url, ...urlFields(u) } });
                        await ctx.graph!.createEdge!({ from: node.id, to: String(un.id), label: 'hosts', data: { source: 'urlhaus' } });
                        urls++;
                    }
                } else {
                    // URLhaus's first sighting stays urlhaus_first_seen and first_seen is left to
                    // the scanner that writes it, as in MalwareBazaar (mbDelta has why).
                    const d = node.data ?? {};
                    await ctx.graph!.updateNode!(
                        node.id,
                        compact({
                            sha256: sha256Of(d.sha256) ? undefined : sha256Of(res.sha256_hash),
                            md5: md5Of(d.md5) ? undefined : md5Of(res.md5_hash),
                            size: typeof d.size === 'number' ? undefined : intOf(res.file_size),
                            urlhaus_signature: str(res.signature),
                            urlhaus_file_type: str(res.file_type),
                            urlhaus_first_seen: abuseTime(res.firstseen),
                            urlhaus_last_seen: abuseTime(res.lastseen),
                            urlhaus_url_count: intOf(res.url_count),
                        }),
                    );
                    wrote++;
                    await classify(node.id, res.signature);
                    const list = Array.isArray(res.urls) ? res.urls : [];
                    const total = Math.max(list.length, intOf(res.url_count) ?? 0);
                    if (total > cap) {
                        capped += total - cap;
                        ctx.progress?.log?.(`${req.label}: URLhaus lists ${total} URL(s) that served it; ${cap} were added`);
                    }
                    for (const u of list.slice(0, cap)) {
                        const url = str(u?.url);
                        if (!URL_RE.test(url)) continue;
                        const un = await ctx.graph!.createNode!({
                            type: 'web.url',
                            data: compact({ url, urlhaus_status: str(u?.url_status), urlhaus_url: str(u?.urlhaus_reference) }),
                        });
                        await ctx.graph!.createEdge!({
                            from: String(un.id),
                            to: node.id,
                            label: 'served file',
                            data: compact({ source: 'urlhaus', first_seen: abuseTime(u?.firstseen), filename: str(u?.filename) }),
                        });
                        urls++;
                    }
                }
            } catch (e) {
                if (e instanceof StopRun) {
                    stop = stopped(e, wrote, nodes.length - i);
                    break;
                }
                if (e instanceof ItemFailed) {
                    failed++;
                    ctx.progress?.log?.(`${req.label}: ${e.message}`);
                    continue;
                }
                throw e;
            }
        }
        ctx.progress?.set?.({ percent: 100 });

        const parts = [`${found} of ${nodes.length} node(s) found in URLhaus`];
        if (urls) parts.push(`${urls} URL(s)`);
        if (payloads) parts.push(`${payloads} payload(s)`);
        if (families.count) parts.push(`${families.count} family/families (${families.created} new)`);
        if (capped) parts.push(`${capped} URL(s) or payload(s) past max_items were not added`);
        if (absent) parts.push(`${absent} not in URLhaus — a real negative, not a failed lookup`);
        if (unusable) parts.push(`${unusable} skipped (no value URLhaus takes)`);
        if (other) parts.push(`${other} selected node(s) are a type URLhaus has no lookup for`);
        if (failed) parts.push(`${failed} lookup(s) failed`);
        if (taxonomy.unavailable) parts.push(`${taxonomy.unavailable}, so family names are as URLhaus spells them`);
        if (stop) parts.push(stop);
        return {
            summary: parts.join('. ') + '.',
            counts: { checked: nodes.length, found, urls, payloads, families: families.count, not_found: absent, skipped: unusable, failed },
        };
    },
});
