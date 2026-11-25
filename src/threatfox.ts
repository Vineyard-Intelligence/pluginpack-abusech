// ThreatFox IOC Lookup — an IP, domain, URL or file hash → the ThreatFox records that list it.
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
    TF_API,
    threat,
} from './common';
import { abuseTime, compact, earliest, entityForIoc, indicatorType, iocIsIp, joinCapped, lookupHost, md5Of, sha1Of, sha256Of } from './convert';
import { resolveFamily } from './families';
import { FamilyNodes } from './graph';

const TYPES = ['infrastructure.ip_address', 'infrastructure.domain', 'web.url', 'threat.file_hash'];

/**
 * The link from an Indicator to the node it identifies, in the words the Threat type pack gives it:
 * "Link it to the concrete typed node it identifies ... with the refers_to edge." This pack is the
 * first to write Indicators, so a wording of its own would make the contract and its first producer
 * disagree, and a skill or query following refers_to would find none of them. That the claim is
 * ThreatFox's is on the indicator (threatfox_*) and on the edge (`source`).
 */
const REFERS_TO = 'refers_to';

/** One ThreatFox IOC record, as `search_ioc` / `search_hash` return it (measured 2026-11-14). */
export interface TfRecord {
    id?: string;
    ioc?: string;
    threat_type?: string;
    threat_type_desc?: string;
    ioc_type?: string;
    ioc_type_desc?: string;
    malware?: string;
    malware_printable?: string;
    malware_alias?: string | null;
    confidence_level?: number;
    first_seen?: string;
    last_seen?: string | null;
    reference?: string | null;
    reporter?: string;
    tags?: string[] | null;
}

/**
 * The searches that find a node's own records, and the test a record must pass to be one.
 *
 * MEASURED 2026-11-14: `search_ioc` matches a SUBSTRING by default ("apij4ya.org" also returned
 * hl.apij4ya.org and gq.apij4ya.org), and `exact_match: true` makes a bare IP find nothing, because
 * ThreatFox lists IPs only as ip:port. So domains, URLs and hashes are searched exactly and IPs
 * loosely, and every record is checked against the node either way: a near-miss record is someone
 * else's indicator, and linking it here would put a family on the wrong node.
 */
export interface OwnSearch {
    body: Record<string, unknown>;
    mine: (r: TfRecord) => boolean;
    /** The raw-result slot this search's answer is kept in (see keep in common.ts). */
    op: string;
}

/**
 * The ops a node's answers are kept under. One per search, not one per plugin: a File Hash is
 * searched once per hash it carries and once more with search_hash, and a shared op would leave
 * only the last of those answers (`latest` is replaced by the next call of the same op).
 */
const OP_IOC = 'threatfox';
const OP_ASSOCIATED = 'threatfox_associated';

export function ownSearches(node: GraphNode): OwnSearch[] {
    const d = node.data ?? {};
    switch (node.type) {
        case 'infrastructure.ip_address': {
            const ip = str(d.ip_address);
            return ip ? [{ body: { query: 'search_ioc', search_term: ip }, mine: (r) => r.ioc_type === 'ip:port' && iocIsIp(r.ioc, ip), op: OP_IOC }] : [];
        }
        case 'infrastructure.domain': {
            // Searched in punycode, and a record matched in either form: the node may hold the
            // Unicode spelling of a name ThreatFox lists in ASCII.
            const dom = lookupHost(d.domain_name);
            if (!dom) return [];
            const names = new Set([dom, str(d.domain_name).toLowerCase().replace(/\.$/, '')]);
            const same = (ioc: unknown) => names.has(str(ioc).toLowerCase().replace(/\.$/, '')) || lookupHost(ioc) === dom;
            return [{ body: { query: 'search_ioc', search_term: dom, exact_match: true }, mine: (r) => r.ioc_type === 'domain' && same(r.ioc), op: OP_IOC }];
        }
        case 'web.url': {
            const url = str(d.url);
            return url ? [{ body: { query: 'search_ioc', search_term: url, exact_match: true }, mine: (r) => r.ioc_type === 'url' && str(r.ioc) === url, op: OP_IOC }] : [];
        }
        case 'threat.file_hash': {
            // ThreatFox lists a sample's hashes as separate IOCs (an md5, a sha1 and a sha256 record
            // for one MiniBrowse payload, measured), so each hash the node carries is its own search.
            const out: OwnSearch[] = [];
            for (const [alg, h] of [['sha256', sha256Of(d.sha256)], ['sha1', sha1Of(d.sha1)], ['md5', md5Of(d.md5)]] as const) {
                if (h) out.push({ body: { query: 'search_ioc', search_term: h, exact_match: true }, mine: (r) => str(r.ioc).toLowerCase() === h && /_hash$/.test(r.ioc_type ?? ''), op: `${OP_IOC}_${alg}` });
            }
            return out;
        }
        default:
            return [];
    }
}

/**
 * ThreatFox's 0–100 `confidence_level`, kept as the number.
 *
 * NOT written to threat.indicator.confidence: the type pack defines that as the ANALYST'S
 * confidence, and a reporter's self-assessed score is not that. The number goes in
 * `threatfox_confidence`, where nobody can read it as the analyst's judgement.
 */
const confidenceOf = (recs: TfRecord[]): number | undefined => {
    const xs = recs.map((r) => r.confidence_level).filter((n): n is number => typeof n === 'number' && Number.isFinite(n));
    return xs.length ? Math.max(...xs) : undefined;
};

/**
 * The records ThreatFox holds for ONE IOC string, as one threat.indicator node.
 *
 * One IOC can be several records — reported twice, or for two families — and the indicator's
 * identity is its value, so they are folded: the earliest first sighting, the latest last one, the
 * highest confidence, every id, reporter and family. Folded rather than written record by record,
 * which would leave whichever record came last on the node.
 */
export function indicatorData(ioc: string, recs: TfRecord[]): Record<string, unknown> {
    let first: string | undefined;
    let last: string | undefined;
    for (const r of recs) {
        first = earliest(first, abuseTime(r.first_seen));
        const l = abuseTime(r.last_seen ?? undefined);
        if (l && (!last || l > last)) last = l;
    }
    const ids = recs.map((r) => str(r.id)).filter(Boolean);
    return compact({
        value: ioc,
        indicator_type: indicatorType(recs[0]?.ioc_type, ioc),
        valid_from: first,
        description: joinCapped(recs.map((r) => str(r.ioc_type_desc) || str(r.threat_type_desc)), 5)?.replace(/, /g, '; '),
        threatfox_id: joinCapped(ids),
        threatfox_url: joinCapped(ids.map((id) => `https://threatfox.abuse.ch/ioc/${id}/`)),
        threatfox_malware: joinCapped(recs.map((r) => str(r.malware_printable))),
        threatfox_threat_type: joinCapped(recs.map((r) => str(r.threat_type))),
        threatfox_confidence: confidenceOf(recs),
        threatfox_reporter: joinCapped(recs.map((r) => str(r.reporter))),
        threatfox_last_seen: last,
        threatfox_tags: joinCapped(recs.flatMap((r) => (Array.isArray(r.tags) ? r.tags : []))),
        threatfox_reference: joinCapped(recs.map((r) => str(r.reference ?? ''))),
    });
}

/** Records grouped by IOC string, first-seen order, at most `cap` IOCs; `dropped` is the rest. */
export function groupByIoc(recs: TfRecord[], cap: number): { groups: Array<[string, TfRecord[]]>; dropped: number } {
    const by = new Map<string, TfRecord[]>();
    for (const r of recs) {
        const ioc = str(r.ioc);
        if (!ioc) continue;
        if (!by.has(ioc)) by.set(ioc, []);
        const list = by.get(ioc)!;
        if (!list.some((x) => x.id && x.id === r.id)) list.push(r);
    }
    const all = [...by.entries()];
    return { groups: all.slice(0, cap), dropped: Math.max(0, all.length - cap) };
}

/**
 * One ThreatFox search for one selected node, its answer kept whole on that node under `op`.
 *
 * Whole, even when it lists several IOC records (one IP on several ports, one IOC reported twice):
 * the request named this node's value and nothing else, so every record in the answer is ThreatFox
 * answering about it, near-misses of the loose IP search included — which records were taken is
 * the plugin's mapping, and the indicator nodes made from them get no copy (spec §5-3). A
 * no_result is kept too; so is an illegal_search_term, which is ThreatFox's answer about the value.
 */
async function search(ctx: HostContext, key: string, body: Record<string, unknown>, nodeId: string, op: string): Promise<TfRecord[]> {
    const { json: res, raw } = await abusePostRaw(ctx, TF_API, { json: body }, key);
    await keep(ctx, nodeId, op, raw);
    if (isMiss(res.query_status)) return [];
    if (res.query_status !== 'ok') {
        // illegal_search_term and the like: a value ThreatFox will not search, not an error.
        ctx.progress?.log?.(`ThreatFox: ${String(body.search_term ?? body.hash ?? '')} — ${res.query_status ?? 'no status'}`);
        return [];
    }
    return Array.isArray(res.data) ? (res.data as TfRecord[]) : [];
}

export const threatFox = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.abusech_threatfox',
        content_type: 'vineyard:plugin',
        name: 'ThreatFox IOC Lookup',
        version: '1.1.0',
        description:
            "Searches abuse.ch ThreatFox for each selected IP Address, Domain, URL or File Hash. Each ThreatFox record that lists it becomes an Indicator (the IOC as ThreatFox lists it, an IP with its port) linked to it by refers_to, carrying valid_from (first seen), threatfox_confidence (0-100), threatfox_reporter, threatfox_threat_type, threatfox_last_seen, threatfox_tags and threatfox_url, and linked 'indicates' to its Malware or Tool family, named as IP Classification names it (DcRAT, Cobalt Strike as a Tool). For a File Hash it also adds the indicators ThreatFox ties to the sample, usually its C2, linked 'associated in ThreatFox with', each referring to its IP Address, Domain or URL. Placeholder families ('Unknown malware') make no node. Up to max_records (default 50) indicators per node. Needs an abuse.ch Auth-Key. Desktop only.",
        icon: 'crosshair',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                max_records: {
                    type: 'integer',
                    title: 'Max indicators per node',
                    default: 50,
                    minimum: 1,
                    maximum: 200,
                    description: 'Indicators past this many for one selected node are counted in the summary, not added. Default 50.',
                },
            },
        },
        io: {
            consumes: [infra('ip_address'), infra('domain'), infra('url', 'web'), threat('file_hash')],
            produces: [threat('indicator'), threat('malware'), threat('tool'), infra('ip_address'), infra('domain'), infra('url', 'web'), threat('file_hash')],
        },
        scopes: { graph: GRAPH_SCOPES, network: NETWORK, config: [KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },

    async run(ctx: HostContext): Promise<RunResult> {
        refuseOnWeb(ctx);
        const { nodes, other } = await selectedOfTypes(ctx, TYPES);
        if (!nodes.length) {
            return { summary: 'Select IP Address, Domain, URL or File Hash nodes first', counts: { checked: 0, listed: 0, indicators: 0 } };
        }
        const key = requireKey(ctx);
        const cap = Math.min(200, Math.max(1, Math.floor(Number(ctx.params?.max_records) || 50)));
        const families = new FamilyNodes(ctx);
        const indicatorIds = new Map<string, string>(); // IOC string -> node id, this run
        let listed = 0;
        let clean = 0;
        let associated = 0;
        let capped = 0;
        let refusedEntities = 0;
        let placeholders = 0;
        let failed = 0;
        let unusable = 0;
        let wrote = 0;
        let stop = '';

        /**
         * One IOC's records → its indicator node, linked to each family the records name. Once per
         * IOC per run: a second selected node reaching the same IOC links to it, and does not write
         * its own (possibly partial) set of records over the folded one.
         */
        const indicatorFor = async (ioc: string, recs: TfRecord[]): Promise<string> => {
            const known = indicatorIds.get(ioc);
            if (known) return known;
            const node = await ctx.graph!.createNode!({ type: 'threat.indicator', data: indicatorData(ioc, recs) });
            const id = String(node.id);
            indicatorIds.set(ioc, id);
            wrote++;
            // De-duplicated by the node a family lands on, not by its name: win.deimos_c2 and
            // win.deimos on one IOC are both "Deimos", and two families.
            const seen = new Set<string>();
            for (const r of recs) {
                const fam = resolveFamily({
                    name: str(r.malware_printable),
                    id: str(r.malware) || undefined,
                    aliases: typeof r.malware_alias === 'string' ? r.malware_alias.split(',') : [],
                });
                if (!fam) {
                    placeholders++;
                    continue;
                }
                const famId = await families.ensure(fam);
                if (seen.has(famId)) continue;
                seen.add(famId);
                await ctx.graph!.createEdge!({
                    from: id,
                    to: famId,
                    label: 'indicates',
                    data: compact({ source: 'threatfox', threat_type: str(r.threat_type), threatfox_confidence: r.confidence_level }),
                });
            }
            return id;
        };

        for (let i = 0; i < nodes.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const node = nodes[i];
            const searches = ownSearches(node);
            if (!searches.length) {
                unusable++;
                ctx.progress?.log?.(`${node.id}: no value ThreatFox can search`);
                continue;
            }
            ctx.progress?.set?.({ percent: Math.round((i / nodes.length) * 100), message: `ThreatFox: ${String(searches[0].body.search_term)}` });
            try {
                const own: TfRecord[] = [];
                for (const s of searches) own.push(...(await search(ctx, key, s.body, node.id, s.op)).filter(s.mine));
                const { groups, dropped } = groupByIoc(own, cap);
                capped += dropped;
                for (const [ioc, recs] of groups) {
                    const indId = await indicatorFor(ioc, recs);
                    await ctx.graph!.createEdge!({ from: indId, to: node.id, label: REFERS_TO, data: { source: 'threatfox' } });
                }
                if (groups.length) listed++;

                // A sample's ThreatFox neighbourhood: the IOCs whose records list this file among
                // their malware samples — in practice the C2 it was seen talking to. `search_hash`
                // takes an md5 or a sha256 (ThreatFox API docs), not a sha1.
                let neighbours = 0;
                if (node.type === 'threat.file_hash') {
                    const h = sha256Of(node.data?.sha256) ?? md5Of(node.data?.md5);
                    const recs = h ? await search(ctx, key, { query: 'search_hash', hash: h }, node.id, OP_ASSOCIATED) : [];
                    // The file's own hash IOCs are already linked above, and a record can list the
                    // sample it IS among its own samples; neither is a neighbour.
                    const d = node.data ?? {};
                    const self = new Set([...own.map((r) => str(r.ioc).toLowerCase()), sha256Of(d.sha256), sha1Of(d.sha1), md5Of(d.md5)].filter(Boolean));
                    const other = recs.filter((r) => !self.has(str(r.ioc).toLowerCase()));
                    const grouped = groupByIoc(other, cap);
                    capped += grouped.dropped;
                    for (const [ioc, rs] of grouped.groups) {
                        const indId = await indicatorFor(ioc, rs);
                        await ctx.graph!.createEdge!({ from: node.id, to: indId, label: 'associated in ThreatFox with', data: { source: 'threatfox' } });
                        // The IOC as the entity other plugins can take further (Shodan, URLhaus, …).
                        // An md5 or sha1 IOC has no such node: a File Hash needs its SHA-256.
                        const ent = entityForIoc(rs[0]?.ioc_type, ioc);
                        if (ent) {
                            // A project on an older type pack can refuse what the copied rule takes
                            // (an internationalised domain on Infrastructure 4.2): the indicator
                            // stays, holding the value, and the entity is counted instead.
                            let e: GraphNode | null = null;
                            try {
                                e = await ctx.graph!.createNode!(ent);
                            } catch (err) {
                                if ((err as Error)?.name === 'AbortError') throw err;
                                refusedEntities++;
                                ctx.progress?.log?.(`${ioc}: ${err instanceof Error ? err.message : String(err)}`);
                            }
                            if (e) await ctx.graph!.createEdge!({ from: indId, to: String(e.id), label: REFERS_TO, data: { source: 'threatfox' } });
                        }
                        neighbours++;
                    }
                    associated += neighbours;
                }
                if (!groups.length && !neighbours) clean++;
            } catch (e) {
                if (e instanceof StopRun) {
                    stop = stopped(e, wrote, nodes.length - i);
                    break;
                }
                if (e instanceof ItemFailed) {
                    failed++;
                    ctx.progress?.log?.(`${node.id}: ${e.message}`);
                    continue;
                }
                throw e;
            }
        }
        ctx.progress?.set?.({ percent: 100 });

        const parts = [`${listed} of ${nodes.length} node(s) listed in ThreatFox, ${indicatorIds.size} indicator(s)`];
        if (associated) parts.push(`${associated} indicator(s) tied to the selected samples`);
        if (families.count) parts.push(`${families.count} family/families (${families.created} new)`);
        if (placeholders) parts.push(`${placeholders} record(s) name no family ('Unknown malware' and the like), so no family node`);
        if (capped) parts.push(`${capped} indicator(s) past max_records were not added`);
        if (refusedEntities) parts.push(`${refusedEntities} indicator value(s) this project's types refuse kept on the indicator only (Infrastructure 4.3 or later takes internationalised domains)`);
        if (clean) parts.push(`${clean} node(s) have no ThreatFox record — a real negative, not a failed lookup`);
        if (other) parts.push(`${other} selected node(s) are a type ThreatFox has no search for`);
        if (unusable) parts.push(`${unusable} skipped (no value ThreatFox can search)`);
        if (failed) parts.push(`${failed} lookup(s) failed`);
        if (stop) parts.push(stop);
        return {
            summary: parts.join('. ') + '.',
            counts: { checked: nodes.length, listed, indicators: indicatorIds.size, associated, families: families.count, not_listed: clean, skipped: unusable, failed },
        };
    },
});
