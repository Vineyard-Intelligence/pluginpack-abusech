// SSLBL Certificate Check — a TLS Certificate → whether abuse.ch SSLBL lists it, and for which family.
//
// SSLBL publishes two lists that matter here, and only one is alive. Measured 2026-11-14:
//
//   sslipblacklist.csv  Botnet C2 IP Blacklist — "deprecated on 2025-01-03", 545 bytes, no rows.
//   sslblacklist.csv    SSL Certificate Blacklist — 11,261 certificates by SHA-1, updated daily,
//                       each with the family whose C2 presented it.
//
// So this checks certificates, not IPs. The list is keyed by SHA-1, which no certificate in a project
// carried until infrastructure 4.2.0 added `fingerprint_sha1` and Shodan, Censys and VirusTotal began
// filling it; a SHA-1 cannot be computed from the SHA-256 that identifies a certificate. A
// certificate without one is counted and named, so the analyst knows to re-run the pack that found it.
//
// There is no query API: the feed is downloaded once per run (849 KB) and matched locally, so which
// certificates were checked never leaves the machine. It is CC0 (abuse.ch terms §3.4) and needs no
// Auth-Key; with one, family names are matched to ThreatFox's (graph.ts, Taxonomy).
import { definePlugin } from './sdk';
import type { HostContext, RunResult } from './sdk';
import {
    abortErr,
    authKey,
    GRAPH_SCOPES,
    infra,
    KEY_CONFIG_OPTIONAL,
    LIFECYCLE,
    NETWORK,
    PLATFORMS,
    refuseOnWeb,
    selectedOfTypes,
    SSLBL_FEED,
    StopRun,
    threat,
} from './common';
import { compact, parseSslblFeed, sha1Of, sslblFeedProblem } from './convert';
import { parseSslblReason } from './families';
import { FamilyNodes, Taxonomy } from './graph';

const LABEL = { c2: 'used as C2', distribution: 'used for malware distribution', mitm: 'used for MITM' } as const;

export const sslbl = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.abusech_sslbl',
        content_type: 'vineyard:plugin',
        name: 'SSLBL Certificate Check',
        version: '1.0.0',
        description:
            "Checks each selected TLS Certificate against the abuse.ch SSLBL SSL Certificate Blacklist, which lists certificates seen on botnet C2 and malware-distribution servers by SHA-1. Needs the certificate's fingerprint_sha1, which Shodan Host, Censys Host Lookup and the VirusTotal reports write; a certificate without one is counted, not checked. A listed certificate gets sslbl_listed (listing date) and sslbl_reason, and the family SSLBL names becomes a Malware or Tool linked 'used as C2', 'used for malware distribution' or 'used for MITM'. Downloads the whole list once per run, so which certificates were checked is not sent anywhere. The Auth-Key is optional: SSLBL needs none, and with one family names are matched to ThreatFox's. Desktop only.",
        icon: 'shield-alert',
        platforms: PLATFORMS,
        io: {
            consumes: [infra('certificate')],
            produces: [threat('malware'), threat('tool')],
        },
        scopes: { graph: GRAPH_SCOPES, network: NETWORK, config: [KEY_CONFIG_OPTIONAL] },
        lifecycle: LIFECYCLE,
    },

    async run(ctx: HostContext): Promise<RunResult> {
        refuseOnWeb(ctx);
        const { nodes, other } = await selectedOfTypes(ctx, ['infrastructure.certificate']);
        if (!nodes.length) return { summary: 'Select TLS Certificate nodes first', counts: { checked: 0, listed: 0 } };
        const withSha1 = nodes.filter((n) => sha1Of(n.data?.fingerprint_sha1));
        const noSha1 = nodes.length - withSha1.length;
        const reRun =
            'run Shodan Host, Censys Host Lookup or VT IP/Domain Report again on the IPs or domains that present them (their current versions write the SHA-1)';
        if (!withSha1.length) {
            // Nothing to match, so nothing is downloaded.
            return {
                summary: `None of the ${nodes.length} certificate(s) carries a fingerprint_sha1, which SSLBL lists certificates by — ${reRun}.`,
                counts: { checked: 0, listed: 0, no_sha1: noSha1 },
            };
        }

        ctx.progress?.set?.({ percent: 5, message: 'Downloading the SSLBL certificate blacklist' });
        let text: string;
        try {
            const res = await ctx.net!.fetch!(SSLBL_FEED, { method: 'GET' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            text = await res.text();
        } catch (e) {
            if (ctx.signal?.aborted) throw abortErr();
            throw new Error(`Could not download the SSLBL certificate blacklist (${e instanceof Error ? e.message : String(e)})`);
        }
        const feed = parseSslblFeed(text);
        const problem = sslblFeedProblem(feed);
        if (problem) {
            // Thrown, not summarised: a partial list would turn listed certificates into "not
            // listed", and a run that writes nothing is the honest result (convert.ts has the case).
            throw new Error(`The SSLBL certificate blacklist arrived incomplete (${problem}); no certificate was checked. Run it again in a few minutes.`);
        }

        const families = new FamilyNodes(ctx);
        const taxonomy = new Taxonomy(ctx, authKey(ctx));
        let listed = 0;
        let stop = '';
        for (let i = 0; i < withSha1.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const node = withSha1[i];
            const sha1 = sha1Of(node.data?.fingerprint_sha1)!;
            const hit = feed.rows.get(sha1);
            if (!hit) continue;
            listed++;
            ctx.progress?.set?.({ percent: 10 + Math.round((i / withSha1.length) * 90), message: `SSLBL: ${sha1}` });
            await ctx.graph!.updateNode!(node.id, compact({ sslbl_listed: hit.listed, sslbl_reason: hit.reason }));
            const parsed = parseSslblReason(hit.reason);
            if (!parsed) continue;
            let fam;
            try {
                fam = await taxonomy.resolve(parsed.family);
            } catch (e) {
                // Only the optional malware-list fetch can raise this, and SSLBL itself needs no key:
                // carry on without the list rather than lose the run over the optional part.
                if (!(e instanceof StopRun)) throw e;
                stop = `The Auth-Key was refused (${e.message}), so family names are as SSLBL spells them`;
                taxonomy.disable();
                fam = await taxonomy.resolve(parsed.family);
            }
            if (!fam) continue;
            const famId = await families.ensure(fam);
            await ctx.graph!.createEdge!({
                from: node.id,
                to: famId,
                label: LABEL[parsed.use],
                data: compact({ source: 'sslbl', listed: hit.listed }),
            });
        }
        ctx.progress?.set?.({ percent: 100 });

        const asOf = feed.updated ? ` (list of ${feed.updated.slice(0, 10)}, ${feed.rows.size} certificates)` : '';
        const parts = [`${listed} of ${withSha1.length} certificate(s) listed by SSLBL${asOf}`];
        if (families.count) parts.push(`${families.count} family/families (${families.created} new)`);
        if (withSha1.length - listed) parts.push(`${withSha1.length - listed} not listed`);
        if (noSha1) parts.push(`${noSha1} certificate(s) have no fingerprint_sha1 and were not checked — ${reRun}`);
        if (other) parts.push(`${other} selected node(s) are not TLS Certificates`);
        if (!authKey(ctx) && families.count) parts.push("No Auth-Key, so family names outside IP Classification's are as SSLBL spells them");
        if (taxonomy.unavailable) parts.push(`${taxonomy.unavailable}, so family names are as SSLBL spells them`);
        if (stop) parts.push(stop);
        return {
            summary: parts.join('. ') + '.',
            counts: { checked: withSha1.length, listed, families: families.count, no_sha1: noSha1 },
        };
    },
});
