// Graph writes shared by the abuse.ch plugins: family nodes and the ThreatFox malware list.
import type { GraphNode, HostContext } from './sdk';
import { abusePost, ItemFailed, StopRun, TF_API } from './common';
import { buildTaxonomy, cleanName, familyKey, needsTaxonomy, resolveFamily, reusableKinds } from './families';
import type { Family, FamilyKind, TaxonomyIndex } from './families';

const TYPE_OF = { malware: 'threat.malware', tool: 'threat.tool' } as const;

/**
 * Family nodes for one run: each family resolved to ONE node, reused where the project has it.
 *
 * WHY AN EXISTING NODE IS LOOKED FOR FIRST, rather than handed to createNode to de-duplicate:
 * `malware_type` is required, abuse.ch never says what kind of malware a family is, and createNode
 * merges whatever it is given onto a node that already exists. Creating "Vidar" with 'unknown' would
 * overwrite the 'stealer' VirusTotal wrote, at commit, on a node the analyst never asked about.
 * An existing node is linked as it stands and nothing on it is written.
 *
 * Found by name under the same normalised key the family table uses, so an analyst's "Formbook" is
 * the "FormBook" abuse.ch reports. Which kind is reused is families.ts's `reusableKinds`.
 *
 * Nodes made this run are keyed by kind AND name. Keyed by name alone, a run that met win.deimos_c2
 * (the DeimosC2 Tool) and then win.deimos (a Malware) pointed both at the first node it made.
 */
export class FamilyNodes {
    private existing: Map<string, Partial<Record<FamilyKind, GraphNode>>> | null = null;
    private made = new Map<string, string>(); // `${kind}:${familyKey}` -> node id, this run
    created = 0;
    linked = 0;

    constructor(private ctx: HostContext) {}

    private async index(): Promise<Map<string, Partial<Record<FamilyKind, GraphNode>>>> {
        if (this.existing) return this.existing;
        const out = new Map<string, Partial<Record<FamilyKind, GraphNode>>>();
        for (const kind of ['malware', 'tool'] as const) {
            try {
                const { nodes } = (await this.ctx.graph?.list?.({ type: TYPE_OF[kind] })) ?? { nodes: [] };
                for (const n of nodes) {
                    if (n.type !== TYPE_OF[kind]) continue;
                    const name = typeof n.data?.name === 'string' ? n.data.name : '';
                    const k = familyKey(name);
                    if (!k) continue;
                    const slot = out.get(k) ?? {};
                    // An exact spelling beats a folded one; among folded ones the first stays.
                    const prior = slot[kind];
                    if (!prior || (prior.data?.name !== name && n.data?.name === name)) slot[kind] = n;
                    out.set(k, slot);
                }
            } catch {
                /* an unreadable list only means nothing is reused */
            }
        }
        this.existing = out;
        return out;
    }

    /** The node id for a family, creating it only when the project has none of a kind it may use. */
    async ensure(f: Family): Promise<string> {
        const k = familyKey(f.name);
        const kinds = reusableKinds(f);
        for (const kind of kinds) {
            const hit = this.made.get(`${kind}:${k}`);
            if (hit) return hit;
        }
        const slot = (await this.index()).get(k) ?? {};
        for (const kind of kinds) {
            const found = slot[kind];
            if (!found) continue;
            this.made.set(`${kind}:${k}`, String(found.id));
            this.linked++;
            return String(found.id);
        }
        const aliases = (f.aliases ?? []).map(cleanName).filter((a) => a && a !== f.name);
        const data: Record<string, unknown> =
            f.kind === 'tool'
                ? { name: f.name, tool_type: f.type }
                : { name: f.name, malware_type: f.type, is_family: true };
        if (aliases.length) data.aliases = [...new Set(aliases)];
        const node = await this.ctx.graph!.createNode!({ type: TYPE_OF[f.kind], data });
        this.made.set(`${f.kind}:${k}`, String(node.id));
        this.created++;
        return String(node.id);
    }

    get count(): number {
        return this.made.size;
    }
}

/**
 * ThreatFox's malware list, fetched at most once per run and only when a name needs it.
 *
 * It is what lets MalwareBazaar's "AgentTesla" and SSLBL's "LummaStealer" land on ThreatFox's
 * "Agent Tesla" and "Lumma Stealer" (families.ts has the measurements). One request of about 470 KB
 * (3,895 families on 2026-11-14), which is why a run whose names are all in the family table never
 * makes it. Failing to get it costs the matching, not the run: names are then kept as the source
 * spells them.
 */
export class Taxonomy {
    private index: TaxonomyIndex | null | undefined;
    unavailable = '';

    constructor(
        private ctx: HostContext,
        private key: string,
    ) {}

    /** Stop using the list for the rest of the run (its key was refused). */
    disable(): void {
        this.key = '';
        this.index = null;
    }

    async for(name: string): Promise<TaxonomyIndex | null> {
        if (!this.key || !needsTaxonomy(name)) return null;
        if (this.index !== undefined) return this.index;
        try {
            const res = await abusePost(this.ctx, TF_API, { json: { query: 'malware_list' } }, this.key);
            this.index = res?.query_status === 'ok' ? buildTaxonomy(res.data) : null;
            if (!this.index) this.unavailable = `ThreatFox's malware list was not available (${res?.query_status ?? 'no status'})`;
        } catch (e) {
            if (e instanceof StopRun) throw e;
            this.index = null;
            this.unavailable = `ThreatFox's malware list was not available (${e instanceof ItemFailed ? e.message : String(e)})`;
        }
        if (this.unavailable) this.ctx.progress?.log?.(`${this.unavailable}; family names are kept as the source spells them`);
        return this.index;
    }

    /** A source's family name, resolved — with the malware list when the key and the name allow. */
    async resolve(name: string): Promise<Family | null> {
        return resolveFamily({ name }, await this.for(name));
    }
}
