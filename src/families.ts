// Malware family names: one family, one node, whichever source named it. Pure and import-free, so
// test/pure.test.mjs can bundle and call it without a host.
//
// WHY THIS EXISTS. `threat.malware` and `threat.tool` are identified by `name`, byte for byte, and
// the sources disagree about spelling. Measured 2026-11-14:
//
//   ip-classification   DcRAT       Quasar      Remcos      Cobalt Strike   (dataset.json)
//   ThreatFox           DCRat       Quasar RAT  Remcos      Cobalt Strike   (malware_printable)
//   MalwareBazaar       DCRat       QuasarRAT   RemcosRAT   CobaltStrike    (signature)
//   SSLBL               DCRat C&C   QuasarRAT   RemcosRAT   CobaltStrike    (Listingreason)
//
// Written as each source spells it, one family becomes up to four nodes and the pivot it exists for
// — "these samples, these C2s and this IP belong to the same family" — never forms. So:
//
//   1. The 36 families IP Classification already writes keep ITS name and ITS type (Cobalt Strike
//      and the other frameworks are `threat.tool`, the rest `threat.malware` with its malware_type).
//      That pack had them first, and changing its spelling would move every node it already made.
//   2. Every other family takes ThreatFox's `malware_printable`. ThreatFox is the one abuse.ch
//      source that keys families by an id (Malpedia's, "win.dcrat") and lists their aliases, so its
//      name is the closest thing abuse.ch has to a canonical one. MalwareBazaar and SSLBL names are
//      matched to it through those aliases when the run has the malware list (see TaxonomyIndex).
//   3. A name nothing matches is kept as the source wrote it.
//
// MATCHING IS EXACT ON A NORMALISED KEY, never a similarity score: lowercase, letters and digits
// only. "DCRat" and "DcRAT" are one key; "Gh0st" and "Ghost" are two, and so are "Posh" and
// "POSHSPY". A similarity rule is the thing that would merge two different families on the one
// case where the difference decides it, and a missed merge costs a duplicate node the analyst can
// merge by hand, where a wrong one destroys the distinction.

export type FamilyKind = 'malware' | 'tool';

export interface Family {
    name: string;
    kind: FamilyKind;
    /** malware_type for a malware, tool_type for a tool. 'unknown' only for malware. */
    type: string;
    aliases?: string[];
}

/** Lowercase letters and digits only — the key two spellings must share to be one family. */
export const familyKey = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]/g, '');

/** Trimmed, inner whitespace collapsed ("GhostPenguin " is a live ThreatFox printable). */
export const cleanName = (s: string): string => s.replace(/\s+/g, ' ').trim();

interface KnownFamily extends Family {
    /** ThreatFox `malware` ids that ARE this family. */
    ids: string[];
    /** Other spellings abuse.ch uses for it, beyond what familyKey already folds. */
    spellings: string[];
}

/**
 * IP Classification's families (pluginpack-ip-classification/src/dataset.json, `c2Families`), with
 * the ThreatFox ids and spellings abuse.ch uses for each, read from ThreatFox's malware list and
 * SSLBL's blacklist on 2026-11-14.
 *
 * An id is mapped only when abuse.ch's own data names the family: its printable is the family, or
 * the family is one of its aliases. So `win.grunt` ("GRUNT", alias "Covenant") is Covenant, while
 * `win.meterpreter` is not Metasploit and `win.loki_mythic` is not Mythic — related, but abuse.ch
 * tracks them as families of their own, and so does this. `win.deimos` is a different malware from
 * the DeimosC2 framework and is deliberately absent: ids are matched before names (see resolve), and
 * reusableKinds keeps the "Deimos" it resolves to off the DeimosC2 Tool.
 *
 * Checked against the whole list: every other ThreatFox id whose printable or alias spells one of
 * these names is listed here, except win.deimos and elf.angryrebel (ANGRYREBEL, which shares the
 * alias "Ghost RAT" with win.ghost_rat). A new id ThreatFox adds for one of these families splits it
 * until it is added — a duplicate node, which is the failure this table chooses over a wrong merge.
 */
const KNOWN: KnownFamily[] = [
    { name: 'Cobalt Strike', kind: 'tool', type: 'c2', ids: ['win.cobalt_strike'], spellings: [] },
    { name: 'Sliver', kind: 'tool', type: 'c2', ids: ['win.sliver'], spellings: [] },
    { name: 'Metasploit', kind: 'tool', type: 'c2', ids: [], spellings: [] },
    { name: 'Mythic', kind: 'tool', type: 'c2', ids: [], spellings: [] },
    { name: 'Havoc', kind: 'tool', type: 'c2', ids: ['win.havoc'], spellings: [] },
    { name: 'Brute Ratel C4', kind: 'tool', type: 'c2', ids: ['win.brute_ratel_c4', 'elf.brute_ratel'], spellings: ['BruteRatel'] },
    { name: 'Covenant', kind: 'tool', type: 'c2', ids: ['win.grunt'], spellings: ['GRUNT'] },
    { name: 'Empire', kind: 'tool', type: 'c2', ids: [], spellings: ['PowerShell Empire'] },
    { name: 'Posh', kind: 'tool', type: 'c2', ids: ['win.poshc2'], spellings: ['PoshC2'] },
    { name: 'Caldera', kind: 'tool', type: 'c2', ids: [], spellings: [] },
    { name: 'Deimos', kind: 'tool', type: 'c2', ids: ['win.deimos_c2'], spellings: ['DeimosC2'] },
    { name: 'NimPlant', kind: 'tool', type: 'c2', ids: ['win.nimplant'], spellings: [] },
    { name: 'Viper', kind: 'tool', type: 'c2', ids: [], spellings: [] },
    { name: 'Villain', kind: 'tool', type: 'c2', ids: [], spellings: [] },
    { name: 'Supershell', kind: 'tool', type: 'c2', ids: [], spellings: [] },
    { name: 'RedGuard', kind: 'tool', type: 'c2', ids: [], spellings: [] },
    { name: 'PANDA', kind: 'tool', type: 'c2', ids: [], spellings: [] },
    { name: 'Hak5 Cloud C2', kind: 'tool', type: 'c2', ids: [], spellings: [] },
    { name: 'Unam Web Panel', kind: 'tool', type: 'c2', ids: [], spellings: [] },
    { name: 'Sectop', kind: 'malware', type: 'rat', ids: ['win.sectop_rat'], spellings: ['SectopRAT'] },
    { name: 'Quasar', kind: 'malware', type: 'rat', ids: ['win.quasar_rat'], spellings: ['Quasar RAT', 'QuasarRAT'] },
    { name: 'Remcos', kind: 'malware', type: 'rat', ids: ['win.remcos'], spellings: ['RemcosRAT'] },
    { name: 'njRAT', kind: 'malware', type: 'rat', ids: ['win.njrat'], spellings: [] },
    { name: 'NanoCore', kind: 'malware', type: 'rat', ids: ['win.nanocore'], spellings: ['Nanocore RAT', 'NanoCoreRAT'] },
    { name: 'DcRAT', kind: 'malware', type: 'rat', ids: ['win.dcrat'], spellings: ['DarkCrystal RAT'] },
    { name: 'AsyncRAT', kind: 'malware', type: 'rat', ids: ['win.asyncrat'], spellings: [] },
    { name: 'Gh0st', kind: 'malware', type: 'rat', ids: ['win.ghost_rat'], spellings: ['Ghost RAT', 'Gh0st RAT'] },
    { name: 'XtremeRAT', kind: 'malware', type: 'rat', ids: ['win.extreme_rat'], spellings: [] },
    { name: 'DarkComet', kind: 'malware', type: 'rat', ids: ['win.darkcomet'], spellings: [] },
    { name: 'NetBus', kind: 'malware', type: 'rat', ids: [], spellings: [] },
    { name: 'Hookbot', kind: 'malware', type: 'rat', ids: [], spellings: [] },
    { name: 'ShadowPad', kind: 'malware', type: 'backdoor', ids: ['win.shadowpad'], spellings: [] },
    { name: 'GoPhish', kind: 'tool', type: 'utility', ids: [], spellings: [] },
    { name: 'XMRig', kind: 'tool', type: 'utility', ids: ['win.xmrig', 'elf.xmrig'], spellings: [] },
    { name: 'BurpSuite', kind: 'tool', type: 'utility', ids: [], spellings: [] },
    { name: 'MobSF', kind: 'tool', type: 'recon', ids: [], spellings: [] },
];

/**
 * Commercial remote-management products SSLBL lists as "C&C" (measured: 514 "ConnectWise C&C" and
 * 10 "SimpleHelp C&C" since 2025). The listing is about a criminal's server; the software is a
 * legitimate product, so it is a `threat.tool`, not a malware family.
 */
const ABUSED_TOOLS: Family[] = [
    { name: 'ConnectWise', kind: 'tool', type: 'utility' },
    { name: 'SimpleHelp', kind: 'tool', type: 'utility' },
];

const BY_ID = new Map<string, KnownFamily>();
const BY_KEY = new Map<string, Family>();
for (const f of KNOWN) {
    for (const id of f.ids) BY_ID.set(id, f);
    for (const s of [f.name, ...f.spellings]) BY_KEY.set(familyKey(s), f);
}
for (const f of ABUSED_TOOLS) BY_KEY.set(familyKey(f.name), f);

/** The family under its project-wide name, without the lookup-only fields. */
const asFamily = (f: Family): Family => ({ name: f.name, kind: f.kind, type: f.type });

/** How many families the table carries — the check that it still matches IP Classification's 36. */
export const KNOWN_FAMILY_COUNT = KNOWN.length;

/**
 * Names that are not a family. ThreatFox files what it cannot attribute under these ids, and SSLBL
 * under "Malware C&C" and "Malware distribution". As nodes they would join every unattributed
 * indicator in the project into one hub that looks like a finding.
 */
const PLACEHOLDER_IDS = new Set(['unknown', 'unknown_loader', 'unknown_rat', 'unknown_stealer', 'unknown_webinject']);
const PLACEHOLDER_KEYS = new Set(['malware', 'unknown', 'sinkhole', 'none', 'na', 'generic']);

export function isPlaceholder(name: string, id?: string): boolean {
    if (id && PLACEHOLDER_IDS.has(id)) return true;
    const k = familyKey(name);
    return !k || PLACEHOLDER_KEYS.has(k) || k.startsWith('unknown');
}

/**
 * ThreatFox's malware list (`{"query":"malware_list"}`) as a lookup from any spelling to the
 * printable name. Built per run, from one request, only when a name needs it.
 */
export interface TaxonomyIndex {
    /** The printable and aliases ThreatFox lists for the name, or null when it does not know it. */
    lookup(name: string): { printable: string; aliases: string[] } | null;
}

/**
 * A printable match wins over an alias match, and an ambiguous key matches nothing: aliases are
 * shared ("Ghost RAT" is win.ghost_rat's printable AND an alias of elf.angryrebel), and picking one
 * of two families is a guess. Measured: 3,895 families on 2026-11-14.
 */
export function buildTaxonomy(list: unknown): TaxonomyIndex {
    const printables = new Map<string, Map<string, string[]>>(); // key -> printable -> aliases
    const aliases = new Map<string, Set<string>>(); // key -> printables
    if (list && typeof list === 'object') {
        for (const v of Object.values(list as Record<string, any>)) {
            const printable = typeof v?.malware_printable === 'string' ? cleanName(v.malware_printable) : '';
            if (!printable) continue;
            const al = typeof v?.malware_alias === 'string' ? v.malware_alias.split(',').map(cleanName).filter(Boolean) : [];
            const pk = familyKey(printable);
            if (!pk) continue;
            if (!printables.has(pk)) printables.set(pk, new Map());
            printables.get(pk)!.set(printable, al);
            for (const a of al) {
                const ak = familyKey(a);
                if (!ak) continue;
                if (!aliases.has(ak)) aliases.set(ak, new Set());
                aliases.get(ak)!.add(printable);
            }
        }
    }
    return {
        lookup(name: string) {
            const k = familyKey(name);
            if (!k) return null;
            const p = printables.get(k);
            if (p) {
                // "Tsunami" and "tsunami" are both printables (elf/osx and win). Same key, different
                // bytes: keep the source's own spelling when it is one of them, else no match.
                if (p.size === 1) {
                    const [[printable, al]] = [...p.entries()];
                    return { printable, aliases: al };
                }
                const own = p.get(cleanName(name));
                return own ? { printable: cleanName(name), aliases: own } : null;
            }
            const a = aliases.get(k);
            if (a && a.size === 1) {
                const printable = [...a][0];
                return { printable, aliases: printables.get(familyKey(printable))?.get(printable) ?? [] };
            }
            return null;
        },
    };
}

/**
 * The family a source names, under its project-wide name — or null for a placeholder.
 *
 * `id` is ThreatFox's `malware`. It is matched before any name, because names collide where ids do
 * not: ThreatFox's "Deimos" (win.deimos) is not IP Classification's Deimos (DeimosC2).
 */
export function resolveFamily(
    input: { name: string; id?: string; aliases?: string[] },
    taxonomy?: TaxonomyIndex | null,
): Family | null {
    const name = cleanName(input.name ?? '');
    const id = typeof input.id === 'string' ? input.id.trim() : undefined;
    if (isPlaceholder(name, id)) return null;

    if (id) {
        const known = BY_ID.get(id);
        if (known) return asFamily(known);
        // An id ThreatFox has and the table does not: its printable is the canonical name already.
        return { name, kind: 'malware', type: 'unknown', aliases: input.aliases?.filter((a) => a !== name) };
    }

    const direct = BY_KEY.get(familyKey(name));
    if (direct) return asFamily(direct);

    const tf = taxonomy?.lookup(name);
    if (tf) {
        if (isPlaceholder(tf.printable)) return null;
        // "RemcosRAT" is an alias of ThreatFox's "Remcos", which the table knows.
        const viaTf = BY_KEY.get(familyKey(tf.printable));
        if (viaTf) return asFamily(viaTf);
        return { name: tf.printable, kind: 'malware', type: 'unknown', aliases: tf.aliases.filter((a) => a !== tf.printable) };
    }
    return { name, kind: 'malware', type: 'unknown' };
}

/**
 * Which kinds of node already in the project a resolved family may land on, in order of preference.
 *
 * A family from the table has a known kind, and only a node of THAT kind is reused: OTX writes every
 * family as a Malware, so a project can hold a Malware "Cobalt Strike" beside IP Classification's
 * Tool, and the Tool is the one meant.
 *
 * A family the table does not know arrives as malware/'unknown' and may land on either, a Malware
 * first — unless its NAME is one the table holds. It got here through a ThreatFox id the table does
 * not map, so it is a different family that happens to share the name: win.deimos ("Deimos") is not
 * DeimosC2 ("Deimos", a Tool). Falling back to the table's Tool would be the very merge the table
 * refuses. A Malware of that name is still reused, because the host makes one node of two Malware
 * with one name anyway (`name` is the type's identity).
 */
export function reusableKinds(f: Family): FamilyKind[] {
    if (!(f.kind === 'malware' && f.type === 'unknown')) return [f.kind];
    return BY_KEY.has(familyKey(f.name)) ? ['malware'] : ['malware', 'tool'];
}

/** Whether resolving a name could use ThreatFox's malware list — so a run fetches it only then. */
export function needsTaxonomy(name: string): boolean {
    const n = cleanName(name);
    return !!n && !isPlaceholder(n) && !BY_KEY.has(familyKey(n));
}

/**
 * An SSLBL `Listingreason` as a family and what the certificate was used for — or null.
 *
 * Measured shapes (11,261 rows, 2026-11-14): "<family> C&C" (246 of 268 distinct reasons),
 * "<family> malware distribution", "<family> MITM" (banking-trojan web injects), and a handful of
 * bare names. Only the three suffixed shapes name a family for certain; a bare name ("FIN7",
 * "doxbin.cy", "Sinkhole") is as often an actor, a site or a status, so it stays on the certificate
 * as text and makes no node.
 */
export function parseSslblReason(reason: string): { family: string; use: 'c2' | 'distribution' | 'mitm' } | null {
    const r = cleanName(reason);
    let m = /^(.+?) C&C$/i.exec(r);
    if (m) return { family: m[1], use: 'c2' };
    m = /^(.+?) malware distribution$/i.exec(r);
    if (m) return { family: m[1], use: 'distribution' };
    m = /^(.+?) MITM$/i.exec(r);
    if (m) return { family: m[1], use: 'mitm' };
    return null;
}
