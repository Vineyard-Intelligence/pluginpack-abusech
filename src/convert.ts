// Value conversions between abuse.ch's spellings and the type packs'. Pure and import-free, so
// test/pure.test.mjs can bundle and call it without a host.
//
// Every regex here repeats a validator a type pack declares. The host REFUSES a createNode whose
// value fails its type's validator, and a refusal throws out of the run: one malformed domain in a
// ThreatFox answer would end the run for every node after it. Checking first turns that into one
// skipped value and a log line.

/**
 * infrastructure.domain.domain_name's validator, Infrastructure 4.3.1's verbatim (test-plugin.mjs
 * compares it with the type pack checked out beside this repository). 4.3 takes a name under an
 * internationalised TLD (`пример.рф`, `c2.example.xn--p1ai`) that 4.2 refused, so a project still on
 * 4.2 can refuse a Domain this passes: the write that makes one (threatfox.ts) catches that.
 */
export const DOMAIN_REGEX = '^[a-zA-Z0-9._\\u0080-\\uffff-]+\\.(?:[a-zA-Z\\u0080-\\uffff]{2,}|[xX][nN]--[a-zA-Z0-9-]{2,})\\.?$';
export const DOMAIN_RE = new RegExp(DOMAIN_REGEX);
/** web.url.url's validator. */
export const URL_RE = /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const SHA1_RE = /^[a-f0-9]{40}$/;
const MD5_RE = /^[a-f0-9]{32}$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export const isIpv4 = (v: string): boolean => IPV4_RE.test(v);
/** A screen, not a parser: hex groups and colons, at least two colons. */
export const isIpv6 = (v: string): boolean => /^[0-9a-fA-F:]+$/.test(v) && (v.match(/:/g) ?? []).length >= 2;
export const isIp = (v: string): boolean => isIpv4(v) || isIpv6(v);

/**
 * A Domain node's name as a lookup asks for it: lower case, no trailing dot, an internationalised
 * name in its punycode (ASCII) form — or null when it is not a host name at all.
 *
 * Only a READ goes through here. The node is already in the project, so its own type took the name,
 * and holding it to a copy of one type pack's validator would only skip names a newer pack takes
 * (URLhaus and ThreatFox skipped every `.рф` Domain while Infrastructure 4.2's rule was copied
 * here). The check is loose: at least one dot and nothing a URL would read as other than a host.
 */
export function lookupHost(v: unknown): string | null {
    const s = typeof v === 'string' ? v.trim().toLowerCase().replace(/\.$/, '') : '';
    if (!s || !s.includes('.') || /[\s/?#@:\\[\]%]/.test(s)) return null;
    try {
        const host = new URL(`http://${s}/`).hostname;
        return host && !host.startsWith('.') && !host.includes('..') ? host : null;
    } catch {
        return null;
    }
}

export type HashKind = 'sha256' | 'sha1' | 'md5';

/** A hash as lowercase hex and its kind, or null. Tolerates a `sha256:`-style prefix and `0x`. */
export function normalizeHash(v: unknown): { hash: string; kind: HashKind } | null {
    if (typeof v !== 'string') return null;
    const s = v
        .trim()
        .toLowerCase()
        .replace(/^(sha256|sha1|md5)[:=]\s*/, '')
        .replace(/^0x/, '');
    if (SHA256_RE.test(s)) return { hash: s, kind: 'sha256' };
    if (SHA1_RE.test(s)) return { hash: s, kind: 'sha1' };
    if (MD5_RE.test(s)) return { hash: s, kind: 'md5' };
    return null;
}

export const sha256Of = (v: unknown): string | null => {
    const h = normalizeHash(v);
    return h?.kind === 'sha256' ? h.hash : null;
};
export const sha1Of = (v: unknown): string | null => {
    const h = normalizeHash(v);
    return h?.kind === 'sha1' ? h.hash : null;
};
export const md5Of = (v: unknown): string | null => {
    const h = normalizeHash(v);
    return h?.kind === 'md5' ? h.hash : null;
};

/**
 * An abuse.ch timestamp as the ISO-8601 UTC the type packs' `datetime` means, or undefined.
 *
 * Measured spellings (2026-11-14): ThreatFox and URLhaus "2026-11-14 10:05:34 UTC", MalwareBazaar
 * and SSLBL "2026-11-14 09:59:00" (UTC by their headers and docs), URLhaus payloads "2026-11-14"
 * (a date only, which is kept as midnight UTC rather than dropped). Anything else is not guessed at.
 */
export function abuseTime(v: unknown): string | undefined {
    if (typeof v !== 'string') return undefined;
    const s = v.trim();
    const full = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?: ?(?:UTC|Z))?$/.exec(s);
    if (full) return `${full[1]}T${full[2]}Z`;
    if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return `${s}T00:00:00Z`;
    return undefined;
}

/** The earlier of two ISO-8601 UTC stamps (same format, so string order is time order). */
export function earliest(a: unknown, b: unknown): string | undefined {
    const x = typeof a === 'string' && a ? a : undefined;
    const y = typeof b === 'string' && b ? b : undefined;
    if (!x) return y;
    if (!y) return x;
    return x <= y ? x : y;
}

/** A count abuse.ch sends as a string ("760668") or a number, as an integer. */
export function intOf(v: unknown): number | undefined {
    const n = typeof v === 'number' ? v : typeof v === 'string' && /^\d+$/.test(v.trim()) ? Number(v.trim()) : NaN;
    return Number.isSafeInteger(n) && n >= 0 ? n : undefined;
}

/** Join a capped list, saying how many were left out rather than truncating in silence. */
export function joinCapped(parts: string[], max = 25): string | undefined {
    const xs = [...new Set(parts.filter((p) => typeof p === 'string' && p.trim()).map((p) => p.trim()))];
    if (!xs.length) return undefined;
    return xs.length <= max ? xs.join(', ') : `${xs.slice(0, max).join(', ')} (+${xs.length - max} more)`;
}

/** Drop undefined, null and '' so a delta never overwrites a field with nothing. */
export function compact(o: Record<string, unknown>): Record<string, unknown> {
    return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null && v !== ''));
}

/**
 * The host part of a ThreatFox `ip:port` IOC, or null.
 *
 * ThreatFox lists an IP only with its port (measured: "112.124.108.207:8084"), so an IP Address node
 * never equals the IOC string. IPv6 is accepted bracketed ("[2001:db8::1]:443"), the form a port
 * after a colon-hex address needs.
 */
export function ipOfIpPort(ioc: string): string | null {
    const s = ioc.trim();
    const v6 = /^\[([0-9a-fA-F:]+)\]:\d{1,5}$/.exec(s);
    if (v6 && isIpv6(v6[1])) return v6[1].toLowerCase();
    const v4 = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(s);
    if (v4 && isIpv4(v4[1])) return v4[1];
    return isIp(s) ? s : null;
}

/**
 * Whether a ThreatFox record's IOC is the IP Address being looked up.
 *
 * `search_ioc` matches a SUBSTRING unless `exact_match` is set, and with `exact_match` a bare IP
 * finds nothing because the IOC carries a port (both measured 2026-11-14). So an IP is searched
 * loosely and every record is checked here: "1.2.3.4" must not claim "11.2.3.45:80".
 */
export function iocIsIp(ioc: unknown, ip: string): boolean {
    if (typeof ioc !== 'string') return false;
    const host = ipOfIpPort(ioc);
    return !!host && host.toLowerCase() === ip.trim().toLowerCase();
}

/** threat.indicator.indicator_type for a ThreatFox `ioc_type`, or undefined. */
export function indicatorType(iocType: unknown, ioc: string): string | undefined {
    switch (iocType) {
        case 'ip:port': {
            const host = ipOfIpPort(ioc);
            return host ? (isIpv4(host) ? 'ipv4' : 'ipv6') : undefined;
        }
        case 'domain':
            return 'domain';
        case 'url':
            return 'url';
        case 'md5_hash':
            return 'md5';
        case 'sha1_hash':
            return 'sha1';
        case 'sha256_hash':
            return 'sha256';
        default:
            return undefined;
    }
}

/** The project node a ThreatFox IOC names, as a create draft — or null when it cannot be one. */
export function entityForIoc(iocType: unknown, ioc: string): { type: string; data: Record<string, unknown> } | null {
    const s = ioc.trim();
    if (iocType === 'ip:port') {
        const ip = ipOfIpPort(s);
        return ip ? { type: 'infrastructure.ip_address', data: { ip_address: ip, version: isIpv4(ip) ? 'ipv4' : 'ipv6' } } : null;
    }
    if (iocType === 'domain') {
        const d = s.toLowerCase().replace(/\.$/, '');
        return DOMAIN_RE.test(d) ? { type: 'infrastructure.domain', data: { domain_name: d } } : null;
    }
    if (iocType === 'url') return URL_RE.test(s) ? { type: 'web.url', data: { url: s } } : null;
    // threat.file_hash is identified by its SHA-256, which the type requires: an md5 or sha1 IOC
    // cannot become one, and stays an indicator only.
    if (iocType === 'sha256_hash') {
        const h = sha256Of(s);
        return h ? { type: 'threat.file_hash', data: { sha256: h } } : null;
    }
    return null;
}

export interface SslblFeed {
    /** The feed's own "Last updated" stamp, ISO-8601 UTC. */
    updated?: string;
    /** SHA-1 (lowercase) -> the listing. */
    rows: Map<string, { listed?: string; reason: string }>;
    /** The row count the closing `# END (n) entries` line states; undefined when there is none. */
    expected?: number;
    /** Data lines read, a skipped one included — what `expected` counts. */
    lines: number;
}

/**
 * The SSLBL SSL Certificate Blacklist CSV (`sslblacklist.csv`).
 *
 * Measured 2026-11-14: 849 KB, 11,261 rows of `Listingdate,SHA1,Listingreason` under a `#` header
 * that carries "Last updated: … UTC", closed by `# END (11261) entries`. No reason held a comma, but
 * only the first two are split on, so one that does stays whole. A row whose second field is not a
 * SHA-1 is skipped, and still counted in `lines`.
 */
export function parseSslblFeed(text: string): SslblFeed {
    const rows = new Map<string, { listed?: string; reason: string }>();
    let updated: string | undefined;
    let expected: number | undefined;
    let lines = 0;
    for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();
        if (!line) continue;
        if (line.startsWith('#')) {
            const m = /Last updated:\s*([0-9-]+ [0-9:]+)/i.exec(line);
            if (m && !updated) updated = abuseTime(m[1]);
            const end = /^#\s*END\s*\((\d+)\)\s*entries/i.exec(line);
            if (end) expected = Number(end[1]);
            continue;
        }
        lines++;
        const a = line.indexOf(',');
        const b = a < 0 ? -1 : line.indexOf(',', a + 1);
        if (b < 0) continue;
        const sha1 = sha1Of(line.slice(a + 1, b));
        if (!sha1) continue;
        rows.set(sha1, { listed: abuseTime(line.slice(0, a)), reason: line.slice(b + 1).trim() });
    }
    return { updated, rows, expected, lines };
}

/**
 * Why a downloaded SSLBL list must not be matched against — or null when it is whole.
 *
 * WHY: on 2026-11-14 the abuse.ch CDN served a cut copy, 524,288 bytes with the full header and the
 * same "Last updated", 6,896 of 11,261 rows and no END line. Matched as it stood, a certificate
 * listed in the missing part (everything before 2021-09-03, 39% of the list) came back "not
 * listed", which the analyst reads as a real negative. The END line is the one thing in the file
 * that says how long it should be, so a list without it, or with a different number of rows, is
 * refused rather than half-checked.
 */
export function sslblFeedProblem(feed: SslblFeed): string | null {
    if (feed.expected === undefined) return `no END line after ${feed.lines} rows`;
    if (feed.lines !== feed.expected) return `${feed.lines} of ${feed.expected} rows`;
    if (!feed.rows.size) return 'the list is empty';
    return null;
}
