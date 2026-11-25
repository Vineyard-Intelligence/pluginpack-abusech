// abuse.ch pack — MalwareBazaar, ThreatFox, URLhaus and SSLBL for VINEYARD.
//
// What it adds over VirusTotal and OTX: hash, URL and domain lookups against the free abuse.ch
// trackers, with each claim's confidence, first sighting and reporter, and the C2 certificates SSLBL
// lists. IP Classification already ties IPv4 addresses to 36 C2 families; ThreatFox's IP→family
// answer is an independent second source for those, and lands on the same family nodes (families.ts).
//
// KEY MODEL: the analyst's own abuse.ch Auth-Key, a `secret: true` config value sent only as the
// `Auth-Key` header to the three abuse.ch APIs — never in a URL, never to SSLBL, which needs none.
// No key is bundled: abuse.ch issues them per person, free, at https://auth.abuse.ch/.
//
// Graph writes are STAGED: nothing reaches the project until the analyst reviews and applies it.
import { definePluginPack } from './sdk';
import type { PluginManifest, VineyardPluginPack } from './sdk';
import { PLATFORMS } from './common';
import { malwareBazaar } from './malwarebazaar';
import { threatFox } from './threatfox';
import { urlhaus } from './urlhaus';
import { sslbl } from './sslbl';

// The pack's page in the marketplace drawer, in Markdown. Lines in an array rather than one template
// literal, because the Markdown is full of backticks.
const PAGE = [
    "For the malware side of an investigation: what a sample is and when abuse.ch first saw it, which family a hash, IP, domain or URL was reported for and by whom, where a payload was spread from, and which TLS certificates SSLBL has seen on C2 servers. Families land on IP Classification's nodes, so its C2s and ThreatFox's meet.",
    '',
    '**Needs:** a free abuse.ch Auth-Key (https://auth.abuse.ch/), one for every plugin. SSLBL Certificate Check works without one.',
    '',
    "**Who sees it:** abuse.ch (Spamhaus) receives every hash, IP, domain and URL looked up, with the analyst's Auth-Key. The SSLBL list is downloaded whole and matched locally, so checked certificates are not sent. The hosts under investigation are never contacted.",
    '',
    "**Terms** (https://abuse.ch/terms-of-use/): MalwareBazaar, ThreatFox and URLhaus are free for not-for-profit use (§3.1); for-profit use may need a Spamhaus subscription (§4.1). SSLBL is CC0 (§3.4). The data may not train or improve an AI model without Spamhaus' consent (§7.3): check how the AI panel's provider treats what it is sent.",
    '',
    '**Read results with care:**',
    '',
    "- ThreatFox's confidence (0–100) is the reporter's own claim, not a verdict.",
    '- "Unknown malware" and similar placeholders make no family node.',
    "- SSLBL's C2 IP list was deprecated on 2025-01-03, so IPs are not checked against SSLBL.",
    '',
    '**Data and licences:** abuse.ch data, under its terms; the pack bundles none of its own.',
    '',
    '**Source:** https://github.com/Vineyard-Intelligence/pluginpack-abusech (Apache-2.0)',
].join('\n');

const pack: VineyardPluginPack & {
    author: { name: string; url: string };
    license: string;
    icon: string;
    platforms: PluginManifest['platforms'];
} = {
    identifier: 'run.vineyard.pluginpacks.abusech',
    content_type: 'vineyard:pluginpack',
    name: 'abuse.ch',
    version: '1.2.0',
    summary:
        'abuse.ch lookups: MalwareBazaar samples, ThreatFox indicators with confidence and reporter, URLhaus distribution URLs and payloads, and SSLBL-listed C2 certificates. Needs a free abuse.ch Auth-Key (SSLBL does not). Desktop only.',
    description: PAGE,
    author: { name: 'VINEYARD', url: 'https://vineyard.run' },
    license: 'Apache-2.0',
    icon: 'biohazard',
    platforms: PLATFORMS,
    plugins: [malwareBazaar, threatFox, urlhaus, sslbl],
};

export const abusechPack = definePluginPack(pack);
export default abusechPack;
