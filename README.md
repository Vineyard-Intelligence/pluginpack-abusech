# abuse.ch — a Vineyard plugin pack

Looks up hashes, IP addresses, domains, URLs and TLS certificates in the free
[abuse.ch](https://abuse.ch/) trackers: MalwareBazaar, ThreatFox, URLhaus and SSLBL.

VirusTotal and OTX leave the malware side of an investigation thin. This pack adds what a sample
is and when it was first seen, which C2 an indicator belongs to with the reporter's confidence and
name, where a payload was distributed from, and which certificates SSLBL has seen on C2 servers.

## Plugins

| Plugin | Takes | Adds |
| --- | --- | --- |
| **MalwareBazaar Hash Lookup** | File Hash (SHA-256, SHA-1 or MD5) | The missing hashes and size, `mb_*` fields (signature, tags, first/last seen, file name and type, reporter, origin country, imphash, TLSH, ssdeep, YARA rule names, sample page). The signature as a Malware or Tool family, `classified as` |
| **ThreatFox IOC Lookup** | IP Address, Domain, URL, File Hash | Each ThreatFox record as an Indicator that `refers_to` the node, with first seen, confidence, reporter, threat type and IOC page, linked `indicates` to its family. For a File Hash, also the indicators ThreatFox ties to the sample — usually its C2 — `associated in ThreatFox with`, each referring to its IP Address, Domain or URL |
| **URLhaus Lookup** | URL, Domain, IP Address, File Hash | `urlhaus_*` fields. A URL's payloads as File Hashes (`served file`); a host's URLs (`hosts`); the URLs that served a payload (`served file`). A payload's signature as its family, `classified as` |
| **SSLBL Certificate Check** | TLS Certificate with `fingerprint_sha1` | `sslbl_listed` and `sslbl_reason`, and the family SSLBL names, linked `used as C2`, `used for malware distribution` or `used for MITM` |

Start from what you have: a hash goes to MalwareBazaar and ThreatFox, an IP or domain to ThreatFox
and URLhaus, a certificate that Shodan, Censys or VirusTotal found to SSLBL.

## Setup

1. Get a free Auth-Key at [auth.abuse.ch](https://auth.abuse.ch/). MalwareBazaar, ThreatFox and
   URLhaus refuse requests without one since 2025-06-30.
2. In Vineyard, open **Run plugins**, pick an abuse.ch plugin and paste the key into its settings.
   Every plugin in the pack calls the same abuse.ch hosts, so the key is entered once for all four.
   SSLBL Certificate Check works without it.

**Desktop app only.** None of the abuse.ch hosts sends CORS headers (measured 2026-11-14; the APIs
also answer a browser's preflight with 401), so the web build cannot read their answers. The
desktop shell supplies the headers for the hosts a pack declares.

Requires the Infrastructure type pack 4.2.0 or later for `fingerprint_sha1`, and the Threat type pack.

## Terms

- MalwareBazaar, ThreatFox and URLhaus are free for **not-for-profit use** only
  ([abuse.ch terms of use](https://abuse.ch/terms-of-use/) §3.1). Commercial or for-profit use may
  need a paid Spamhaus subscription (§4.1).
- SSLBL is CC0, free for any use (§3.4).
- The data may not be used to customise, train or otherwise improve an AI model without Spamhaus'
  consent (§7.3). Check how the model provider behind Vineyard's AI panel treats what it is sent
  before giving it abuse.ch results.
- abuse.ch receives every value looked up, with your key. The SSLBL list is downloaded whole and
  matched locally, so the certificates you check are not sent.

## Why it is shaped this way

**One family, one node, whatever the source called it.** Malware and Tool nodes are identified by
their name, byte for byte, and the sources disagree: IP Classification writes `DcRAT`, ThreatFox
`DCRat`; IP Classification `Quasar`, ThreatFox `Quasar RAT`, MalwareBazaar and SSLBL `QuasarRAT`.
The 36 families IP Classification writes keep its name and its type — Cobalt Strike and the other
frameworks stay Tools — and every other family takes ThreatFox's name, which MalwareBazaar's and
SSLBL's spellings are matched to through ThreatFox's alias list. Matching is exact on letters and
digits; it never guesses at similar names (`src/families.ts`).

**An existing family is linked, never rewritten.** abuse.ch does not say what kind of malware a
family is. A family new to the project gets `malware_type: unknown`; one already there keeps
whatever it had.

**A ThreatFox record is an Indicator node, apart from the entity.** Its confidence and reporter
are the reporter's claim about an IP or domain, not facts about it; as their own node, a wrong
claim can be removed and the IP stays. The Indicator is linked to what it identifies by
`refers_to`, the edge the Threat type pack names for that. ThreatFox's confidence is kept as the
number (`threatfox_confidence`), not written into the Indicator's `confidence`, which is the
analyst's.

**One name can be two families.** ThreatFox's `win.deimos` is a malware; IP Classification's
Deimos is the DeimosC2 framework, a Tool. ThreatFox ids are matched before names, and a family that
reaches a table name through an id the table does not map lands only on a Malware of that name,
never on the table's Tool.

**First sightings stay with their source.** A File Hash's `first_seen` is the scanner's —
VirusTotal writes its first submission on every report — so MalwareBazaar's and URLhaus's go in
`mb_first_seen` and `urlhaus_first_seen`. Writing an earlier one into `first_seen` would make the
field change back on the next VirusTotal run, and again on the next abuse.ch one.

**Placeholders make no node.** ThreatFox files what it cannot attribute as "Unknown malware",
"Unknown Loader" and similar; SSLBL as "Malware C&C". As family nodes they would tie unrelated
indicators together.

**IPs are searched loosely, and every record is checked.** ThreatFox lists an IP only with its port
(`1.2.3.4:443`), so an exact search for the IP finds nothing, and the loose search is a substring
match that also returns `11.2.3.45:80`. Domains, URLs and hashes are searched exactly.

**Certificates, not IPs, for SSLBL.** SSLBL's Botnet C2 IP Blacklist was deprecated on 2025-01-03
and is empty. Its SSL Certificate Blacklist is current, and lists certificates by SHA-1 — which is
why the Infrastructure type pack gained `fingerprint_sha1` and the Shodan, Censys and VirusTotal
packs began filling it. A certificate without one is counted and the plugins that would fill it
are named.

**An incomplete list checks nothing.** On 2026-11-14 the abuse.ch CDN served a cut copy of the
certificate list: 524,288 bytes, the full header, 6,896 of 11,261 rows and no closing
`# END (n) entries` line. Matched as it stood, every certificate listed before 2021-09 came back
"not listed", which reads as a real negative. The plugin compares the rows it read with that line
and fails the run when they differ or the line is missing.

**Capped fan-out.** A shared host such as github.com has over 60,000 URLhaus entries and one Mozi
payload was served from 760,668 URLs. URLs and payloads per node stop at `max_items` (default 25),
ThreatFox indicators at `max_records` (default 50), and the summary says how many were left out.

## Build and test

```sh
node build.mjs          # bundles src/main.ts into dist/pack.mjs (esbuild 0.25.12, pinned)
node gen-manifest.mjs   # regenerates plugins/abusech.manifest.json from the bundle
node test-plugin.mjs    # plugins against recorded response shapes; no network
node test/pure.test.mjs # family names and value conversions
```

`node build.mjs && git diff --exit-code dist/pack.mjs` checks the published bundle against this
source. `test/pure.test.mjs` compares the family table with
`../pluginpack-ip-classification/src/dataset.json`; set `IPC_DATASET` when that checkout is
elsewhere.

`ABUSECH_AUTH_KEY=… node live-test.mjs` runs every plugin against the live APIs on indicators it
picks from each tracker's recent entries. A ThreatFox entry is used only once ThreatFox answers
for its id, because the recent list can hold IOCs that ThreatFox's lookups do not answer for; the
output names each one skipped. The key is read from the environment only and never printed.

## License

Apache-2.0. Data returned by abuse.ch is subject to the
[abuse.ch terms of use](https://abuse.ch/terms-of-use/).
