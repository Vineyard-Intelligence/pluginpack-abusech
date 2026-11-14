// Unit tests for the pure modules — family names (src/families.ts) and value conversions
// (src/convert.ts). No network, no host.
//   Run: node test/pure.test.mjs
//
// The modules are bundled to a temp directory with the same pinned esbuild the pack uses, because
// they are TypeScript and this runs on plain Node.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const dir = mkdtempSync(join(tmpdir(), 'abusech-pure-'));
const load = async (name) => {
    const out = join(dir, `${name}.mjs`);
    execFileSync('npx', ['--yes', 'esbuild@0.25.12', join(root, 'src', `${name}.ts`), '--bundle', '--format=esm', '--platform=neutral', '--log-level=warning', `--outfile=${out}`], { cwd: root });
    return import(pathToFileURL(out).href);
};
const fam = await load('families');
const cv = await load('convert');

const ok = [];
const fail = [];
const check = (name, cond) => (cond ? ok : fail).push(name);

// ---- the family table still IS IP Classification's ------------------------------------------
// The point of the table is that a ThreatFox C2 and an IP Classification C2 of one family meet at
// one node. That only holds while the names, kinds and types here equal that pack's dataset, so the
// dataset is read and compared, not restated. IPC_DATASET points elsewhere for a scratch clone.
{
    const path = process.env.IPC_DATASET ?? join(root, '..', 'pluginpack-ip-classification', 'src', 'dataset.json');
    if (!existsSync(path)) {
        console.log(`SKIP family table vs IP Classification: ${path} not found (set IPC_DATASET)`);
    } else {
        const ipc = JSON.parse(readFileSync(path, 'utf8')).c2Families;
        check(`table holds all ${ipc.length} IP Classification families`, fam.KNOWN_FAMILY_COUNT === ipc.length);
        for (const f of ipc) {
            // Its own name, its label, and the label spelled the way abuse.ch might ("dcrat") all
            // land on IP Classification's exact name, kind and type.
            for (const spelling of [f.name, f.label, f.name.toUpperCase()]) {
                const r = fam.resolveFamily({ name: spelling });
                check(`"${spelling}" → ${f.name} (${f.kind}/${f.type})`, r && r.name === f.name && r.kind === f.kind && r.type === f.type);
            }
        }
    }
}

// ---- the Domain rule is the type pack's ---------------------------------------------------------
// A copy of the validator drifted once: Infrastructure 4.3 took internationalised TLDs while this
// pack still held 4.2's rule, and URLhaus and ThreatFox skipped every such Domain. ABUSECH_TYPEPACKS
// points elsewhere for a scratch clone.
{
    const path = join(process.env.ABUSECH_TYPEPACKS ?? join(root, '..', 'typepack-basic', 'typepacks'), 'infrastructure.json');
    if (!existsSync(path)) {
        console.log(`SKIP Domain rule vs the type pack: ${path} not found (set ABUSECH_TYPEPACKS)`);
    } else {
        const doc = JSON.parse(readFileSync(path, 'utf8'));
        const want = doc.types.find((t) => t.name === 'domain').properties.domain_name.validator.regex;
        check(`the Domain rule is Infrastructure ${doc.version}'s, verbatim`, cv.DOMAIN_REGEX === want);
    }
}

// ---- measured spellings -----------------------------------------------------------------------
{
    const by = (name, id) => fam.resolveFamily({ name, id });
    check('ThreatFox DCRat (win.dcrat) → DcRAT', by('DCRat', 'win.dcrat')?.name === 'DcRAT');
    check('MalwareBazaar QuasarRAT → Quasar', by('QuasarRAT')?.name === 'Quasar');
    check('ThreatFox Quasar RAT (win.quasar_rat) → Quasar', by('Quasar RAT', 'win.quasar_rat')?.name === 'Quasar');
    check('MalwareBazaar RemcosRAT → Remcos', by('RemcosRAT')?.name === 'Remcos');
    check('CobaltStrike → the Cobalt Strike Tool', by('CobaltStrike')?.kind === 'tool' && by('CobaltStrike')?.name === 'Cobalt Strike');
    check('win.cobalt_strike → Tool c2', by('Cobalt Strike', 'win.cobalt_strike')?.type === 'c2');
    check('elf.brute_ratel → Brute Ratel C4', by('brute_ratel', 'elf.brute_ratel')?.name === 'Brute Ratel C4');
    check('win.grunt (alias Covenant) → Covenant', by('GRUNT', 'win.grunt')?.name === 'Covenant');
    // Same name, different malware: ids win over names.
    const deimos = by('Deimos', 'win.deimos');
    check('win.deimos is NOT the DeimosC2 tool', deimos?.kind === 'malware' && deimos?.type === 'unknown' && deimos?.name === 'Deimos');
    check('win.deimos_c2 is the Deimos tool', by('DeimosC2', 'win.deimos_c2')?.kind === 'tool');
    check('win.meterpreter is its own family, not Metasploit', by('Meterpreter', 'win.meterpreter')?.name === 'Meterpreter');
    check('Gh0st and Ghost stay apart by key', fam.familyKey('Gh0st') !== fam.familyKey('Ghost'));
    check('Ghost RAT (measured TF printable) → Gh0st', by('Ghost RAT', 'win.ghost_rat')?.name === 'Gh0st');
    check('unknown family keeps its own name', by('WARDENStealer')?.name === 'WARDENStealer' && by('WARDENStealer')?.type === 'unknown');
    check('trailing space collapsed', by('GhostPenguin ', 'elf.ghostpenguin')?.name === 'GhostPenguin');
    check('ConnectWise is an abused Tool, not malware', by('ConnectWise')?.kind === 'tool');
    for (const [n, id] of [['Unknown malware', 'unknown'], ['Unknown Loader', 'unknown_loader'], ['Unknown RAT'], ['Malware'], ['Sinkhole'], ['']]) {
        check(`placeholder "${n}" makes no family`, fam.resolveFamily({ name: n, id }) === null);
    }
    check('needsTaxonomy: a table name needs no list', fam.needsTaxonomy('DCRat') === false && fam.needsTaxonomy('AgentTesla') === true && fam.needsTaxonomy('Unknown Loader') === false);
}

// ---- ThreatFox malware list as the canonical spelling ------------------------------------------
{
    // Trimmed from {"query":"malware_list"} (2026-11-14).
    const list = {
        'win.agent_tesla': { malware_printable: 'Agent Tesla', malware_alias: 'AgenTesla,AgentTesla,Negasteal' },
        'win.lumma': { malware_printable: 'Lumma Stealer', malware_alias: null },
        'win.remcos': { malware_printable: 'Remcos', malware_alias: 'RemcosRAT,Remvio,Socmer' },
        'win.ghost_rat': { malware_printable: 'Ghost RAT', malware_alias: 'Farfli,Gh0st RAT,PCRat' },
        'elf.angryrebel': { malware_printable: 'ANGRYREBEL', malware_alias: 'Ghost RAT' },
        'elf.tsunami': { malware_printable: 'Tsunami', malware_alias: 'Muhstik,Radiation,Amnesia' },
        'win.tsunami': { malware_printable: 'tsunami', malware_alias: null },
        'win.purerat': { malware_printable: 'PureRAT', malware_alias: 'PureHVNC,ResolverRAT' },
        'win.foo': { malware_printable: 'Foo', malware_alias: 'Shared' },
        'win.bar': { malware_printable: 'Bar', malware_alias: 'Shared' },
    };
    const tx = fam.buildTaxonomy(list);
    const r = (n) => fam.resolveFamily({ name: n }, tx);
    check('AgentTesla (MalwareBazaar) → Agent Tesla (ThreatFox)', r('AgentTesla')?.name === 'Agent Tesla');
    check('LummaStealer (SSLBL) → Lumma Stealer', r('LummaStealer')?.name === 'Lumma Stealer');
    check('PureHVNC (an alias) → PureRAT', r('PureHVNC')?.name === 'PureRAT');
    check('aliases come along for a new node', JSON.stringify(r('AgentTesla')?.aliases) === JSON.stringify(['AgenTesla', 'AgentTesla', 'Negasteal']));
    check('a printable match beats an alias match (Ghost RAT is win.ghost_rat, then the table)', r('Ghost RAT')?.name === 'Gh0st');
    check('an alias two families share matches neither', r('Shared')?.name === 'Shared' && !r('Shared')?.aliases);
    check('Tsunami/tsunami: the source spelling is kept', r('tsunami')?.name === 'tsunami' && r('Tsunami')?.name === 'Tsunami' && r('TSUNAMI')?.name === 'TSUNAMI');
    check('an empty list changes nothing', fam.resolveFamily({ name: 'AgentTesla' }, fam.buildTaxonomy(null))?.name === 'AgentTesla');
}

// ---- SSLBL reasons ----------------------------------------------------------------------------
{
    const p = fam.parseSslblReason;
    check('"QuasarRAT C&C" → QuasarRAT, c2', JSON.stringify(p('QuasarRAT C&C')) === JSON.stringify({ family: 'QuasarRAT', use: 'c2' }));
    check('"NetSupport RAT malware distribution" → distribution', p('NetSupport RAT malware distribution')?.family === 'NetSupport RAT' && p('NetSupport RAT malware distribution')?.use === 'distribution');
    check('"Vawtrak MITM" → mitm', p('Vawtrak MITM')?.use === 'mitm');
    check('a bare name is not a family for certain', p('FIN7') === null && p('doxbin.cy') === null && p('Sinkhole') === null);
    check('"Malware C&C" parses, and resolves to no family', p('Malware C&C')?.family === 'Malware' && fam.resolveFamily({ name: 'Malware' }) === null);
}

// ---- conversions ------------------------------------------------------------------------------
{
    check('ThreatFox time', cv.abuseTime('2026-11-14 10:05:34 UTC') === '2026-11-14T10:05:34Z');
    check('MalwareBazaar time', cv.abuseTime('2026-11-14 09:59:00') === '2026-11-14T09:59:00Z');
    check('URLhaus payload date', cv.abuseTime('2026-11-14') === '2026-11-14T00:00:00Z');
    check('anything else is not guessed', cv.abuseTime('14/11/2026') === undefined && cv.abuseTime(null) === undefined);
    check('earliest', cv.earliest('2026-01-02T00:00:00Z', '2025-12-31T00:00:00Z') === '2025-12-31T00:00:00Z' && cv.earliest(undefined, 'x') === 'x');
    check('ip:port host', cv.ipOfIpPort('112.124.108.207:8084') === '112.124.108.207' && cv.ipOfIpPort('[2001:db8::1]:443') === '2001:db8::1');
    check('1.2.3.4 does not claim 11.2.3.45:80', !cv.iocIsIp('11.2.3.45:80', '1.2.3.4') && !cv.iocIsIp('1.2.3.40:80', '1.2.3.4') && cv.iocIsIp('1.2.3.4:80', '1.2.3.4'));
    check('999.1.1.1 is not an IP', cv.ipOfIpPort('999.1.1.1:80') === null);
    check('indicator types', cv.indicatorType('ip:port', '1.2.3.4:80') === 'ipv4' && cv.indicatorType('sha256_hash', 'x') === 'sha256' && cv.indicatorType('envelope_from', 'x') === undefined);
    check('an md5 IOC makes no File Hash (it needs a SHA-256)', cv.entityForIoc('md5_hash', 'a'.repeat(32)) === null);
    check('a domain IOC the type would refuse makes no node', cv.entityForIoc('domain', 'bad domain') === null);
    check('a domain IOC under an internationalised TLD is a Domain', cv.entityForIoc('domain', 'C2.Example.XN--P1AI')?.data.domain_name === 'c2.example.xn--p1ai' && cv.entityForIoc('domain', 'пример.рф')?.type === 'infrastructure.domain');
    check('a lookup asks for a host in lower case and punycode', cv.lookupHost('C2.Example.XN--P1AI.') === 'c2.example.xn--p1ai' && cv.lookupHost('пример.рф') === 'xn--e1afmkfd.xn--p1ai' && cv.lookupHost('ApiJ4ya.org') === 'apij4ya.org');
    check('…and gets null for what is not a host', ['bad domain', 'wpad', 'a/b.example', 'user@host.example', 'host.example:443', 'a..example', '', null].every((v) => cv.lookupHost(v) === null));
    check('an IP IOC makes an IP without its port', cv.entityForIoc('ip:port', '5.6.7.8:443')?.data.ip_address === '5.6.7.8');
    check('hash normalisation', cv.normalizeHash('SHA256: ' + 'AB'.repeat(32))?.hash === 'ab'.repeat(32) && cv.normalizeHash('xyz') === null);
    check('counts as strings', cv.intOf('760668') === 760668 && cv.intOf('x') === undefined);

    const feed = cv.parseSslblFeed(
        [
            '################################################################',
            '# abuse.ch SSLBL SSL Certificate Blacklist (SHA1 Fingerprints) #',
            '# Last updated: 2026-11-14 09:14:20 UTC                        #',
            '# Listingdate,SHA1,Listingreason',
            '2026-11-14 09:14:20,C8E6FC7BB95A5FE2122679CFCA61F87C7CE2875A,NativeLoader C&C',
            '2026-11-14 08:35:11,0d04a50138c74a1ecfa1a7b4a3afddeb2a4be571,QuasarRAT C&C',
            '2026-11-14 08:35:11,not-a-sha1,Junk C&C',
            '# END (3) entries',
        ].join('\r\n'),
    );
    check('feed: header date read', feed.updated === '2026-11-14T09:14:20Z');
    check('feed: rows keyed by lowercase SHA-1', feed.rows.get('c8e6fc7bb95a5fe2122679cfca61f87c7ce2875a')?.reason === 'NativeLoader C&C');
    check('feed: a row without a SHA-1 is skipped', feed.rows.size === 2);
    check('feed: listing date as ISO', feed.rows.get('0d04a50138c74a1ecfa1a7b4a3afddeb2a4be571')?.listed === '2026-11-14T08:35:11Z');
    // The END line counts every data row, the skipped one included, so "complete" compares lines read.
    check('feed: END count and rows read', feed.expected === 3 && feed.lines === 3 && cv.sslblFeedProblem(feed) === null);

    // A cut copy (the CDN served a 524,288-byte one on 2026-11-14): full header, no END line.
    const cut = cv.parseSslblFeed('# Last updated: 2026-11-14 09:14:20 UTC\n2026-11-14 08:35:11,0d04a50138c74a1ecfa1a7b4a3afddeb2a4be571,QuasarRAT C&C\n2021-09-03 10:00:00,0d04a50138c74a1ecf');
    check('feed: no END line is incomplete', cut.expected === undefined && /no END line/.test(cv.sslblFeedProblem(cut) ?? ''));
    const short = cv.parseSslblFeed('2026-11-14 08:35:11,0d04a50138c74a1ecfa1a7b4a3afddeb2a4be571,QuasarRAT C&C\n# END (11261) entries');
    check('feed: fewer rows than the END line is incomplete', /1 of 11261 rows/.test(cv.sslblFeedProblem(short) ?? ''));
    check('feed: an empty list is a problem too', /empty/.test(cv.sslblFeedProblem(cv.parseSslblFeed('# END (0) entries')) ?? ''));
}

// ---- which existing family node a family may land on ----------------------------------------
{
    const kinds = (input) => fam.reusableKinds(fam.resolveFamily(input)).join();
    check('a table Tool reuses only a Tool (not OTX\'s Malware "Cobalt Strike")', kinds({ name: 'Cobalt Strike', id: 'win.cobalt_strike' }) === 'tool');
    check('a table Malware reuses only a Malware', kinds({ name: 'DCRat', id: 'win.dcrat' }) === 'malware');
    check('DeimosC2 (win.deimos_c2) is the table Tool', kinds({ name: 'DeimosC2', id: 'win.deimos_c2' }) === 'tool');
    // win.deimos resolves to a kind-unknown "Deimos" whose name the table holds as a Tool. Falling
    // back to that Tool is the merge the table exists to prevent.
    check('win.deimos never reuses the DeimosC2 Tool', kinds({ name: 'Deimos', id: 'win.deimos' }) === 'malware');
    check('a family the table does not know reuses either, a Malware first', kinds({ name: 'Vidar', id: 'win.vidar' }) === 'malware,tool');
}

for (const n of fail) console.log('FAIL', n);
console.log(`\n${fail.length ? 'FAIL' : 'PASS'} pure: ${ok.length} / ${ok.length + fail.length}`);
if (fail.length) process.exit(1);
