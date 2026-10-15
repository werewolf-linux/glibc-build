#!/usr/bin/env python3
"""Publish validated native artifacts to immutable R2 snapshots and GitHub."""
import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zlib
import yaml
from derive import derive
from inputs import ROOT, verify, sha256
import notes

ARCHES = ('x86_64', 'aarch64')
ENDPOINT = 'https://c860af766754fb92eec27bc723e6db5d.r2.cloudflarestorage.com'
BUCKET = 'werewolf'
PREFIX = 'apk/glibc/'
PUBLIC = 'https://dist.werewolf-linux.org/' + PREFIX
# Release notes, staged with the draft and copied beside the snapshot, by type.
# The JSON goes last: a draft that has it has all three.
NOTES = {'release-notes.md': 'text/markdown; charset=utf-8', 'release-notes.html': 'text/html; charset=utf-8',
         'release-notes.json': 'application/json'}

def run(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, text=True).stdout

def release(tag):
    # The tag endpoint excludes drafts. Listing with push access includes them.
    result = subprocess.run(['gh', 'api', '--paginate', '--slurp',
                             'repos/' + os.environ['GITHUB_REPOSITORY'] + '/releases?per_page=100'],
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr)
    matches = [item for page in json.loads(result.stdout) for item in page if item['tag_name'] == tag]
    if len(matches) > 1:
        raise ValueError('Multiple releases use the same build tag')
    return matches[0] if matches else None

def archive(directory, destination):
    # Retry staging from the same artifacts without depending on extraction times.
    with destination.open('wb') as output, gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as tar:
            for path in [directory] + sorted(directory.rglob('*')):
                name = '.' if path == directory else './' + path.relative_to(directory).as_posix()
                member = tar.gettarinfo(str(path), arcname=name)
                member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = ''
                if member.isfile():
                    with path.open('rb') as data:
                        tar.addfile(member, data)
                else:
                    tar.addfile(member)

def members(data):
    parts = []
    while data:
        stream = zlib.decompressobj(31)
        raw = stream.decompress(data)
        if not stream.eof:
            raise ValueError('Truncated gzip member')
        length = len(data) - len(stream.unused_data)
        parts.append((data[:length], raw))
        data = stream.unused_data
    return parts

def contents(raw):
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        return {m.name: archive.extractfile(m).read() for m in archive if m.isfile()}

def authenticated(path, key):
    parts = members(path.read_bytes())
    if len(parts) not in (2, 3):
        raise ValueError('Unsigned or malformed APK/index: ' + str(path))
    signature = contents(parts[0][1])
    if set(signature) != {'.SIGN.RSA256.werewolf-packages.rsa.pub'}:
        raise ValueError('Unexpected APK signing key: ' + str(path))
    with tempfile.TemporaryDirectory() as directory:
        signature_path = Path(directory) / 'sig'
        control = Path(directory) / 'control'
        signature_path.write_bytes(next(iter(signature.values())))
        control.write_bytes(parts[1][0])
        run('openssl', 'dgst', '-sha256', '-verify', str(key),
            '-signature', str(signature_path), str(control))
    return parts

def raw_gate(files, max_fail_per_mille):
    results = [data.splitlines()[0] for name, data in files.items()
               if name.endswith('.test-result') and data.splitlines()]
    passed = sum(line.startswith(b'PASS:') for line in results)
    failed = sum(line.startswith(b'FAIL:') for line in results)
    if passed + failed == 0 or failed * 1000 > (passed + failed) * max_fail_per_mille:
        raise ValueError(f'Raw failure gate failed: PASS={passed}, FAIL={failed}')
    if not any(name.endswith('/policy-report.json') for name in files):
        raise ValueError('Focused hardening evidence is missing')

def package_names(config):
    def expand(name):
        return name.replace('${{package.name}}', config['package']['name']).replace(
            '${{package.version}}', str(config['package']['version']))
    names = {config['package']['name']}
    ranges = {item['name']: item['items'] for item in config.get('data', [])}
    for sub in config['subpackages']:
        if sub.get('if'):
            raise ValueError('Review conditional package publication before updating')
        for key in ranges[sub['range']] if 'range' in sub else ['']:
            name = expand(sub['name']).replace('${{range.key}}', key)
            if '${{' in name:
                raise ValueError('Unresolved package name: ' + name)
            names.add(name)
    return names

def validate(directory, arch, lock, source_sha=None):
    record = json.loads((directory / 'build.json').read_text())
    expected = lock['version'] + '-r' + str(lock['epoch'] + lock['revision'])
    if (record['build_id'], record['arch'], record['version']) != (lock['build_id'], arch, expected):
        raise ValueError('Mixed build inputs or architectures')
    if record['source_sha'] != (source_sha or os.environ['GITHUB_SHA']):
        raise ValueError('Artifact came from a different downstream commit')
    for name, digest in record['sha256'].items():
        path = directory / name
        if not path.resolve().is_relative_to(directory.resolve()) or sha256(path) != digest:
            raise ValueError('Artifact hash mismatch: ' + name)
    actual = {str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file()}
    if actual != set(record['sha256']) | {'build.json'}:
        raise ValueError('Unrecorded or missing artifact files')
    key = ROOT / 'release/packages.pub'
    if (directory / 'werewolf-packages.rsa.pub').read_bytes() != key.read_bytes():
        raise ValueError('Ephemeral signing key cannot be published')
    upstream = json.loads((directory / 'upstream.lock.json').read_text())
    if any(upstream[k] != lock[k] for k in ['build_id', 'sha256', 'mode', 'policy_sha256']):
        raise ValueError('Upstream provenance mismatch')
    config = derive()
    if yaml.safe_load((directory / 'glibc.yaml').read_text()) != config:
        raise ValueError('Artifact recipe differs from the verified derivation')
    index = authenticated(directory / arch / 'APKINDEX.tar.gz', key)
    text = contents(index[1][1])['APKINDEX'].decode()
    indexed = set()
    for stanza in text.strip().split('\n\n'):
        fields = dict(line.split(':', 1) for line in stanza.splitlines())
        if fields['V'] != expected or fields['A'] != arch:
            raise ValueError('Index contains a different version or architecture')
        indexed.add(fields['P'] + '-' + fields['V'] + '.apk')
    apks = list((directory / arch).glob('*.apk'))
    if not apks or indexed != {p.name for p in apks}:
        raise ValueError('Incomplete APK index')
    if indexed != {name + '-' + expected + '.apk' for name in package_names(config)}:
        raise ValueError('Missing or unexpected derived package')
    testresults = 0
    for apk in apks:
        parts = authenticated(apk, key)
        if len(parts) != 3:
            raise ValueError('Missing APK payload')
        info = contents(parts[1][1])['.PKGINFO'].decode()
        fields = dict(line.split(' = ', 1) for line in info.splitlines() if ' = ' in line)
        if fields['pkgver'] != expected or fields['arch'] != arch:
            raise ValueError('APK metadata mismatch')
        if apk.name != fields['pkgname'] + '-' + fields['pkgver'] + '.apk':
            raise ValueError('APK filename and signed metadata differ')
        if fields['datahash'] != hashlib.sha256(parts[2][0]).hexdigest():
            raise ValueError('APK payload hash mismatch')
        if fields['pkgname'].endswith('-testresults'):
            policy = json.loads((ROOT / 'policy.json').read_text())
            raw_gate(contents(parts[2][1]), policy['max_fail_per_mille'])
            testresults += 1
    if testresults != 1:
        raise ValueError('Missing or duplicate upstream test results')
    return record

def status(tag):
    current = release(tag)
    if current is None:
        return 'build'
    if 'release.json' not in {a['name'] for a in current['assets']}:
        if not current['draft']:
            raise ValueError('Published release has no completion manifest')
        return 'build'
    return 'publish' if current['draft'] else 'complete'

def download(url):
    # A public object, or None when it is absent. Any other failure stops the
    # stage, so notes never call a release the first, or unchanged, because a
    # read failed; the next scheduled check stages again.
    # dist.werewolf-linux.org refuses Python's default User-Agent.
    request = urllib.request.Request(url, headers={'User-Agent': 'glibc-build-publish (+' + notes.SOURCE + ')'})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            if attempt == 2:
                raise
        except urllib.error.URLError:
            if attempt == 2:
                raise
        time.sleep(15 * (attempt + 1))

def apk_files(data):
    # An APK's payload files by path.
    return contents(members(data)[-1][1])

def stanzas(index):
    # An authenticated APKINDEX.tar.gz's stanzas as {field: value} maps.
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'APKINDEX.tar.gz'
        path.write_bytes(index)
        text = contents(authenticated(path, ROOT / 'release/packages.pub')[1][1])['APKINDEX'].decode()
    return [dict(line.split(':', 1) for line in s.splitlines()) for s in text.strip().split('\n\n')]

def stream(version):
    # glibc-neutered's package stem for a release version: 2.44-r19 is glibc-neutered-2.44.
    return 'glibc-neutered-' + version.split('-r')[0]

def lookup(path):
    # A GitHub API read for notes' commit lists; None when GitHub cannot
    # answer, which the notes render as unavailable, never as no change.
    try:
        return json.loads(run('gh', 'api', path))
    except subprocess.CalledProcessError:
        return None

def subjects(commits):
    return [{'sha': c['sha'], 'subject': c['commit']['message'].splitlines()[0]}
            for c in commits if len(c['parents']) == 1]

def glibc_commit(data):
    # The glibc commit a test results package was built from, in its recipe.
    recipe = contents(members(data)[1][1])['.melange.yaml']
    return yaml.safe_load(recipe)['vars']['glibc-expected-commit']

def results(data):
    files = apk_files(data)
    report = next(v for k, v in files.items() if k.endswith('/policy-report.json'))
    summary = next(v for k, v in files.items() if k.endswith('glibc-testresults/tests.sum'))
    return notes.statuses(summary.decode(errors='replace')), json.loads(report)

def gather(artifacts, lock, records):
    # Facts for notes.build: this build's evidence, the previous release's and
    # Wolfi's advisories. Run once per release; stage() keeps what it wrote.
    wolfi = lock['version'] + '-r' + str(lock['epoch'])
    version = records[ARCHES[0]]['version']
    previous = None
    pointer = download(PUBLIC + 'current.json')
    if pointer is not None:
        pointer = json.loads(pointer)
        if pointer['build_id'] == lock['build_id']:
            raise ValueError('current.json already names this build')
        old = download(PUBLIC + 'builds/' + pointer['build_id'] + '/release-notes.json')
        old = json.loads(old) if old is not None else None
        if old is not None:
            origin = old['source']['wolfi_version']
        else:
            # Releases before notes name their Wolfi build in a provides.
            entry = next(s for s in stanzas(download(PUBLIC + ARCHES[1] + '/APKINDEX.tar.gz'))
                         if s['P'] == stream(pointer['version']) and s['V'] == pointer['version'])
            origin = next((p.rsplit(':', 1)[1] for p in entry.get('p', '').split()
                           if p.startswith('wolfi-origin:')), None)
        previous = {'version': pointer['version'], 'build_id': pointer['build_id'],
                    'commit': pointer['source_sha'], 'wolfi_version': origin,
                    'wolfi_commit': old['source']['wolfi_commit'] if old is not None else None,
                    'wolfi_inputs': old['wolfi_inputs'] if old is not None else None}
    commits = glibc_commits = None
    architectures = {}
    for arch in ARCHES:
        directory = artifacts / ('glibc-' + arch)
        tests, report = results(next((directory / arch).glob('*-testresults-*.apk')).read_bytes())
        before = None
        if previous is not None:
            old = download(PUBLIC + arch + '/' + stream(previous['version']) + '-testresults-' +
                           previous['version'] + '.apk')
            if old is not None:
                before = results(old)[0]
                previous.setdefault('glibc_commit', glibc_commit(old))
        packages = [{'name': s['P'], 'version': s['V'], 'size': int(s['S'])}
                    for s in stanzas((directory / arch / 'APKINDEX.tar.gz').read_bytes())]
        architectures[arch] = {'tests': tests, 'previous_tests': before, 'report': report,
                               'packages': sorted(packages, key=lambda p: p['name'])}
    if previous is not None:
        found = lookup('repos/' + os.environ['GITHUB_REPOSITORY'] + '/compare/' + previous['commit'] +
                       '...' + os.environ['GITHUB_SHA'])
        commits = subjects(found['commits']) if found else None
        # Upstream glibc: the release-branch commits Wolfi's new pin brings, from
        # the mirror source.py fetches first.
        if previous.get('glibc_commit') == lock['glibc_commit']:
            glibc_commits = []
        elif previous.get('glibc_commit'):
            found = lookup('repos/kraj/glibc/compare/' + previous['glibc_commit'] + '...' + lock['glibc_commit'])
            glibc_commits = subjects(found['commits']) if found else None
    secdb = json.loads(download(notes.SECDB))
    policy = json.loads((ROOT / 'policy.json').read_text())
    return {'version': version, 'build_id': lock['build_id'],
            'date': datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
            'commit': os.environ['GITHUB_SHA'],
            'run': os.environ.get('GITHUB_SERVER_URL', 'https://github.com') + '/' +
                   os.environ['GITHUB_REPOSITORY'] + '/actions/runs/' + os.environ['GITHUB_RUN_ID'],
            'source': {'glibc_commit': lock['glibc_commit'], 'wolfi_commit': lock['wolfi_commit'],
                       'wolfi_version': wolfi, 'recipe': lock['recipe'], 'policy_revision': lock['revision']},
            'repository': {'stable': PUBLIC, 'snapshot': PUBLIC + 'builds/' + lock['build_id'],
                           'key_sha256': sha256(ROOT / 'release/packages.pub')},
            'patches': (ROOT / 'patches/series').read_text().split(), 'wolfi_inputs': lock['sha256'],
            'previous': previous, 'commits': commits, 'glibc_commits': glibc_commits,
            'ceiling': policy['max_fail_per_mille'],
            'security': notes.security(secdb, 'glibc-' + lock['version'],
                                       previous['wolfi_version'] if previous else None, wolfi),
            'architectures': architectures}

def stage(artifacts, assets, lock, tag):
    assets.mkdir(parents=True, exist_ok=True)
    records = {}
    for arch in ARCHES:
        directory = artifacts / ('glibc-' + arch)
        records[arch] = validate(directory, arch, lock)
        archive(directory, assets / ('glibc-' + arch + '.tar.gz'))
    manifest = {'build_id': lock['build_id'], 'version': records[ARCHES[0]]['version'],
                'source_sha': os.environ['GITHUB_SHA'], 'run_number': int(os.environ['GITHUB_RUN_NUMBER']),
                'repository': PUBLIC + 'builds/' + lock['build_id'],
                'sha256': {p.name: sha256(p) for p in sorted(assets.glob('*.tar.gz'))}}
    (assets / 'SHA256SUMS').write_text(''.join(digest + '  ' + name + '\n' for name, digest in manifest['sha256'].items()))
    (assets / 'release.json').write_text(json.dumps(manifest, indent=2) + '\n')
    current = release(tag)
    staged = {a['name'] for a in current['assets']} if current else set()
    if 'release-notes.json' in staged:
        # A retry keeps the notes first staged, whatever has changed since.
        for name in NOTES:
            run('gh', 'release', 'download', tag, '--pattern', name, '--clobber', '--dir', str(assets))
    else:
        made = notes.build(gather(artifacts, lock, records))
        (assets / 'release-notes.json').write_bytes(notes.encode(made))
        (assets / 'release-notes.md').write_text(notes.markdown(made))
        (assets / 'release-notes.html').write_text(notes.page(made))
    body = {'body': (assets / 'release-notes.md').read_text()}
    with tempfile.TemporaryDirectory() as directory:
        request = Path(directory) / 'release.json'
        if current is None:
            body.update({'tag_name': tag, 'draft': True, 'make_latest': 'false',
                         'target_commitish': os.environ['GITHUB_SHA'], 'name': 'glibc ' + manifest['version']})
            request.write_text(json.dumps(body))
            current = json.loads(run('gh', 'api', '--method', 'POST',
                                     'repos/' + os.environ['GITHUB_REPOSITORY'] + '/releases',
                                     '--input', str(request)))
        elif current.get('body') != body['body'] and current['draft']:
            request.write_text(json.dumps(body))
            run('gh', 'api', '--method', 'PATCH', 'repos/' + os.environ['GITHUB_REPOSITORY'] +
                '/releases/' + str(current['id']), '--input', str(request))
    if not current['draft']:
        raise ValueError('Refusing to change a published release')
    existing = {a['name'] for a in current['assets']}
    # release.json is last: a staged draft with it is complete.
    for path in [assets / ('glibc-' + a + '.tar.gz') for a in ARCHES] + [assets / 'SHA256SUMS'] + \
            [assets / name for name in NOTES] + [assets / 'release.json']:
        if path.name in existing:
            with tempfile.TemporaryDirectory() as directory:
                run('gh', 'release', 'download', tag, '--pattern', path.name, '--dir', directory)
                if sha256(Path(directory) / path.name) != sha256(path):
                    raise ValueError('Release asset already exists with different bytes: ' + path.name)
        else:
            run('gh', 'release', 'upload', tag, str(path))

def aws(*arguments):
    return subprocess.run(['aws', '--endpoint-url', ENDPOINT, '--region', 'auto',
                           's3api', *arguments], capture_output=True, text=True)

def fetch(key, destination):
    result = aws('get-object', '--bucket', BUCKET, '--key', PREFIX + key, str(destination))
    if result.returncode == 0:
        return True
    if '(NoSuchKey)' in result.stderr or '(404)' in result.stderr:
        return False
    raise RuntimeError(result.stderr)

def upload(path, key, immutable=True, content_type=None):
    if immutable:
        with tempfile.TemporaryDirectory() as directory:
            previous = Path(directory) / 'object'
            if fetch(key, previous):
                if sha256(previous) != sha256(path):
                    raise ValueError('R2 object already exists with different bytes: ' + key)
                return
    result = aws('put-object', '--bucket', BUCKET, '--key', PREFIX + key, '--body', str(path),
                 '--cache-control', 'public, max-age=31536000, immutable' if immutable else 'no-cache',
                 *(['--content-type', content_type] if content_type else []))
    if result.returncode:
        raise RuntimeError(result.stderr)

def entries(parts):
    # An authenticated index's stanzas, by the APK file each names.
    text = contents(parts[1][1])['APKINDEX'].decode()
    found = {}
    for stanza in text.strip().split('\n\n'):
        fields = dict(line.split(':', 1) for line in stanza.splitlines())
        found[fields['P'] + '-' + fields['V'] + '.apk'] = stanza
    return found

def merge(previous, current):
    # A published version keeps its first build: machines may hold it.
    merged, added = dict(previous), []
    for name, stanza in sorted(current.items()):
        if name not in merged:
            merged[name] = stanza
            added.append(name)
        elif merged[name] != stanza:
            print(name + ': the stable repository keeps its earlier build; increment policy.json revision to ship this one')
    return merged, added

def signed_index(stanzas, key):
    text = ''.join(stanzas[name] + '\n\n' for name in sorted(stanzas)).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data in [('APKINDEX', text), ('DESCRIPTION', b'')]:
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(data), 0o644
            archive.addfile(item, io.BytesIO(data))
    control = gzip.compress(buffer.getvalue(), mtime=0)
    signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key)], input=control,
                               stdout=subprocess.PIPE, check=True).stdout
    item = tarfile.TarInfo('.SIGN.RSA256.werewolf-packages.rsa.pub')
    item.size, item.mode, item.uname, item.gname = len(signature), 0o644, 'root', 'root'
    # apk reads both members as one tar stream: the signature's has no end marker.
    header = item.tobuf(tarfile.USTAR_FORMAT, tarfile.ENCODING, 'surrogateescape')
    return gzip.compress(header + signature + b'\0' * (-len(signature) % 512), mtime=0) + control

def stable(root, arch, key, directory):
    # The stable repository's next index, verified, and the APKs it adds.
    trust = ROOT / 'release/packages.pub'
    previous = {}
    published = directory / (arch + '-previous.tar.gz')
    if fetch(arch + '/APKINDEX.tar.gz', published):
        previous = entries(authenticated(published, trust))
    merged, added = merge(previous, entries(authenticated(root / arch / 'APKINDEX.tar.gz', trust)))
    index = directory / (arch + '-APKINDEX.tar.gz')
    index.write_bytes(signed_index(merged, key))
    authenticated(index, trust)
    return index, added

def publish(assets, lock, tag, key=ROOT / 'build/keys/werewolf-packages.rsa'):
    assets.mkdir(parents=True, exist_ok=True)
    run('gh', 'release', 'download', tag, '--dir', str(assets), '--clobber')
    manifest = json.loads((assets / 'release.json').read_text())
    if manifest['build_id'] != lock['build_id'] or not re.fullmatch('[0-9a-f]{40}', manifest['source_sha']):
        raise ValueError('Release manifest does not match captured inputs')
    if set(manifest['sha256']) != {'glibc-' + a + '.tar.gz' for a in ARCHES}:
        raise ValueError('Both native architectures are required')
    snapshot = 'builds/' + lock['build_id'] + '/'
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        roots, indexes = {}, {}
        # Validate and sign everything before the first upload.
        for name, digest in manifest['sha256'].items():
            if sha256(assets / name) != digest:
                raise ValueError('Release archive hash mismatch')
            arch = next(a for a in ARCHES if name == 'glibc-' + a + '.tar.gz')
            roots[arch] = work / arch
            with tarfile.open(assets / name) as archive:
                archive.extractall(roots[arch], filter='data')
            validate(roots[arch], arch, lock, source_sha=manifest['source_sha'])
            indexes[arch] = stable(roots[arch], arch, key, work)
        for arch, root in roots.items():
            # Objects first, then signed index; readers never see a partial index.
            for apk in sorted((root / arch).glob('*.apk')):
                upload(apk, snapshot + arch + '/' + apk.name)
            upload(root / arch / 'APKINDEX.tar.gz', snapshot + arch + '/APKINDEX.tar.gz')
            upload(assets / ('glibc-' + arch + '.tar.gz'), snapshot + 'glibc-' + arch + '.tar.gz')
        upload(assets / 'SHA256SUMS', snapshot + 'SHA256SUMS')
        # A draft staged before release notes existed has none.
        noted = (assets / 'release-notes.json').is_file()
        for name, kind in NOTES.items() if noted else ():
            upload(assets / name, snapshot + name, content_type=kind)
        upload(assets / 'release.json', snapshot + 'release.json')
        # The stable repository machines follow: every published APK, kept, and one index.
        for arch, (index, added) in indexes.items():
            for name in added:
                upload(roots[arch] / arch / name, arch + '/' + name)
            upload(index, arch + '/APKINDEX.tar.gz', immutable=False)
    with tempfile.TemporaryDirectory() as directory:
        current = Path(directory) / 'current'
        if not fetch('current.json', current) or json.loads(current.read_text())['run_number'] <= manifest['run_number']:
            upload(assets / 'release.json', 'current.json', immutable=False)
    if noted:
        update_index(json.loads((assets / 'release-notes.json').read_text()))
    # The public release is the completion marker, after both R2 repositories exist.
    run('gh', 'release', 'edit', tag, '--draft=false', '--latest=false')
    print(manifest['repository'])

def update_index(made):
    # The repository's front page lists every release with notes, newest first.
    with tempfile.TemporaryDirectory() as directory:
        listing = Path(directory) / 'releases.json'
        existing = json.loads(listing.read_text()) if fetch('releases.json', listing) else []
        if not isinstance(existing, list) or not all({'build_id', 'version'} <= set(r) for r in existing):
            raise ValueError('releases.json is malformed')
        entries = notes.releases(existing, made)
        listing.write_bytes(notes.encode(entries))
        upload(listing, 'releases.json', immutable=False, content_type='application/json')
        page = Path(directory) / 'index.html'
        page.write_text(notes.index(entries))
        upload(page, 'index.html', immutable=False, content_type='text/html; charset=utf-8')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['status', 'stage', 'publish'])
    parser.add_argument('--artifacts', type=Path, default=Path('artifacts'))
    parser.add_argument('--assets', type=Path, default=Path('build/release'))
    args = parser.parse_args()
    lock = verify()
    tag = 'build-' + lock['build_id']
    if args.command == 'status':
        state = status(tag)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                output.write('state=' + state + '\nbuild_id=' + lock['build_id'] + '\n')
        print(state)
    elif args.command == 'stage':
        stage(args.artifacts, args.assets, lock, tag)
    else:
        publish(args.assets, lock, tag)

if __name__ == '__main__':
    main()
