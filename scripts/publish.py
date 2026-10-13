#!/usr/bin/env python3
"""Publish validated native artifacts to immutable R2 snapshots and GitHub."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import zlib
import yaml
from derive import derive
from inputs import ROOT, verify, sha256

ARCHES = ('x86_64', 'aarch64')
ENDPOINT = 'https://c860af766754fb92eec27bc723e6db5d.r2.cloudflarestorage.com'
BUCKET = 'werewolf'
PREFIX = 'apk/glibc-neutered/'
PUBLIC = 'https://dist.werewolf-linux.org/' + PREFIX

def run(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, text=True).stdout

def release(tag):
    result = subprocess.run(['gh', 'api', 'repos/' + os.environ['GITHUB_REPOSITORY'] +
                             '/releases/tags/' + tag], capture_output=True, text=True)
    if result.returncode:
        if 'HTTP 404' in result.stderr:
            return None
        raise RuntimeError(result.stderr)
    return json.loads(result.stdout)

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

def stage(artifacts, assets, lock, tag):
    assets.mkdir(parents=True, exist_ok=True)
    records = {}
    for arch in ARCHES:
        directory = artifacts / ('glibc-neutered-' + arch)
        records[arch] = validate(directory, arch, lock)
        run('tar', '-czf', str(assets / ('glibc-neutered-' + arch + '.tar.gz')),
            '-C', str(directory), '.')
    manifest = {'build_id': lock['build_id'], 'version': records[ARCHES[0]]['version'],
                'source_sha': os.environ['GITHUB_SHA'], 'run_number': int(os.environ['GITHUB_RUN_NUMBER']),
                'repository': PUBLIC + 'builds/' + lock['build_id'],
                'sha256': {p.name: sha256(p) for p in sorted(assets.glob('*.tar.gz'))}}
    (assets / 'SHA256SUMS').write_text(''.join(digest + '  ' + name + '\n' for name, digest in manifest['sha256'].items()))
    (assets / 'release.json').write_text(json.dumps(manifest, indent=2) + '\n')
    current = release(tag)
    if current is None:
        run('gh', 'release', 'create', tag, '--draft', '--latest=false',
            '--target', os.environ['GITHUB_SHA'], '--title', 'glibc-neutered ' + manifest['version'],
            '--notes', 'Signed APKs for x86_64 and aarch64. Repository: ' + manifest['repository'] +
            '\nBoth native builds, hardening probes, ABI checks and the downstream raw failure gate passed. '
            'Every upstream failure is retained in the testresults APK.')
        current = release(tag)
    if not current['draft']:
        raise ValueError('Refusing to change a published release')
    existing = {a['name'] for a in current['assets']}
    for path in [assets / ('glibc-neutered-' + a + '.tar.gz') for a in ARCHES] + [assets / 'SHA256SUMS', assets / 'release.json']:
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

def upload(path, key, immutable=True):
    if immutable:
        with tempfile.TemporaryDirectory() as directory:
            previous = Path(directory) / 'object'
            if fetch(key, previous):
                if sha256(previous) != sha256(path):
                    raise ValueError('R2 object already exists with different bytes: ' + key)
                return
    result = aws('put-object', '--bucket', BUCKET, '--key', PREFIX + key, '--body', str(path),
                 '--cache-control', 'public, max-age=31536000, immutable' if immutable else 'no-cache')
    if result.returncode:
        raise RuntimeError(result.stderr)

def publish(assets, lock, tag):
    assets.mkdir(parents=True, exist_ok=True)
    run('gh', 'release', 'download', tag, '--dir', str(assets), '--clobber')
    manifest = json.loads((assets / 'release.json').read_text())
    if manifest['build_id'] != lock['build_id'] or not re.fullmatch('[0-9a-f]{40}', manifest['source_sha']):
        raise ValueError('Release manifest does not match captured inputs')
    if set(manifest['sha256']) != {'glibc-neutered-' + a + '.tar.gz' for a in ARCHES}:
        raise ValueError('Both native architectures are required')
    snapshot = 'builds/' + lock['build_id'] + '/'
    for name, digest in manifest['sha256'].items():
        if sha256(assets / name) != digest:
            raise ValueError('Release archive hash mismatch')
        arch = next(a for a in ARCHES if name == 'glibc-neutered-' + a + '.tar.gz')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with tarfile.open(assets / name) as archive:
                archive.extractall(root, filter='data')
            validate(root, arch, lock, source_sha=manifest['source_sha'])
            # Objects first, then signed index; readers never see a partial index.
            for apk in sorted((root / arch).glob('*.apk')):
                upload(apk, snapshot + arch + '/' + apk.name)
            upload(root / arch / 'APKINDEX.tar.gz', snapshot + arch + '/APKINDEX.tar.gz')
        upload(assets / name, snapshot + name)
    upload(assets / 'SHA256SUMS', snapshot + 'SHA256SUMS')
    upload(assets / 'release.json', snapshot + 'release.json')
    with tempfile.TemporaryDirectory() as directory:
        current = Path(directory) / 'current'
        if not fetch('current.json', current) or json.loads(current.read_text())['run_number'] <= manifest['run_number']:
            upload(assets / 'release.json', 'current.json', immutable=False)
    # The public release is the completion marker, after both R2 repositories exist.
    run('gh', 'release', 'edit', tag, '--draft=false', '--latest=false')
    print(manifest['repository'])

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
