#!/usr/bin/env python3
"""Copy the published repository to its canonical prefix before new builds."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import tempfile
from urllib.parse import quote

import publish

LEGACY = 'apk/glibc-neutered/'
MARKER = 'prefix-migration.json'


def request(*args, missing=False):
    result = publish.aws(*args)
    if result.returncode:
        if missing and ('(NoSuchKey)' in result.stderr or '(404)' in result.stderr):
            return None
        raise RuntimeError(result.stderr)
    return json.loads(result.stdout or '{}')


def head(key):
    return request('head-object', '--bucket', publish.BUCKET, '--key', key, missing=True)


def listing():
    objects, token = [], None
    while True:
        page = request('list-objects-v2', '--bucket', publish.BUCKET, '--prefix', LEGACY,
                       '--no-paginate', *(['--continuation-token', token] if token else []))
        objects.extend(page.get('Contents', []))
        if not page.get('IsTruncated'):
            return objects
        token = page['NextContinuationToken']


def phase(key):
    name = key.removeprefix(LEGACY)
    if name in ('releases.json', 'index.html', 'current.json'):
        return 3 + ('releases.json', 'index.html', 'current.json').index(name)
    if name in (arch + '/APKINDEX.tar.gz' for arch in publish.ARCHES):
        return 2
    if name.endswith(('/APKINDEX.tar.gz', '.json', '.md', '.html')):
        return 1
    return 0


def copy(item):
    source = item['Key']
    destination = publish.PREFIX + source.removeprefix(LEGACY)
    previous = head(destination)
    if source.endswith(('.json', '.md', '.html')):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'object'
            request('get-object', '--bucket', publish.BUCKET, '--key', source,
                    '--if-match', item['ETag'], str(path))
            data = path.read_bytes().replace(b'/apk/glibc-neutered', b'/apk/glibc')
            path.write_bytes(data)
            # Every source object came from put-object (single-part MD5 ETag).
            digest = '"' + hashlib.md5(data, usedforsecurity=False).hexdigest() + '"'
            if previous:
                if (previous['ETag'], previous['ContentLength']) != (digest, len(data)):
                    raise ValueError('Migration destination differs: ' + destination)
                return
            kind = {'.json': 'application/json', '.md': 'text/markdown; charset=utf-8',
                    '.html': 'text/html; charset=utf-8'}[Path(source).suffix]
            request('put-object', '--bucket', publish.BUCKET, '--key', destination,
                    '--body', str(path), '--content-type', kind, '--cache-control', 'no-cache')
            expected = digest, len(data)
    else:
        expected = item['ETag'], item['Size']
        if previous:
            if (previous['ETag'], previous['ContentLength']) != expected:
                raise ValueError('Migration destination differs: ' + destination)
            return
        request('copy-object', '--bucket', publish.BUCKET, '--key', destination,
                '--copy-source', quote(publish.BUCKET + '/' + source, safe='/'),
                '--copy-source-if-match', item['ETag'])
    copied = head(destination)
    if copied is None or (copied['ETag'], copied['ContentLength']) != expected:
        raise ValueError('Migration copy verification failed: ' + destination)
    print(destination, flush=True)


def migrate():
    if LEGACY == publish.PREFIX:
        raise ValueError('Source and destination prefixes must differ')
    with tempfile.TemporaryDirectory() as directory:
        marker = Path(directory) / MARKER
        if publish.fetch(MARKER, marker):
            if json.loads(marker.read_text()) != {'source': LEGACY, 'destination': publish.PREFIX}:
                raise ValueError('Unexpected migration marker')
            print('Repository prefix migration is complete')
            return
        objects = listing()
        names = {item['Key'] for item in objects}
        required = {LEGACY + 'current.json'} | {LEGACY + a + '/APKINDEX.tar.gz' for a in publish.ARCHES}
        if not required <= names:
            raise ValueError('Legacy repository is incomplete')
        # Authenticate both indexes before exposing either at the new URL.
        for arch in publish.ARCHES:
            path = Path(directory) / (arch + '.tar.gz')
            item = next(o for o in objects if o['Key'] == LEGACY + arch + '/APKINDEX.tar.gz')
            request('get-object', '--bucket', publish.BUCKET, '--key', item['Key'],
                    '--if-match', item['ETag'], str(path))
            publish.authenticated(path, publish.ROOT / 'release/packages.pub')
        # Payloads, snapshot metadata, signed stable indexes, catalog, pointer.
        for step in range(6):
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(copy, (item for item in objects if phase(item['Key']) == step)))
        marker.write_text(json.dumps({'source': LEGACY, 'destination': publish.PREFIX}) + '\n')
        publish.upload(marker, MARKER, content_type='application/json')


if __name__ == '__main__':
    migrate()
