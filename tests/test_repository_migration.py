import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import publish

spec = importlib.util.spec_from_file_location('migration', ROOT / 'scripts/migrate-repository.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


def etag(data):
    return '"' + hashlib.md5(data, usedforsecurity=False).hexdigest() + '"'


class RepositoryMigration(unittest.TestCase):
    def setUp(self):
        self.objects, self.writes = {}, []
        self.failure_key = None
        self.authentications = []
        for arch in publish.ARCHES:
            self.objects[migration.LEGACY + arch + '/APKINDEX.tar.gz'] = b'signed index ' + arch.encode()
            self.objects[migration.LEGACY + arch + '/glibc-neutered-2.44-r21.apk'] = b'signed APK ' + arch.encode()
        self.objects[migration.LEGACY + 'builds/old/glibc-aarch64.tar.gz'] = b'archive /apk/glibc-neutered'
        pointer = json.dumps({'repository': 'https://dist.werewolf-linux.org/' + migration.LEGACY + 'builds/old',
                              'version': '2.44-r21', 'sha256': {'glibc-aarch64.tar.gz': 'original-hash'}}).encode()
        self.objects[migration.LEGACY + 'builds/old/release.json'] = pointer
        self.objects[migration.LEGACY + 'current.json'] = pointer
        self.objects[migration.LEGACY + 'releases.json'] = b'[{"url":"/apk/glibc-neutered/builds/old"}]'
        self.objects[migration.LEGACY + 'index.html'] = b'<a href="/apk/glibc-neutered/builds/old">glibc-neutered</a>'

    def aws(self, *args):
        action = args[0]
        key = args[args.index('--key') + 1] if '--key' in args else None
        response = {}
        if action == 'list-objects-v2':
            prefix = args[args.index('--prefix') + 1]
            keys = sorted(k for k in self.objects if k.startswith(prefix))
            offset = int(args[args.index('--continuation-token') + 1]) if '--continuation-token' in args else 0
            selected = keys[offset:offset + 3]
            response = {'Contents': [{'Key': k, 'Size': len(self.objects[k]), 'ETag': etag(self.objects[k])}
                                     for k in selected], 'IsTruncated': offset + 3 < len(keys)}
            if response['IsTruncated']:
                response['NextContinuationToken'] = str(offset + 3)
        elif action in ('head-object', 'get-object'):
            if key not in self.objects:
                return subprocess.CompletedProcess(args, 1, '', '(404) Not Found')
            data = self.objects[key]
            response = {'ETag': etag(data), 'ContentLength': len(data)}
            if action == 'get-object':
                if '--if-match' in args:
                    self.assertEqual(etag(data), args[args.index('--if-match') + 1])
                Path(args[-1]).write_bytes(data)
        elif action in ('copy-object', 'put-object'):
            if self.failure_key == key:
                self.failure_key = None
                return subprocess.CompletedProcess(args, 1, '', 'transient copy failure')
            if action == 'copy-object':
                source = args[args.index('--copy-source') + 1].removeprefix(publish.BUCKET + '/')
                data = self.objects[source]
                self.assertEqual(etag(data), args[args.index('--copy-source-if-match') + 1])
            else:
                data = Path(args[args.index('--body') + 1]).read_bytes()
            self.objects[key] = data
            self.writes.append(key)
        else:
            self.fail('Unexpected AWS action: ' + action)
        return subprocess.CompletedProcess(args, 0, json.dumps(response), '')

    def migrate(self):
        def authenticate(path, key):
            self.assertTrue(path.read_bytes().startswith(b'signed index '))
            self.assertFalse(self.writes)
            self.authentications.append(path.name)
        with patch.object(publish, 'aws', side_effect=self.aws), \
             patch.object(publish, 'authenticated', side_effect=authenticate):
            migration.migrate()

    def test_history_is_copied_and_pointer_is_exposed_last(self):
        before = dict(self.objects)
        self.migrate()
        self.assertEqual(2, len(self.authentications))
        for source, original in before.items():
            destination = publish.PREFIX + source.removeprefix(migration.LEGACY)
            expected = original.replace(b'/apk/glibc-neutered', b'/apk/glibc') if source.endswith(
                ('.json', '.html', '.md')) else original
            self.assertEqual(expected, self.objects[destination])
            self.assertEqual(original, self.objects[source])
        self.assertIn(b'original-hash', self.objects[publish.PREFIX + 'current.json'])
        for arch in publish.ARCHES:
            self.assertLess(self.writes.index(publish.PREFIX + arch + '/glibc-neutered-2.44-r21.apk'),
                            self.writes.index(publish.PREFIX + arch + '/APKINDEX.tar.gz'))
        self.assertEqual([publish.PREFIX + 'current.json', publish.PREFIX + migration.MARKER], self.writes[-2:])
        self.writes.clear()
        self.migrate()
        self.assertEqual([], self.writes)

    def test_interrupted_copy_resumes_without_exposing_incomplete_indexes(self):
        self.failure_key = publish.PREFIX + 'aarch64/glibc-neutered-2.44-r21.apk'
        with self.assertRaisesRegex(RuntimeError, 'transient copy'):
            self.migrate()
        for arch in publish.ARCHES:
            self.assertNotIn(publish.PREFIX + arch + '/APKINDEX.tar.gz', self.objects)
        self.assertNotIn(publish.PREFIX + 'current.json', self.objects)
        self.writes.clear()
        self.migrate()
        self.assertIn(publish.PREFIX + migration.MARKER, self.objects)

    def test_conflicting_destination_stops_without_overwriting_it(self):
        key = publish.PREFIX + 'aarch64/glibc-neutered-2.44-r21.apk'
        self.objects[key] = b'conflicting bytes'
        with self.assertRaisesRegex(ValueError, 'destination differs'):
            self.migrate()
        self.assertEqual(b'conflicting bytes', self.objects[key])
        self.assertNotIn(publish.PREFIX + 'current.json', self.objects)

    def test_authentication_errors_and_incomplete_sources_stop_migration(self):
        with patch.object(publish, 'aws', return_value=subprocess.CompletedProcess([], 1, '', '(403) Forbidden')):
            with self.assertRaisesRegex(RuntimeError, 'Forbidden'):
                migration.head('anything')
        del self.objects[migration.LEGACY + 'aarch64/APKINDEX.tar.gz']
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.migrate()
        self.assertEqual([], self.writes)


if __name__ == '__main__':
    unittest.main()
