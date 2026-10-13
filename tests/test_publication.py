import io
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import inputs
import publish
import refresh

class LatestInputs(unittest.TestCase):
    def recipe(self, root, version, source='1'*40, primary=True):
        config = {'package': {'name': 'glibc-' + version, 'version': version,
                              'dependencies': {'provides': ['glibc=${{package.full-version}}'] if primary else []}},
                  'vars': {'glibc-expected-commit': source}}
        (root / ('glibc-' + version + '.yaml')).write_text(yaml.safe_dump(config))

    def test_latest_is_numeric_and_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for version in ['2.9', '2.10', '2.11_rc1']:
                self.recipe(root, version)
            self.recipe(root, '99.0', primary=False)
            self.assertEqual('glibc-2.10.yaml', refresh.latest(root)[0].name)

    def test_invalid_newest_source_pin_never_falls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.recipe(root, '2.9')
            self.recipe(root, '2.10', source='floating')
            with self.assertRaises(ValueError):
                refresh.latest(root)

    def test_unrelated_commit_does_not_rebuild_but_source_and_policy_do(self):
        lock = {'recipe': 'example.yaml', 'glibc_commit': '1'*40, 'revision': 6,
                'sha256': {'upstream.yaml': '2'*64}, 'mode': {'upstream.yaml': 0o644},
                'policy_sha256': {'patch': '3'*64},
                'wolfi_commit': '4'*40}
        first = inputs.identity(lock)
        lock['wolfi_commit'] = '5'*40
        self.assertEqual(first, inputs.identity(lock))
        lock['glibc_commit'] = '6'*40
        self.assertNotEqual(first, inputs.identity(lock))
        lock['glibc_commit'] = '1'*40
        lock['policy_sha256']['patch'] = '7'*64
        self.assertNotEqual(first, inputs.identity(lock))

class ReleaseGate(unittest.TestCase):
    def test_control_signature_is_required_and_tampering_is_rejected(self):
        def member(files):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as archive:
                for name, data in files.items():
                    item = tarfile.TarInfo(name)
                    item.size = len(data)
                    archive.addfile(item, io.BytesIO(data))
            return gzip.compress(buffer.getvalue())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, public = root/'key', root/'key.pub'
            subprocess.run(['openssl', 'genrsa', '-out', str(private), '2048'], check=True, capture_output=True)
            subprocess.run(['openssl', 'rsa', '-in', str(private), '-pubout', '-out', str(public)], check=True, capture_output=True)
            control = member({'APKINDEX': b'P:example\n'})
            (root/'control').write_bytes(control)
            subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(private), '-out', str(root/'sig'), str(root/'control')], check=True, capture_output=True)
            signed = member({'.SIGN.RSA256.werewolf-packages.rsa.pub': (root/'sig').read_bytes()})
            archive = root/'APKINDEX.tar.gz'
            archive.write_bytes(signed + control)
            self.assertEqual(2, len(publish.authenticated(archive, public)))
            archive.write_bytes(signed + member({'APKINDEX': b'P:attacker\n'}))
            with self.assertRaises(subprocess.CalledProcessError):
                publish.authenticated(archive, public)
            archive.write_bytes(control)
            with self.assertRaises(ValueError):
                publish.authenticated(archive, public)

    def results(self, passed, failed):
        files = {f'{i}.test-result': b'PASS: case\n' for i in range(passed)}
        files.update({f'f{i}.test-result': b'FAIL: case\n' for i in range(failed)})
        files['usr/share/glibc-testresults/policy-report.json'] = b'{}'
        return files

    def test_current_raw_results_pass_55_but_fail_20(self):
        files = self.results(6355, 345)
        publish.raw_gate(files, 55)
        with self.assertRaises(ValueError):
            publish.raw_gate(files, 20)

    def test_ceiling_is_exact_and_unsupported_does_not_dilute_it(self):
        files = self.results(6332, 368)
        publish.raw_gate(files, 55)
        files['extra.test-result'] = b'FAIL: another\n'
        files.update({f'u{i}.test-result': b'UNSUPPORTED: case\n' for i in range(10000)})
        with self.assertRaises(ValueError):
            publish.raw_gate(files, 55)

    def test_empty_results_and_missing_policy_evidence_fail(self):
        with self.assertRaises(ValueError):
            publish.raw_gate(self.results(0, 0), 55)
        files = self.results(100, 0)
        del files['usr/share/glibc-testresults/policy-report.json']
        with self.assertRaises(ValueError):
            publish.raw_gate(files, 55)

    def test_existing_r2_object_must_have_identical_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'object'
            path.write_bytes(b'new')
            def existing(key, destination):
                destination.write_bytes(b'old')
                return True
            with patch.object(publish, 'fetch', existing), patch.object(publish, 'aws') as aws:
                with self.assertRaises(ValueError):
                    publish.upload(path, 'builds/example/aarch64/example.apk')
                aws.assert_not_called()

    def test_missing_r2_object_uploads_and_matching_object_skips(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'object'
            path.write_bytes(b'new')
            with patch.object(publish, 'fetch', return_value=False), patch.object(publish, 'aws') as aws:
                aws.return_value.returncode = 0
                publish.upload(path, 'builds/example/aarch64/example.apk')
                aws.assert_called_once()
            def existing(key, destination):
                destination.write_bytes(path.read_bytes())
                return True
            with patch.object(publish, 'fetch', existing), patch.object(publish, 'aws') as aws:
                publish.upload(path, 'builds/example/aarch64/example.apk')
                aws.assert_not_called()

    def test_auth_error_is_not_treated_as_absent_release(self):
        result = subprocess.CompletedProcess([], 1, '', 'HTTP 403: Forbidden')
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'example/repo'}):
            with patch.object(subprocess, 'run', return_value=result):
                with self.assertRaises(RuntimeError):
                    publish.release('build-example')

    def test_status_only_reuses_complete_drafts(self):
        with patch.object(publish, 'release', return_value=None):
            self.assertEqual('build', publish.status('example'))
        with patch.object(publish, 'release', return_value={'draft': True, 'assets': []}):
            self.assertEqual('build', publish.status('example'))
        with patch.object(publish, 'release', return_value={'draft': True, 'assets': [{'name': 'release.json'}]}):
            self.assertEqual('publish', publish.status('example'))
        with patch.object(publish, 'release', return_value={'draft': False, 'assets': []}):
            with self.assertRaises(ValueError):
                publish.status('example')

if __name__ == '__main__':
    unittest.main()
