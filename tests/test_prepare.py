import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import prepare

class SourcePreparation(unittest.TestCase):
    def test_generated_inputs_prepare_source_without_a_legacy_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'original'
            source.mkdir()
            def git(*args):
                return subprocess.run(['git', '-C', str(source), *args],
                    check=True, capture_output=True, text=True).stdout.strip()
            git('init')
            (source/'policy.txt').write_text('base\n')
            git('add', 'policy.txt')
            git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                'commit', '-m', 'fixture')
            commit = git('rev-parse', 'HEAD')
            inputs = root/'build/inputs'
            (inputs/'upstream').mkdir(parents=True)
            (root/'patches').mkdir()
            (inputs/'upstream.lock.json').write_text(json.dumps({'glibc_commit': commit}))
            (inputs/'upstream.yaml').write_text(yaml.safe_dump({
                'pipeline': [{'uses': 'patch', 'with': {'patches': 'upstream.patch'}}]}))
            def change(before, after):
                return '--- a/policy.txt\n+++ b/policy.txt\n@@ -1 +1 @@\n-'+before+'\n+'+after+'\n'
            (inputs/'upstream/upstream.patch').write_text(change('base', 'upstream'))
            (root/'patches/policy.patch').write_text(change('upstream', 'downstream'))
            (root/'patches/series').write_text('policy.patch\n')
            failures = 'FAIL: preserved upstream fixture\n'
            (inputs/'upstream/allowed-failures.txt').write_text(failures)
            destination = root/'prepared'
            actual_run = subprocess.run
            def quiet_run(*args, **kwargs):
                kwargs.setdefault('stdout', subprocess.PIPE)
                kwargs.setdefault('stderr', subprocess.PIPE)
                return actual_run(*args, **kwargs)
            with patch.object(prepare, 'ROOT', root), patch.object(prepare, 'INPUTS', inputs), \
                 patch.object(sys, 'argv', ['prepare.py', str(destination), '--source', str(source)]), \
                 patch.object(prepare.subprocess, 'run', side_effect=quiet_run), \
                 contextlib.redirect_stdout(io.StringIO()):
                prepare.main()
            self.assertFalse((root/'upstream').exists())
            self.assertEqual('downstream\n', (destination/'policy.txt').read_text())
            self.assertEqual(failures, (destination/'allowed-failures.txt').read_text())

if __name__ == '__main__':
    unittest.main()
