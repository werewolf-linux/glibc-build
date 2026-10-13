import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import derive

class Derivation(unittest.TestCase):
    def test_future_upstream_flag_survives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            upstream = yaml.safe_load((ROOT/'upstream.yaml').read_text())
            configure = next(x for x in upstream['pipeline'] if x.get('name') == 'Configure glibc')
            configure['runs'] += '\n# Added by a future Wolfi update: --enable-future-protection\n'
            (root/'upstream.yaml').write_text(yaml.safe_dump(upstream))
            shutil.copyfile(ROOT/'upstream.lock.json', root/'upstream.lock.json')
            with patch.object(derive, 'ROOT', root):
                result = derive.derive()
            self.assertIn('--enable-future-protection', next(x['runs'] for x in result['pipeline'] if x.get('name') == 'Configure glibc'))

    def test_source_pin_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(ROOT/'upstream.yaml', root/'upstream.yaml')
            lock = json.loads((ROOT/'upstream.lock.json').read_text())
            lock['glibc_commit'] = '0'*40
            (root/'upstream.lock.json').write_text(json.dumps(lock))
            with patch.object(derive, 'ROOT', root), self.assertRaises(AssertionError):
                derive.derive()

    def test_removed_facilities_cannot_resolve_back_to_wolfi(self):
        result = derive.derive()
        names = [x['name'] for x in result['subpackages']]
        for forbidden in ['nscd-', 'nss-db-', 'nss-hesiod-', 'pcprofiledump-', 'sotruss-']:
            self.assertFalse(any(x.startswith(forbidden) for x in names), forbidden)
        solver = next(x['runs'] for x in result['test']['pipeline'] if x.get('name') == 'Verify version-streamed virtuals do not resolve to an older package')
        for forbidden in derive.REMOVED:
            self.assertNotIn(forbidden, [line.strip() for line in solver.splitlines()])

    def test_development_and_loader_packages_require_matching_policy_libc(self):
        result = derive.derive()
        dev = next(x for x in result['subpackages'] if x['name'] == '${{package.name}}-dev')
        deps = dev['dependencies']
        self.assertIn('${{package.name}}=${{package.full-version}}', deps['runtime'])
        self.assertIn('glibc-2.44-dev=${{package.full-version}}', deps['provides'])
        self.assertIn('glibc-2.44-dev', deps['replaces'])
        loader = next(x for x in result['subpackages'] if x['name'].startswith('ld-linux-neutered-'))
        self.assertIn('${{package.name}}=${{package.full-version}}', loader['dependencies']['runtime'])
        self.assertIn('ld-linux-neutered-${{package.version}}=${{package.full-version}}', result['package']['dependencies']['runtime'])

if __name__ == '__main__':
    unittest.main()
