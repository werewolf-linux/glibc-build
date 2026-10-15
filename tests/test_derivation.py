import json
from pathlib import Path
import re
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
    def test_source_fetch_declares_its_guest_dependency(self):
        result = derive.derive()
        self.assertIn('git', result['pipeline'][0]['needs']['packages'])

    def test_future_upstream_flag_survives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'build/inputs').mkdir(parents=True)
            upstream = yaml.safe_load((ROOT/'build/inputs/upstream.yaml').read_text())
            configure = next(x for x in upstream['pipeline'] if x.get('name') == 'Configure glibc')
            configure['runs'] += '\n# Added by a future Wolfi update: --enable-future-protection\n'
            (root/'build/inputs/upstream.yaml').write_text(yaml.safe_dump(upstream))
            shutil.copyfile(ROOT/'build/inputs/upstream.lock.json', root/'build/inputs/upstream.lock.json')
            shutil.copyfile(ROOT/'policy.json', root/'policy.json')
            shutil.copytree(ROOT/'profile', root/'profile')
            with patch.object(derive, 'ROOT', root):
                result = derive.derive()
            self.assertIn('--enable-future-protection', next(x['runs'] for x in result['pipeline'] if x.get('name') == 'Configure glibc'))

    def test_source_pin_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'build/inputs').mkdir(parents=True)
            shutil.copyfile(ROOT/'build/inputs/upstream.yaml', root/'build/inputs/upstream.yaml')
            lock = json.loads((ROOT/'build/inputs/upstream.lock.json').read_text())
            lock['glibc_commit'] = '0'*40
            (root/'build/inputs/upstream.lock.json').write_text(json.dumps(lock))
            shutil.copyfile(ROOT/'policy.json', root/'policy.json')
            with patch.object(derive, 'ROOT', root), self.assertRaises(AssertionError):
                derive.derive()

    def test_changed_upstream_source_checkout_requires_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'build/inputs').mkdir(parents=True)
            upstream = yaml.safe_load((ROOT/'build/inputs/upstream.yaml').read_text())
            upstream['pipeline'][0]['with']['recurse-submodules'] = 'true'
            (root/'build/inputs/upstream.yaml').write_text(yaml.safe_dump(upstream))
            shutil.copyfile(ROOT/'build/inputs/upstream.lock.json', root/'build/inputs/upstream.lock.json')
            shutil.copyfile(ROOT/'policy.json', root/'policy.json')
            with patch.object(derive, 'ROOT', root), self.assertRaisesRegex(ValueError, 'Review changed'):
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
        self.assertIn('glibc-'+str(result['package']['version'])+'-dev=${{package.full-version}}', deps['provides'])
        self.assertIn('glibc-'+str(result['package']['version'])+'-dev', deps['replaces'])
        loader = next(x for x in result['subpackages'] if x['name'].startswith('ld-linux-neutered-'))
        self.assertIn('${{package.name}}=${{package.full-version}}', loader['dependencies']['runtime'])
        self.assertIn('ld-linux-neutered-${{package.version}}=${{package.full-version}}', result['package']['dependencies']['runtime'])

    def test_builtin_nss_configuration_is_a_required_owned_package(self):
        result = derive.derive()
        self.assertIn('${{package.name}}-nss-config=${{package.full-version}}', result['package']['dependencies']['runtime'])
        profile = next(x for x in result['subpackages'] if x['name'] == '${{package.name}}-nss-config')
        self.assertEqual(['wolfi-baselayout'], profile['dependencies']['replaces'])
        self.assertIn('${{package.name}}=${{package.full-version}}', profile['dependencies']['runtime'])
        for line in (ROOT/'profile/nsswitch.conf').read_text().splitlines():
            self.assertLessEqual(set(line.split(':', 1)[1].split()), {'files', 'dns'})

    def test_removed_subpackage_files_leave_the_main_package(self):
        result = derive.derive()
        removal = next(x['runs'] for x in result['pipeline'] if x.get('name') == 'Remove unsupported runtime facilities')
        # xtrace is a bash script: left behind, every image would need bash.
        for path in ['usr/bin/xtrace', 'usr/bin/mtrace', 'usr/bin/sprof', 'usr/bin/makedb', 'usr/lib/audit/*']:
            self.assertIn('rm -rf "${{targets.destdir}}"/' + path + '\n', removal)

    def test_changed_removed_subpackage_packaging_requires_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'build/inputs').mkdir(parents=True)
            upstream = yaml.safe_load((ROOT/'build/inputs/upstream.yaml').read_text())
            tracing = next(x for x in upstream['subpackages'] if x['name'] == '${{package.name}}-tracing')
            tracing['pipeline'][0]['runs'] += 'cp "${{targets.destdir}}"/usr/bin/new "${{targets.subpkgdir}}"/usr/bin\n'
            (root/'build/inputs/upstream.yaml').write_text(yaml.safe_dump(upstream))
            shutil.copyfile(ROOT/'build/inputs/upstream.lock.json', root/'build/inputs/upstream.lock.json')
            shutil.copyfile(ROOT/'policy.json', root/'policy.json')
            shutil.copytree(ROOT/'profile', root/'profile')
            with patch.object(derive, 'ROOT', root), self.assertRaisesRegex(ValueError, 'Review changed upstream glibc-tracing'):
                derive.derive()

    def configure(self, result):
        return next(x['runs'] for x in result['pipeline'] if x.get('name') == 'Configure glibc')

    def test_hardening_beyond_wolfi_survives_configparms_rebuilds(self):
        configure = self.configure(derive.derive())
        for line in derive.HARDENING:
            for target in ['configparms.base', 'configparms']:
                self.assertIn(f"echo '{line}' >> {target}\n", configure)
        self.assertEqual(['6.18'], re.findall(r'--enable-kernel=([0-9.]+)', configure))

    def test_a_newer_upstream_minimum_kernel_is_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'build/inputs').mkdir(parents=True)
            upstream = yaml.safe_load((ROOT/'build/inputs/upstream.yaml').read_text())
            configure = next(x for x in upstream['pipeline'] if x.get('name') == 'Configure glibc')
            configure['runs'] = re.sub(r'--enable-kernel=[0-9.]+', '--enable-kernel=7.1', configure['runs'])
            (root/'build/inputs/upstream.yaml').write_text(yaml.safe_dump(upstream))
            shutil.copyfile(ROOT/'build/inputs/upstream.lock.json', root/'build/inputs/upstream.lock.json')
            shutil.copyfile(ROOT/'policy.json', root/'policy.json')
            shutil.copytree(ROOT/'profile', root/'profile')
            with patch.object(derive, 'ROOT', root):
                result = derive.derive()
            self.assertEqual(['7.1'], re.findall(r'--enable-kernel=([0-9.]+)', self.configure(result)))

    def test_every_package_names_the_wolfi_source_it_rebuilds(self):
        upstream = yaml.safe_load((ROOT/'build/inputs/upstream.yaml').read_text())['package']
        result = derive.derive()
        source = f"wolfi-origin:{upstream['name']}:{upstream['version']}-r{upstream['epoch']}"
        for section in [result['package']] + result['subpackages']:
            # Unversioned: apk installs one provider of each name=version.
            self.assertIn(source, section['dependencies']['provides'])

    def test_unversioned_virtual_prefers_policy_libc_and_newer_streams(self):
        result = derive.derive()
        self.assertIn('glibc-neutered=${{package.full-version}}', result['package']['dependencies']['provides'])
        self.assertNotIn('neutered-priority', result['vars'])
        transform = next(x for x in result['var-transforms'] if x['to'] == 'neutered-priority')
        wolfi = next(x for x in result['var-transforms'] if x['to'] == 'provider-priority')
        self.assertEqual((wolfi['from'], wolfi['match']), (transform['from'], transform['match']))
        self.assertEqual('10$1$2', transform['replace'])

if __name__ == '__main__':
    unittest.main()
