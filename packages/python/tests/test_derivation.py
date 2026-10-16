import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts'))
import derive
import packages
import verify

HERE = Path(__file__).resolve().parent
FIXTURE = yaml.safe_load((HERE / 'fixtures/python-3.15.yaml').read_text())
COMMIT = next(s for s in FIXTURE['pipeline'] if s.get('uses') == 'git-checkout')['with']['expected-commit']
LOCK = {'recipe': 'python-3.15.yaml', 'version': '3.15.0_git20261010', 'epoch': 0, 'revision': 1,
        'source_commit': COMMIT}


class Derivation(unittest.TestCase):
    def derived(self, change=None, lock=None):
        """The package and derive() over a copy of Wolfi's recipe, after change(recipe)."""
        upstream = copy.deepcopy(FIXTURE)
        if change:
            change(upstream)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        shutil.copytree(ROOT / 'packages/python', root / 'packages/python',
                        ignore=shutil.ignore_patterns('__pycache__'))
        pkg = packages.Package('python', root=root)
        pkg.inputs.mkdir(parents=True)
        (pkg.inputs / 'upstream.yaml').write_text(yaml.safe_dump(upstream))
        (pkg.inputs / 'upstream.lock.json').write_text(json.dumps(dict(LOCK, **(lock or {}))))
        return pkg, upstream, derive.derive(pkg)

    def names(self, derived):
        return [s.get('name') or s.get('uses') for s in derived['pipeline']]

    def test_wolfi_names_and_a_version_above_every_wolfi_rebuild(self):
        pkg, _, derived = self.derived()
        self.assertEqual('python-3.15', derived['package']['name'])
        self.assertEqual(1000, derived['package']['epoch'])
        self.assertEqual('3.15.0_git20261010-r1000', pkg.hooks.full_version(LOCK))
        self.assertEqual([s['name'] for s in FIXTURE['subpackages']], [s['name'] for s in derived['subpackages']])
        for section in [derived['package']] + derived['subpackages']:
            self.assertIn('wolfi-origin:python-3.15:3.15.0_git20261010-r0', section['dependencies']['provides'])

    def test_the_locked_commit_is_fetched_in_place_of_wolfis_checkout(self):
        _, _, derived = self.derived()
        self.assertEqual('Fetch the locked source commit', derived['pipeline'][0]['name'])
        self.assertIn(COMMIT, derived['pipeline'][0]['runs'])
        self.assertFalse([s for s in derived['pipeline'] if s.get('uses') == 'git-checkout'])

    def test_our_patches_follow_wolfis_and_reach_the_free_threaded_and_jit_builds(self):
        _, _, derived = self.derived()
        names = self.names(derived)
        ours = names.index('Apply Werewolf policy patches')
        self.assertEqual('patch', derived['pipeline'][ours - 1]['uses'])
        self.assertLess(ours, names.index('Clone patched source for no-GIL and JIT builds'))
        self.assertLess(names.index('Allow ctypes and the environment in the build guest only'),
                        names.index('autoconf/configure'))

    def test_loadable_sqlite_extensions_alone_leave_the_configure_options(self):
        _, upstream, derived = self.derived()
        before = upstream['vars']['python-config'].splitlines()
        after = derived['vars']['python-config'].splitlines()
        self.assertEqual([o for o in before if 'loadable-sqlite' not in o], after)
        self.assertEqual(len(before) - 1, len(after))

    def test_the_probe_runs_in_the_package_test(self):
        _, _, derived = self.derived()
        self.assertIn('sh /tmp/probe/probe.sh /tmp/probe/probe.py', derived['test']['pipeline'][-1]['runs'])
        self.assertEqual({'enabled': False}, derived['update'])

    def test_verify_accepts_the_derivation_of_wolfis_recipe(self):
        pkg, upstream, derived = self.derived()
        verify.check(pkg, upstream, derived)

    def test_changed_recipes_stop_the_derivation_for_review(self):
        def repository(recipe):
            recipe['pipeline'][0]['with']['repository'] = 'https://example.com/cpython'

        def option(recipe):
            recipe['vars']['python-config'] = recipe['vars']['python-config'].replace(
                '--enable-loadable-sqlite-extensions \\\n', '')

        def clone(recipe):
            recipe['pipeline'] = [s for s in recipe['pipeline']
                                  if s.get('name') != 'Clone patched source for no-GIL and JIT builds']

        def late_patch(recipe):
            patch = next(s for s in recipe['pipeline'] if s.get('uses') == 'patch')
            recipe['pipeline'].append(copy.deepcopy(patch))

        def name(recipe):
            recipe['package']['name'] = 'python-3.16'

        def second_checkout(recipe):
            recipe['pipeline'].insert(1, copy.deepcopy(recipe['pipeline'][0]))

        for change in [repository, option, clone, late_patch, name, second_checkout]:
            with self.subTest(change.__name__), self.assertRaisesRegex(ValueError, 'Review'):
                self.derived(change)

    def test_a_source_pin_other_than_the_lock_is_refused(self):
        with self.assertRaises(AssertionError):
            self.derived(lock={'source_commit': '0' * 40})

    def test_verify_refuses_a_relaxed_derivation(self):
        pkg, upstream, derived = self.derived()
        for relax in [
            lambda d: d['pipeline'].remove(next(s for s in d['pipeline'] if s.get('uses') == 'patch')),
            lambda d: d['environment']['contents']['packages'].remove('build-base'),
            lambda d: d['test']['pipeline'].pop(0),
            lambda d: d['subpackages'][0]['pipeline'].pop(),
            lambda d: d['vars'].update({'python-config': d['vars']['python-config'] + '--enable-loadable-sqlite-extensions \\\n'}),
            lambda d: d.update(update={'enabled': True}),
        ]:
            relaxed = copy.deepcopy(derived)
            relax(relaxed)
            with self.subTest(relax=relax), self.assertRaises(AssertionError):
                verify.check(pkg, upstream, relaxed)

    def test_epoch_moves_with_wolfi_and_with_the_policy_never_colliding(self):
        pkg, _, _ = self.derived()
        seen = {pkg.hooks.epoch(e, r) for e in range(0, 50) for r in range(1, 20)}
        self.assertEqual(50 * 19, len(seen))
        with self.assertRaises(ValueError):
            pkg.hooks.epoch(1000, 1)

    def test_the_probe_cannot_end_its_heredoc_early_or_use_melange_variables(self):
        pkg, _, _ = self.derived()
        for text in ['${{package.name}}', pkg.hooks.PROBE_PY, pkg.hooks.PROBE_SH]:
            (pkg.dir / 'tests/probe.sh').write_text('echo ' + text + '\n')
            with self.subTest(text=text), self.assertRaises(ValueError):
                pkg.hooks.probe(pkg)


if __name__ == '__main__':
    unittest.main()
