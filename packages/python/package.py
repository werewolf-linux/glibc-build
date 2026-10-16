"""Python: Wolfi's newest stable CPython, with three policy patches (README.md).

The hooks scripts/packages.py names. Packages keep Wolfi's names; their epoch
sorts above every Wolfi rebuild of the same CPython snapshot."""
from pathlib import Path
import re
import shutil
from derive import fetch
import patching

TITLE = 'Python'
FAMILY = 'python-'
SOURCES = ('https://github.com/python/cpython.git',)
UPSTREAM = 'https://github.com/python/cpython'
PATCHES = 'werewolf/patches'  # in the build context
# The configure option this build leaves out: sqlite3 loading native code.
REMOVED_OPTION = '--enable-loadable-sqlite-extensions'
CLONE = 'Clone patched source for no-GIL and JIT builds'
ALLOW = 'Allow ctypes and the environment in the build guest only'
PROBE_PY, PROBE_SH = 'WEREWOLF_PROBE_PY', 'WEREWOLF_PROBE_SH'

def checkout(config):
    """The index of the recipe's one git-checkout step."""
    found = [i for i, step in enumerate(config['pipeline']) if step.get('uses') == 'git-checkout']
    if len(found) != 1:
        raise ValueError('Review changed upstream source checkout before deriving')
    return found[0]

def source_commit(config):
    found = [s for s in config['pipeline'] if s.get('uses') == 'git-checkout']
    return found[0].get('with', {}).get('expected-commit') if len(found) == 1 else None

def epoch(wolfi_epoch, revision):
    """Our epoch: above every Wolfi rebuild of the same snapshot, so apk
    prefers ours, and moving when either Wolfi's epoch or our revision does."""
    if not 0 <= wolfi_epoch < 1000:
        raise ValueError('Review Wolfi epoch ' + str(wolfi_epoch) + ': ours would no longer sort above it')
    return 1000 * revision + wolfi_epoch

def full_version(lock):
    return lock['version'] + '-r' + str(epoch(lock['epoch'], lock['revision']))

def context(pkg, destination):
    # Beside Wolfi's files, under a name CPython does not use at its top.
    shutil.copytree(pkg.dir / 'patches', destination / PATCHES)

def probe(pkg):
    py = (pkg.dir / 'tests/probe.py').read_text()
    sh = (pkg.dir / 'tests/probe.sh').read_text()
    for text in (py, sh):
        if '${{' in text or PROBE_PY in text or PROBE_SH in text:
            raise ValueError('tests/probe.* cannot be embedded in a Melange recipe')
    return ("mkdir -p /tmp/probe\n"
            "cat > /tmp/probe/probe.py <<'" + PROBE_PY + "'\n" + py + PROBE_PY + '\n' +
            "cat > /tmp/probe/probe.sh <<'" + PROBE_SH + "'\n" + sh + PROBE_SH + '\n' +
            'sh /tmp/probe/probe.sh /tmp/probe/probe.py\n')

def derive(pkg, config, lock):
    original = config['package']['name']
    if original != Path(lock['recipe']).stem or str(config['package']['version']) != lock['version']:
        raise ValueError('Review changed upstream package identity before deriving')
    pipeline = config['pipeline']
    at = checkout(config)
    source = pipeline[at].get('with', {})
    assert source.get('expected-commit') == lock['source_commit'], 'source pin differs from the lock'
    if source.get('repository') != UPSTREAM or set(source) - {'branch', 'tag', 'expected-commit', 'repository'}:
        raise ValueError('Review changed upstream source checkout before deriving')
    pipeline[at] = fetch(lock['source_commit'], pkg.sources(lock))
    # Wolfi's patches first, as Wolfi applies them; then ours, before the
    # free-threaded and JIT builds copy the patched tree.
    patched = [i for i, step in enumerate(pipeline) if step.get('uses') == 'patch']
    clones = [i for i, step in enumerate(pipeline) if step.get('name') == CLONE]
    configures = [i for i, step in enumerate(pipeline) if step.get('uses') == 'autoconf/configure']
    if not patched or len(clones) != 1 or not configures or not patched[-1] < clones[0] < configures[0]:
        raise ValueError('Review changed upstream patch and clone steps before deriving')
    # The build imports every extension it built, and drops one that refuses
    # to load (Tools/build/check_extension_modules.py); its PGO run's tests set
    # PYTHON* variables for the interpreters they start. So the build guest,
    # and only it, allows ctypes and the environment. Packages hold nothing
    # under /etc/werewolf, and werewolf's forms cannot allow the environment.
    pipeline[patched[-1] + 1:patched[-1] + 1] = [
        patching.step(PATCHES),
        {'name': ALLOW, 'runs': 'mkdir -p /etc/werewolf/allow/python\n'
                                ': > /etc/werewolf/allow/python/ctypes\n'
                                ': > /etc/werewolf/allow/python/environment\n'}]
    options = config['vars']['python-config']
    line = re.compile(r'^[ \t]*' + re.escape(REMOVED_OPTION) + r'[ \t]*\\\n', re.M)
    config['vars']['python-config'], count = line.subn('', options)
    if count != 1:
        raise ValueError('Review changed upstream configure option ' + REMOVED_OPTION + ' before deriving')
    wolfi = str(config['package']['version']) + '-r' + str(config['package']['epoch'])
    config['package']['epoch'] = epoch(config['package']['epoch'], lock['revision'])
    config['package']['description'] += ' (Werewolf fixed hardening policy)'
    # Each package names the Wolfi build it rebuilds: werewolf matches Wolfi's
    # CVE fixes against that (lib/prebuilt.zig), not against our epoch.
    for section in [config['package']] + config['subpackages']:
        section.setdefault('dependencies', {}).setdefault('provides', []).append(
            'wolfi-origin:' + original + ':' + wolfi)
    config['test']['pipeline'].append({'name': 'Werewolf protections hold, and allowances take each back',
                                       'runs': probe(pkg)})
    config['update'] = {'enabled': False}
    return config

def check(pkg, upstream, derived):
    """Raise AssertionError unless derived keeps everything Wolfi builds with."""
    options = lambda c: c['vars']['python-config'].splitlines()
    kept = [o for o in options(upstream) if REMOVED_OPTION not in o]
    assert options(derived) == kept, 'upstream configure options changed beyond the removed one'
    assert not [o for o in options(derived) if REMOVED_OPTION in o], 'loadable sqlite extensions still configured'
    assert derived['environment'] == upstream['environment'], 'upstream build environment changed'
    patches = lambda c: [x for x in c['pipeline'] if x.get('uses') == 'patch']
    assert patches(upstream) == patches(derived), "Wolfi's patches changed"
    names = [x.get('name') for x in derived['pipeline']]
    ours = names.index('Apply Werewolf policy patches')
    assert derived['pipeline'][ours - 1] == patches(upstream)[-1], "our patches must follow Wolfi's"
    assert ours < names.index(CLONE), 'the free-threaded and JIT builds must copy the patched tree'
    ours_only = ('Apply Werewolf policy patches', ALLOW, 'Fetch the locked source commit')
    steps = lambda c: [x for x in c['pipeline'] if x.get('name') not in ours_only and x.get('uses') != 'git-checkout']
    assert steps(upstream) == steps(derived), 'an upstream build step changed'
    strip = lambda subs: [{**s, 'dependencies': {**s.get('dependencies', {}), 'provides': [
        p for p in s.get('dependencies', {}).get('provides', []) if not p.startswith('wolfi-origin:')]}}
        for s in subs]
    assert strip(upstream['subpackages']) == strip(derived['subpackages']), 'an upstream subpackage changed'
    for test in upstream['test']['pipeline']:
        assert test in derived['test']['pipeline'], "Wolfi's package test removed"
