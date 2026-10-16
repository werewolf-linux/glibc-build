"""PHP: Wolfi's newest stable PHP, with seven policy patches (README.md).

The hooks scripts/packages.py names. Packages keep Wolfi's names; their epoch
sorts above every Wolfi rebuild of the same PHP release."""
from pathlib import Path
import re
import shutil
from derive import fetch
import patching

TITLE = 'PHP'
FAMILY = 'php-'
SOURCES = ('https://github.com/php/php-src.git',)
UPSTREAM = 'https://github.com/php/php-src'
PATCHES = 'werewolf/patches'  # in the build context
# What the build leaves out, and the configure flag that builds each.
REMOVED = {'${{package.name}}-dbg': '--enable-phpdbg=shared',  # phpdbg, an interactive debugger
           '${{package.name}}-pear': '--with-pear'}  # PEAR, which installs code from the network
# The package test loads these, so the probe sees their functions and wrapper held.
PROBE_PACKAGES = ['${{package.name}}-pcntl', '${{package.name}}-phar']
PROBE_PHP, PROBE_SH = 'WEREWOLF_PROBE_PHP', 'WEREWOLF_PROBE_SH'
# Capability groups granted in every test environment so Wolfi's own tests
# (and the subpackages') run `php`, scripts and unserialize; the probe clears
# them and proves deny-by-default. PHP has no `environment` group.
GROUPS = ['exec', 'native', 'deserialize', 'phar', 'inline', 'writable-source']

def grant_all():
    return ('mkdir -p /etc/runtime-hardening/allow/all/php\n'
            'for f in ' + ' '.join(GROUPS) + '; do\n'
            '  : > /etc/runtime-hardening/allow/all/php/$f\n'
            'done\n')

def source_commit(config):
    source = config['pipeline'][0]
    return source.get('with', {}).get('expected-commit') if source.get('uses') == 'git-checkout' else None

def epoch(wolfi_epoch, revision):
    """Our epoch: above every Wolfi rebuild of the same PHP release, so apk
    prefers ours, and moving when either Wolfi's epoch or our revision does."""
    if not 0 <= wolfi_epoch < 1000:
        raise ValueError('Review Wolfi epoch ' + str(wolfi_epoch) + ': ours would no longer sort above it')
    return 1000 * revision + wolfi_epoch

def full_version(lock):
    return lock['version'] + '-r' + str(epoch(lock['epoch'], lock['revision']))

def context(pkg, destination):
    # Beside Wolfi's files, under a name php-src does not use at its top.
    shutil.copytree(pkg.dir / 'patches', destination / PATCHES)

def probe(pkg):
    php = (pkg.dir / 'tests/probe.php').read_text()
    sh = (pkg.dir / 'tests/probe.sh').read_text()
    for text in (php, sh):
        if '${{' in text or PROBE_PHP in text or PROBE_SH in text:
            raise ValueError('tests/probe.* cannot be embedded in a Melange recipe')
    return ("cat > /tmp/probe.php <<'" + PROBE_PHP + "'\n" + php + PROBE_PHP + '\n' +
            "cat > /tmp/probe.sh <<'" + PROBE_SH + "'\n" + sh + PROBE_SH + '\n' +
            'sh /tmp/probe.sh /tmp/probe.php\n')

def derive(pkg, config, lock):
    original = config['package']['name']
    if original != Path(lock['recipe']).stem or str(config['package']['version']) != lock['version']:
        raise ValueError('Review changed upstream package identity before deriving')
    pipeline = config['pipeline']
    source = pipeline[0]
    assert source_commit(config) == lock['source_commit'], 'source pin differs from the lock'
    if source != {'uses': 'git-checkout', 'with': {'repository': UPSTREAM, 'tag': 'php-${{package.version}}',
                                                   'expected-commit': lock['source_commit']}}:
        raise ValueError('Review changed upstream source checkout before deriving')
    pipeline[0] = fetch(lock['source_commit'], SOURCES)
    # Wolfi's patches first, as Wolfi applies them; then ours.
    patched = [i for i, step in enumerate(pipeline) if step.get('uses') == 'patch']
    if not patched or patched != list(range(1, patched[-1] + 1)):
        raise ValueError('Review changed upstream patch steps before deriving')
    pipeline.insert(patched[-1] + 1, patching.step(PATCHES))
    # The build runs the new php on build-tree scripts (phar.phar), so the build
    # guest grants every group; packages hold nothing under /etc/runtime-hardening.
    pipeline.insert(patched[-1] + 2, {'name': 'Allow every group in the build guest', 'runs': grant_all()})
    configure = [step for step in pipeline if step.get('name') == 'Configure']
    if len(configure) != 1:
        raise ValueError('Review changed upstream configure step before deriving')
    for flag in REMOVED.values():
        line = re.compile(r'^[ \t]*' + re.escape(flag) + r'[ \t]*\\\n', re.M)
        configure[0]['runs'], count = line.subn('', configure[0]['runs'])
        if count != 1:
            raise ValueError('Review changed upstream configure flag ' + flag + ' before deriving')
    wolfi = str(config['package']['version']) + '-r' + str(config['package']['epoch'])
    config['package']['epoch'] = epoch(config['package']['epoch'], lock['revision'])
    config['package']['description'] += ' (Werewolf fixed hardening policy)'
    if not set(REMOVED) <= {sub['name'] for sub in config['subpackages']}:
        raise ValueError('Review changed upstream subpackages before deriving')
    kept = [sub for sub in config['subpackages'] if sub['name'] not in REMOVED]
    for sub in kept:
        if any(name in REMOVED for name in sub.get('dependencies', {}).get('runtime', [])):
            raise ValueError('Review ' + sub['name'] + ': it depends on a package this build leaves out')
    config['subpackages'] = kept
    # Each package names the Wolfi build it rebuilds: werewolf matches Wolfi's
    # CVE fixes against that (lib/prebuilt.zig), not against our epoch.
    for section in [config['package']] + kept:
        section.setdefault('dependencies', {}).setdefault('provides', []).append(
            'wolfi-origin:' + original + ':' + wolfi)
    test = config['test']
    test.setdefault('environment', {}).setdefault('contents', {}).setdefault('packages', []).extend(PROBE_PACKAGES)
    test['pipeline'].append({'name': 'Werewolf protections hold, and allowances take each back',
                             'runs': probe(pkg)})
    config['update'] = {'enabled': False}
    return config

def test_recipe(config, repository):
    # Grant every group in every test environment (main and subpackages) so
    # Wolfi's own tests run; the probe (in the main test) clears them and proves
    # deny-by-default. Done only when tests run, not in the derived recipe.
    grant = {'name': 'Grant every group for the suite (the probe clears them)', 'runs': grant_all()}
    for section in [config] + config.get('subpackages', []):
        test = section.get('test')
        if test and test.get('pipeline'):
            test['pipeline'].insert(0, dict(grant))
    return config

FLAG = re.compile(r'--[a-zA-Z0-9_-]+(?:=[^\s\\]+)?')

def check(pkg, upstream, derived):
    """Raise AssertionError unless derived keeps everything Wolfi builds with."""
    configure = lambda c: next(x['runs'] for x in c['pipeline'] if x.get('name') == 'Configure')
    removed = set(REMOVED.values())
    kept = set(FLAG.findall(configure(upstream))) - removed
    assert kept <= set(FLAG.findall(configure(derived))), 'upstream configure flags removed'
    assert not removed & set(FLAG.findall(configure(derived))), 'a removed facility is still configured'
    assert derived['environment'] == upstream['environment'], 'upstream build environment changed'
    patches = lambda c: [x for x in c['pipeline'] if x.get('uses') == 'patch']
    assert patches(upstream) == patches(derived), "Wolfi's patches changed"
    ours = next(i for i, x in enumerate(derived['pipeline']) if x.get('name') == 'Apply Werewolf policy patches')
    assert derived['pipeline'][ours - 1] == patches(upstream)[-1], "our patches must follow Wolfi's"
    # Configure loses only the removed flags, which the checks above hold.
    steps = lambda c: [x for x in c['pipeline'][1:]
                       if x.get('name') not in ('Apply Werewolf policy patches', 'Configure', 'Allow every group in the build guest')]
    assert steps(upstream) == steps(derived), 'an upstream build step changed'
    for test in upstream['test']['pipeline']:
        assert test in derived['test']['pipeline'], "Wolfi's package test removed"
