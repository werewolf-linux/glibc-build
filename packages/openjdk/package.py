"""OpenJDK: Wolfi's newest stable OpenJDK, with six policy patches (README.md).

The hooks scripts/packages.py names. Packages keep Wolfi's names; their epoch
sorts above every Wolfi rebuild of the same JDK release."""
from pathlib import Path
import re
import shutil
from derive import fetch
import patching

TITLE = 'OpenJDK'
FAMILY = 'openjdk-'
PATCHES = 'werewolf/patches'  # in the build context
REPOSITORY = 'https://github.com/openjdk/jdk${{vars.java-version}}u'
UPSTREAM = 'https://github.com/openjdk/jdk'
PROBE_JAVA, PROBE_SH = 'WEREWOLF_PROBE_JAVA', 'WEREWOLF_PROBE_SH'

def checkout(config):
    """Wolfi's one git-checkout step: its index and the step."""
    found = [(i, step) for i, step in enumerate(config['pipeline']) if step.get('uses') == 'git-checkout']
    if len(found) != 1:
        raise ValueError('Review changed upstream source checkout before deriving')
    return found[0]

def source_commit(config):
    try:
        return checkout(config)[1].get('with', {}).get('expected-commit')
    except ValueError:
        return None

def sources(lock):
    """The update repository of the locked release, then mainline, which holds each GA."""
    feature = lock['version'].split('.')[0]
    if not re.fullmatch('[0-9]+', feature):
        raise ValueError('Review OpenJDK version ' + lock['version'])
    return ('https://github.com/openjdk/jdk' + feature + 'u.git', UPSTREAM + '.git')

def epoch(wolfi_epoch, revision):
    """Our epoch: above every Wolfi rebuild of the same JDK release, so apk
    prefers ours, and moving when either Wolfi's epoch or our revision does."""
    if not 0 <= wolfi_epoch < 1000:
        raise ValueError('Review Wolfi epoch ' + str(wolfi_epoch) + ': ours would no longer sort above it')
    return 1000 * revision + wolfi_epoch

def full_version(lock):
    return lock['version'] + '-r' + str(epoch(lock['epoch'], lock['revision']))

def context(pkg, destination):
    # Beside Wolfi's files, under a name the JDK's source does not use at its top.
    shutil.copytree(pkg.dir / 'patches', destination / PATCHES)

def probe(pkg):
    java = (pkg.dir / 'tests/Probe.java').read_text()
    sh = (pkg.dir / 'tests/probe.sh').read_text()
    for text in (java, sh):
        if '${{' in text or PROBE_JAVA in text or PROBE_SH in text:
            raise ValueError('tests/Probe.java and tests/probe.sh cannot be embedded in a Melange recipe')
    return ('work=$(mktemp -d)\n'
            "cat > \"$work/Probe.java\" <<'" + PROBE_JAVA + "'\n" + java + PROBE_JAVA + '\n' +
            "cat > \"$work/probe.sh\" <<'" + PROBE_SH + "'\n" + sh + PROBE_SH + '\n' +
            'sh "$work/probe.sh" "$work"\n')

def derive(pkg, config, lock):
    original = config['package']['name']
    if original != Path(lock['recipe']).stem or str(config['package']['version']) != lock['version']:
        raise ValueError('Review changed upstream package identity before deriving')
    pipeline = config['pipeline']
    index, source = checkout(config)
    assert source_commit(config) == lock['source_commit'], 'source pin differs from the lock'
    if set(source.get('with', {})) != {'repository', 'tag', 'expected-commit'} or \
            source['with']['repository'] != REPOSITORY:
        raise ValueError('Review changed upstream source checkout before deriving')
    pipeline[index] = fetch(lock['source_commit'], sources(lock))
    # Wolfi's patches first, as Wolfi applies them; then ours.
    patched = [i for i, step in enumerate(pipeline) if step.get('uses') == 'patch']
    if not patched or patched[0] < index:
        raise ValueError('Review changed upstream patch steps before deriving')
    pipeline.insert(patched[-1] + 1, patching.step(PATCHES))
    wolfi = str(config['package']['version']) + '-r' + str(config['package']['epoch'])
    config['package']['epoch'] = epoch(config['package']['epoch'], lock['revision'])
    config['package']['description'] += ' (Werewolf fixed hardening policy)'
    # Each package names the Wolfi build it rebuilds: werewolf matches Wolfi's
    # CVE fixes against that (lib/prebuilt.zig), not against our epoch.
    for section in [config['package']] + config['subpackages']:
        section.setdefault('dependencies', {}).setdefault('provides', []).append(
            'wolfi-origin:' + original + ':' + wolfi)
    test = config['test']
    if 'openjdk-${{vars.java-version}}-default-jdk' not in test.get('environment', {}).get('contents', {}).get('packages', []):
        raise ValueError('Review changed upstream package test environment: the probe needs the JDK')
    test['pipeline'].append({'name': 'Werewolf protections hold, and allowances take each back',
                             'runs': probe(pkg)})
    config['update'] = {'enabled': False}
    return config

def check(pkg, upstream, derived):
    """Raise AssertionError unless derived keeps everything Wolfi builds with."""
    configure = lambda c: [x for x in c['pipeline'] if x.get('uses') == 'autoconf/configure']
    assert configure(upstream) == configure(derived), 'upstream configure changed'
    assert derived['environment'] == upstream['environment'], 'upstream build environment changed'
    patches = lambda c: [x for x in c['pipeline'] if x.get('uses') == 'patch']
    assert patches(upstream) == patches(derived), "Wolfi's patches changed"
    ours = next(i for i, x in enumerate(derived['pipeline']) if x.get('name') == 'Apply Werewolf policy patches')
    assert derived['pipeline'][ours - 1] == patches(upstream)[-1], "our patches must follow Wolfi's"
    steps = lambda c: [x for x in c['pipeline']
                       if x.get('uses') != 'git-checkout'
                       and x.get('name') not in ('Apply Werewolf policy patches', 'Fetch the locked source commit')]
    assert steps(upstream) == steps(derived), 'an upstream build step changed'
    names = lambda c: [x['name'] for x in c['subpackages']]
    assert names(upstream) == names(derived), 'an upstream subpackage changed'
    for test in upstream['test']['pipeline']:
        assert test in derived['test']['pipeline'], "Wolfi's package test removed"
    assert upstream['test']['environment'] == derived['test']['environment'], 'upstream test environment changed'
