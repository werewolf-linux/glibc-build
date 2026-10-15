#!/usr/bin/env python3
"""Derive a build context from the unchanged, pinned Wolfi recipe."""
import copy
import json
from pathlib import Path
import shlex
import shutil
import yaml

ROOT = Path(__file__).resolve().parents[1]
REMOVED = {'nscd', 'nss-db', 'nss-hesiod', 'sotruss', 'pcprofiledump', 'glibc-tracing'}
APK_TEST_ADAPTER = '''mv /usr/bin/apk /usr/bin/apk.real
for app in info add del version update; do ln -s apk.real "/usr/bin/apk_$app"; done
cat > /usr/bin/apk <<'NEUTERED_APK'
#!/bin/sh
case "$1" in
  info|add|del|version|update) app=$1; shift; exec "/usr/bin/apk_$app" "$@" ;;
  *) exec /usr/bin/apk.real "$@" ;;
esac
NEUTERED_APK
chmod 755 /usr/bin/apk
test "$(apk version -t 0-r0 1-r0)" = '<'
if test -n '${{vars.neutered-test-repository}}'; then
  printf '%s\\n' '${{vars.neutered-test-repository}}' 'https://packages.wolfi.dev/os' > /etc/apk/repositories
  apk update
fi
'''

def derive():
    config = yaml.safe_load((ROOT / 'build/inputs/upstream.yaml').read_text())
    lock = json.loads((ROOT / 'build/inputs/upstream.lock.json').read_text())
    policy = json.loads((ROOT / 'policy.json').read_text())
    assert config['vars']['glibc-expected-commit'] == lock['glibc_commit']
    original = config['package']['name']
    config['package']['name'] = original.replace('glibc-', 'glibc-neutered-', 1)
    wolfi = f"{config['package']['version']}-r{config['package']['epoch']}"
    config['package']['epoch'] += lock['revision']
    config['package']['description'] += ' (Werewolf fixed hardening policy)'
    deps = config['package']['dependencies']
    # glibc-neutered names whichever stream is newest, so a consumer can
    # require this policy without naming a glibc version.
    deps['provides'] += [original + '=${{package.full-version}}', 'glibc-neutered=${{package.full-version}}']
    deps['replaces'] = [original]
    deps['provider-priority'] = '${{vars.neutered-priority}}'
    # Above every Wolfi stream (2.44 -> 244), and a newer stream above an
    # older one (2.44 -> 10244), as Wolfi's own provider-priority orders them.
    config['var-transforms'].append({'from': '${{package.version}}', 'match': '([0-9])[.]([0-9]+)',
                                     'replace': '10$1$2', 'to': 'neutered-priority'})
    config['vars']['neutered-test-repository'] = ''
    old_loader = 'ld-linux-${{package.version}}'
    loader = 'ld-linux-neutered-${{package.version}}'
    deps['runtime'] = [x.replace(old_loader, loader) for x in deps['runtime']]
    deps['runtime'].append('${{package.name}}-nss-config=${{package.full-version}}')
    pipeline = config['pipeline']
    assert pipeline[0]['uses'] == 'git-checkout'
    assert pipeline[1]['uses'] == 'patch'
    if pipeline[0]['with'] != {
            'expected-commit': '${{vars.glibc-expected-commit}}',
            'repository': 'https://sourceware.org/git/glibc.git',
            'branch': 'release/${{package.version}}/master'}:
        raise ValueError('Review changed upstream source checkout before deriving')
    pipeline[0] = {'name': 'Fetch the locked glibc commit',
                   'needs': {'packages': ['git']},
                   'runs': 'python3 neutered-source.py . "${{vars.glibc-expected-commit}}"\n'}
    # git apply refuses fuzzy context matching; verify each hunk before applying.
    pipeline.insert(2, {'name': 'Apply Werewolf policy patches', 'runs':
        'while IFS= read -r patch; do\n'
        '  git apply --check "patches/$patch"\n'
        '  git apply "patches/$patch"\n'
        'done < patches/series\n'})
    configure = next(x for x in pipeline if x.get('name') == 'Configure glibc')
    assert configure['runs'].count('--disable-werror') == 1
    continuation = ' ' + chr(92) + '\n        '
    configure['runs'] = configure['runs'].replace('--disable-werror', continuation.join([
        '--disable-build-nscd', '--disable-nscd', '--enable-hardcoded-path-in-tests', '--disable-werror']))
    # Test executables carry the build interpreter/RPATH. Build utilities run
    # with the build host's installed libc, never a permissive policy build.
    # Makeconfig assigns rtld-prefix after reading configparms. An override
    # also survives Wolfi's second pass rebuilding configparms from its base.
    configure['runs'] += '\n' + "echo 'override rtld-prefix =' >> configparms.base\n" + \
        "echo 'override rtld-prefix =' >> configparms\n"
    configure['runs'] += "echo 'include $(common-objpfx)../tests/harness.mk' >> configparms.base\n" + \
        "echo 'include $(common-objpfx)../tests/harness.mk' >> configparms\n"
    test = next(x for x in pipeline if x.get('name') == 'Run the glibc testsuite')
    assert 'make -C build' in test['runs']
    # Retain Wolfi's full suite and its gates; hardcoded test paths avoid a
    # --library-path exception. Runtime programs never gain such an exception.
    index = pipeline.index(test)
    pipeline.insert(index, {'name': 'Install explicit locale test fixtures', 'runs':
        'python3 tests/prepare-locales.py --build build\n'})
    pipeline.insert(index, {'name': 'Configure built-in NSS providers for validation', 'runs':
        'cp profile/nsswitch.conf /etc/nsswitch.conf\n'})
    index = pipeline.index(test)
    pipeline.insert(index, {'name': 'Verify fixed hardening policy', 'runs':
        'case "${{build.arch}}" in\n'
        '  aarch64) baseline=/lib/ld-linux-aarch64.so.1 ;;\n'
        '  x86_64) baseline=/lib64/ld-linux-x86-64.so.2 ;;\n'
        '  *) exit 1 ;;\n'
        'esac\n'
        'python3 tests/run.py --build build --cc gcc --baseline-loader "$baseline" --report build/policy-report.json\n'})
    pipeline.insert(index, {'uses': 'test/compiler/hardening-check', 'with': {'cc': 'gcc'}})
    index = next(i for i, x in enumerate(pipeline) if x.get('uses') == 'strip')
    removal = {'name': 'Remove unsupported runtime facilities', 'runs':
        'rm -rf "${{targets.destdir}}/usr/lib/gconv"\n'
        'rm -f "${{targets.destdir}}/usr/bin/iconvconfig" '
        '"${{targets.destdir}}/usr/bin/sotruss" '
        '"${{targets.destdir}}/usr/bin/pcprofiledump"\n'
        'rm -f "${{targets.destdir}}"/usr/lib/libnss_db.so* "${{targets.destdir}}"/usr/lib/libnss_hesiod.so* '
        '"${{targets.destdir}}"/usr/lib/libpcprofile.so* "${{targets.destdir}}"/usr/lib/libmemusage.so* "${{targets.destdir}}"/usr/lib/libsotruss.so* "${{targets.destdir}}"/usr/lib/libc_malloc_debug.so*\n'}
    pipeline.insert(index, removal)
    kept = []
    for sub in config['subpackages']:
        name = sub['name'].replace('${{package.name}}', 'glibc')
        base = name.split('-${{package.version}}')[0]
        if base in REMOVED:
            # Its files would stay in the main package: xtrace alone needs bash.
            for step in sub['pipeline']:
                for line in step['runs'].splitlines():
                    words = shlex.split(line)
                    if not words or words[0] == 'mkdir':
                        continue
                    if words[0] != 'mv':
                        raise ValueError('Review changed upstream ' + base + ' packaging before deriving')
                    for source in words[1:-1]:
                        path = source.removeprefix('${{targets.destdir}}/')
                        if path == source or '..' in path.split('/'):
                            raise ValueError('Review changed upstream ' + base + ' packaging before deriving')
                        removal['runs'] += 'rm -rf "${{targets.destdir}}"/' + path + '\n'
            continue
        if '${{package.name}}' in sub['name']:
            original_name = sub['name'].replace('${{package.name}}', original)
            subdeps = sub.setdefault('dependencies', {})
            subdeps.setdefault('provides', []).append(original_name+'=${{package.full-version}}')
            subdeps.setdefault('replaces', []).append(original_name)
            subdeps['provider-priority'] = '${{vars.neutered-priority}}'
            subdeps['runtime'] = [
                '${{package.name}}=${{package.full-version}}' if x.startswith('glibc>=') else x
                for x in subdeps.get('runtime', [])]
        if sub['name'] == old_loader:
            sub['name'] = loader
            sub['dependencies']['provides'].append(old_loader + '=${{package.full-version}}')
            sub['dependencies']['replaces'] = [old_loader]
            sub['dependencies']['provider-priority'] = '${{vars.neutered-priority}}'
        if sub['name'] == '${{package.name}}-iconv':
            sub['description'] = 'Built-in iconv command; external converters disabled'
            sub['pipeline'] = [{'runs': 'mkdir -p "${{targets.subpkgdir}}/usr/bin"\n'
                'mv "${{targets.destdir}}/usr/bin/iconv" "${{targets.subpkgdir}}/usr/bin/"\n'}]
            # iconvconfig is intentionally absent; keep CLI and refusal checks.
            sub['test']['pipeline'] = [copy.deepcopy(x) for x in sub['test']['pipeline']]
            for x in sub['test']['pipeline']:
                if x.get('with', {}).get('bins'):
                    x['with']['bins'] = 'iconv\n'
        if sub['name'] == '${{package.name}}-testresults':
            sub['pipeline'].append({'runs': 'cp build/policy-report.json "${{targets.subpkgdir}}/usr/share/glibc-testresults/policy-report.json"\n'})
            gate = next(x for x in sub['test']['pipeline'] if x.get('name') == 'Verify PASS/FAIL ratio in test result files is within acceptable threshold')
            assert gate['runs'].count('MAX_FAIL_RATIO=0.02') == 1
            gate['runs'] = gate['runs'].replace('MAX_FAIL_RATIO=0.02',
                'MAX_FAIL_RATIO=' + format(policy['max_fail_per_mille'] / 1000, '.3f'))
        if sub['name'] == 'posix-libc-utils-${{package.version}}':
            sub['test']['environment'] = {'contents': {'packages': ['build-base', '${{package.name}}-dev']}}
            sub['test']['pipeline'].append({'name': 'ldd lists dependencies without executing target code', 'runs':
                "cat > ldd-probe.c <<'NEUTERED_LDD'\n"
                '#include <fcntl.h>\n#include <unistd.h>\n'
                'static void mark(void) { int fd = open("ldd-executed", O_WRONLY|O_CREAT, 0600); if (fd >= 0) close(fd); }\n'
                '__attribute__((constructor)) static void init(void) { mark(); }\n'
                'int main(void) { mark(); return 0; }\n'
                'NEUTERED_LDD\n'
                'gcc ldd-probe.c -o ldd-probe\n'
                './ldd-probe\n'
                'test -f ldd-executed\nrm ldd-executed\n'
                'ldd ./ldd-probe > ldd-list\n'
                'grep "libc.so.6" ldd-list\ntest ! -e ldd-executed\n'
                'for option in -d -r -u -v; do\n'
                '  if ldd "$option" ./ldd-probe; then exit 1; fi\n'
                '  test ! -e ldd-executed\ndone\n'})
        kept.append(sub)
    config['subpackages'] = kept
    config['subpackages'].append({
        'name': '${{package.name}}-nss-config',
        'description': 'Fixed files/DNS account and host configuration',
        'dependencies': {'replaces': ['wolfi-baselayout'], 'runtime': ['${{package.name}}=${{package.full-version}}']},
        'pipeline': [{'runs': 'install -Dm644 profile/nsswitch.conf "${{targets.subpkgdir}}/etc/nsswitch.conf"\n'}],
        'test': {'pipeline': [{'runs': "cmp /etc/nsswitch.conf - <<'NEUTERED_NSS'\n" +
            (ROOT/'profile/nsswitch.conf').read_text()+'NEUTERED_NSS\n'}]}})
    # Each package names the Wolfi source and version it rebuilds, unversioned
    # so that all may: Werewolf matches Wolfi's CVE fixes against it, not ours.
    for section in [config['package']] + config['subpackages']:
        section.setdefault('dependencies', {}).setdefault('provides', []).append(
            'wolfi-origin:' + original + ':' + wolfi)
    # Keep the original ratio and assertions; find must use explicit commands.
    for section in [config] + config['subpackages']:
        tests = section.get('test', {}).get('pipeline', [])
        if tests:
            tests.insert(0, {'name': 'Adapt apk test tooling to strict option ordering', 'runs': APK_TEST_ADAPTER})
        for step in tests:
            if 'runs' in step:
                step['runs'] = step['runs'].replace('-exec grep ', '-exec /usr/bin/grep ')
    # Preserve the solver test for every remaining virtual package.
    for x in config['test']['pipeline']:
        if x.get('name') == 'Verify version-streamed virtuals do not resolve to an older package':
            lines = x['runs'].splitlines()
            x['runs'] = '\n'.join(s for s in lines if s.strip() not in REMOVED) + '\n'
    config['update'] = {'enabled': False}
    return config

def main():
    context = ROOT / 'build/context'
    if context.exists():
        shutil.rmtree(context)
    shutil.copytree(ROOT / 'build/inputs/upstream', context)
    for path in ['patches', 'tests', 'profile']:
        shutil.copytree(ROOT / path, context / path, dirs_exist_ok=True)
    shutil.copyfile(ROOT / 'scripts/source.py', context / 'neutered-source.py')
    recipe = ROOT / 'build/glibc.yaml'
    recipe.write_text(yaml.safe_dump(derive(), sort_keys=False, width=120))
    print(recipe)

if __name__ == '__main__':
    main()
