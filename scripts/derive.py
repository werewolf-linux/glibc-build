#!/usr/bin/env python3
"""Derive a build context from the unchanged, pinned Wolfi recipe."""
import copy
import json
from pathlib import Path
import shutil
import yaml

ROOT = Path(__file__).resolve().parents[1]
REMOVED = {'nscd', 'nss-db', 'nss-hesiod', 'sotruss', 'pcprofiledump', 'glibc-tracing'}

def derive():
    config = yaml.safe_load((ROOT / 'upstream.yaml').read_text())
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    assert config['vars']['glibc-expected-commit'] == lock['glibc_commit']
    original = config['package']['name']
    config['package']['name'] = original.replace('glibc-', 'glibc-neutered-', 1)
    config['package']['epoch'] += lock['revision']
    config['package']['description'] += ' (Werewolf fixed hardening policy)'
    deps = config['package']['dependencies']
    deps['provides'].append(original + '=${{package.full-version}}')
    deps['replaces'] = [original]
    deps['provider-priority'] = '${{vars.neutered-priority}}'
    config['vars']['neutered-priority'] = '10000'
    old_loader = 'ld-linux-${{package.version}}'
    loader = 'ld-linux-neutered-${{package.version}}'
    deps['runtime'] = [x.replace(old_loader, loader) for x in deps['runtime']]
    pipeline = config['pipeline']
    assert pipeline[0]['uses'] == 'git-checkout'
    assert pipeline[1]['uses'] == 'patch'
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
    test = next(x for x in pipeline if x.get('name') == 'Run the glibc testsuite')
    assert 'make -C build' in test['runs']
    # Retain Wolfi's full suite and its gates; hardcoded test paths avoid a
    # --library-path exception. Runtime programs never gain such an exception.
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
    pipeline.insert(index, {'name': 'Remove unsupported runtime facilities', 'runs':
        'rm -rf "${{targets.destdir}}/usr/lib/gconv"\n'
        'rm -f "${{targets.destdir}}/usr/bin/iconvconfig" '
        '"${{targets.destdir}}/usr/bin/sotruss" '
        '"${{targets.destdir}}/usr/bin/pcprofiledump"\n'
        'rm -f "${{targets.destdir}}"/usr/lib/libnss_db.so* "${{targets.destdir}}"/usr/lib/libnss_hesiod.so* '
        '"${{targets.destdir}}"/usr/lib/libpcprofile.so* "${{targets.destdir}}"/usr/lib/libmemusage.so* "${{targets.destdir}}"/usr/lib/libsotruss.so* "${{targets.destdir}}"/usr/lib/libc_malloc_debug.so*\n'})
    kept = []
    for sub in config['subpackages']:
        name = sub['name'].replace('${{package.name}}', 'glibc')
        base = name.split('-${{package.version}}')[0]
        if base in REMOVED:
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
        kept.append(sub)
    config['subpackages'] = kept
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
    shutil.copytree(ROOT / 'upstream', context)
    for path in ['patches', 'tests']:
        shutil.copytree(ROOT / path, context / path, dirs_exist_ok=True)
    recipe = ROOT / 'build/glibc.yaml'
    recipe.write_text(yaml.safe_dump(derive(), sort_keys=False, width=120))
    print(recipe)

if __name__ == '__main__':
    main()
