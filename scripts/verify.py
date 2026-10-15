#!/usr/bin/env python3
"""Verify provenance and that our derivation does not relax Wolfi hardening."""
import hashlib
import json
from pathlib import Path
import re
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from derive import derive, version
from inputs import verify, INPUTS

def main():
    lock = verify()
    assert re.fullmatch('[0-9a-f]{40}', lock['wolfi_commit'])
    assert re.fullmatch('[0-9a-f]{40}', lock['glibc_commit'])
    for name, digest in lock['sha256'].items():
        assert hashlib.sha256((INPUTS/name).read_bytes()).hexdigest() == digest, name
    upstream = yaml.safe_load((INPUTS/'upstream.yaml').read_text())
    derived = derive()
    assert 'git' in derived['pipeline'][0]['needs']['packages'], 'source fetch requires Git in the guest'
    configure = lambda c: next(x['runs'] for x in c['pipeline'] if x.get('name') == 'Configure glibc')
    flags = lambda s: set(re.findall(r'--[a-zA-Z0-9_-]+(?:=[^\s\\]+)?', s))
    kept = {f for f in flags(configure(upstream)) if not f.startswith('--enable-kernel=')}
    assert kept <= flags(configure(derived)), 'upstream configure flags removed'
    # The minimum kernel may only rise: it removes fallbacks, never protections.
    kernels = lambda s: [version(v) for v in re.findall(r'--enable-kernel=([0-9.]+)', s)]
    assert len(kernels(configure(derived))) == 1, 'one minimum kernel'
    assert kernels(configure(derived)) >= kernels(configure(upstream)), 'minimum kernel lowered'
    assert derived['environment'] == upstream['environment'], 'upstream compiler environment changed'
    packages = derived['environment']['contents']['packages']
    assert 'openssf-compiler-options' in packages and 'build-base' in packages
    for flag in ['--enable-bind-now', '--enable-fortify-source', '--enable-stackguard-randomization',
                 '--enable-stack-protector=strong', '--enable-cet']:
        assert flag in flags(configure(derived)), flag
    assert derived['environment']['environment']['CPPFLAGS'] == ''
    assert 'CFLAGS' not in derived['environment'].get('environment', {})
    assert 'LDFLAGS' not in derived['environment'].get('environment', {})
    original_patch = next(x for x in upstream['pipeline'] if x.get('uses') == 'patch')
    assert original_patch == next(x for x in derived['pipeline'] if x.get('uses') == 'patch')
    for name in ['Run the glibc testsuite', 'Generate public ABI report', 'Check libc public ABI against the previous report']:
        assert next(x for x in upstream['pipeline'] if x.get('name') == name) == next(x for x in derived['pipeline'] if x.get('name') == name), name
    policy = json.loads((ROOT/'policy.json').read_text())
    assert 0 <= policy['max_fail_per_mille'] <= 55
    gate_name = 'Verify PASS/FAIL ratio in test result files is within acceptable threshold'
    def gate(config):
        sub = next(x for x in config['subpackages'] if x['name'] == '${{package.name}}-testresults')
        return next(x['runs'] for x in sub['test']['pipeline'] if x.get('name') == gate_name)
    ceiling = format(policy['max_fail_per_mille'] / 1000, '.3f')
    assert gate(derived).replace('MAX_FAIL_RATIO='+ceiling, 'MAX_FAIL_RATIO=0.02').replace(
        '-exec /usr/bin/grep ', '-exec grep ') == gate(upstream), 'raw test counting/gate changed'
    series = (ROOT/'patches/series').read_text().splitlines()
    assert len(series) == len(set(series)) == 4
    assert set(series) == {p.name for p in (ROOT/'patches').glob('*.patch')}
    for name in series:
        assert re.fullmatch(r'[0-9]{4}-[a-z-]+\.patch', name), name
        text = (ROOT/'patches'/name).read_text()
        assert 'Subject:' in text and 'Upstream-Status:' in text and 'Reference:' in text
    print('PASS: input hashes, upstream hardening/environment/patches/ABI gates, patch series')

if __name__ == '__main__':
    main()
