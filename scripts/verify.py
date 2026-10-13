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
from derive import derive

def main():
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    assert re.fullmatch('[0-9a-f]{40}', lock['wolfi_commit'])
    assert re.fullmatch('[0-9a-f]{40}', lock['glibc_commit'])
    for name, digest in lock['sha256'].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest() == digest, name
    upstream = yaml.safe_load((ROOT/'upstream.yaml').read_text())
    derived = derive()
    configure = lambda c: next(x['runs'] for x in c['pipeline'] if x.get('name') == 'Configure glibc')
    flags = lambda s: set(re.findall(r'--[a-zA-Z0-9_-]+(?:=[^\s\\]+)?', s))
    assert flags(configure(upstream)) <= flags(configure(derived)), 'upstream configure flags removed'
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
