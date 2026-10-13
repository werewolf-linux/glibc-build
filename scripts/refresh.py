#!/usr/bin/env python3
"""Capture Wolfi's latest stable glibc recipe without maintaining a version."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import yaml
from inputs import ROOT, INPUTS, identity, policy_hashes, sha256, file_modes

def latest(checkout):
    candidates = []
    for path in checkout.glob('glibc*.yaml'):
        config = yaml.safe_load(path.read_text())
        package = config.get('package', {})
        version = str(package.get('version', ''))
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)+', version):
            continue
        if package.get('name') != 'glibc-' + version:
            continue
        if 'glibc=${{package.full-version}}' not in package.get('dependencies', {}).get('provides', []):
            continue
        candidates.append((tuple(map(int, version.split('.'))), path, config))
    if not candidates:
        raise ValueError('No stable primary Wolfi glibc recipe found')
    _, path, config = max(candidates, key=lambda candidate: candidate[0])
    source = config.get('vars', {}).get('glibc-expected-commit', '')
    if not re.fullmatch('[0-9a-f]{40}', source):
        raise ValueError('Latest recipe has no exact source pin')
    return path, config

def capture(checkout, destination=INPUTS):
    path, config = latest(checkout)
    commit = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
    if subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain'], text=True).strip():
        raise ValueError('Wolfi checkout has local changes')
    policy = json.loads((ROOT / 'policy.json').read_text())
    revision = policy['revision']
    if type(revision) is not int or revision < 1:
        raise ValueError('Policy revision must be a positive integer')
    if type(policy['max_fail_per_mille']) is not int or not 0 <= policy['max_fail_per_mille'] <= 55:
        raise ValueError('Raw failure ceiling must not exceed 5.5%')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='inputs-') as directory:
        candidate = Path(directory)
        shutil.copyfile(path, candidate / 'upstream.yaml')
        shutil.copytree(checkout / path.stem, candidate / 'upstream')
        shutil.copytree(checkout / 'pipelines', candidate / 'pipelines')
        shutil.copyfile(checkout / 'wolfi-signing.rsa.pub', candidate / 'wolfi-signing.rsa.pub')
        lock = {'repository': 'https://github.com/wolfi-dev/os', 'recipe': path.name,
                'wolfi_commit': commit, 'glibc_commit': config['vars']['glibc-expected-commit'],
                'version': str(config['package']['version']), 'epoch': config['package']['epoch'],
                'revision': revision,
                'sha256': {str(p.relative_to(candidate)): sha256(p) for p in sorted(candidate.rglob('*')) if p.is_file()},
                'mode': file_modes(candidate),
                'policy_sha256': policy_hashes()}
        lock['build_id'] = identity(lock)
        (candidate / 'upstream.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(candidate, destination)
    return lock

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wolfi', type=Path, help='clean existing Wolfi checkout for offline use')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='neutered-wolfi-') as directory:
        checkout = args.wolfi
        if checkout is None:
            checkout = Path(directory) / 'os'
            subprocess.run(['git', 'clone', '--depth=1', 'https://github.com/wolfi-dev/os.git', str(checkout)], check=True)
        lock = capture(checkout)
    print('Wolfi', lock['version'], 'build', lock['build_id'])

if __name__ == '__main__':
    main()
