#!/usr/bin/env python3
"""Refresh unchanged upstream inputs; patch drift must be reviewed separately."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import yaml

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wolfi', type=Path, help='existing Wolfi checkout for offline updates')
    args = parser.parse_args()
    current = json.loads((ROOT/'upstream.lock.json').read_text()) if (ROOT/'upstream.lock.json').exists() else {}
    with tempfile.TemporaryDirectory(prefix='neutered-upstream-') as directory:
        checkout = args.wolfi
        if checkout is None:
            checkout = Path(directory)/'os'
            subprocess.run(['git', 'clone', '--depth=1', 'https://github.com/wolfi-dev/os.git', str(checkout)], check=True)
        commit = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
        # Follow this release stream until an explicit stream migration.
        recipe = current.get('recipe', 'glibc-2.44.yaml')
        raw = (checkout/recipe).read_bytes()
        config = yaml.safe_load(raw)
        source = config['vars']['glibc-expected-commit']
        old_inputs = (ROOT/'upstream.yaml').read_bytes() if (ROOT/'upstream.yaml').exists() else None
        old_hashes = current.get('sha256', {})
        candidate = Path(directory)/'candidate'
        candidate.mkdir()
        (candidate/'upstream.yaml').write_bytes(raw)
        shutil.copytree(checkout/Path(recipe).stem, candidate/'upstream')
        shutil.copytree(checkout/'pipelines', candidate/'pipelines')
        shutil.copyfile(checkout/'wolfi-signing.rsa.pub', candidate/'wolfi-signing.rsa.pub')
        hashes = {str(p.relative_to(candidate)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(candidate.rglob('*')) if p.is_file()}
        if raw == old_inputs and hashes == old_hashes:
            print('Wolfi recipe and supporting files unchanged')
            return
        lock = {'repository': 'https://github.com/wolfi-dev/os', 'recipe': recipe,
                'wolfi_commit': commit, 'glibc_commit': source,
                'revision': current.get('revision', 0) + 1, 'sha256': hashes}
        # Candidate files are complete before replacing the working inputs.
        shutil.copyfile(candidate/'upstream.yaml', ROOT/'upstream.yaml')
        if (ROOT/'upstream').exists():
            shutil.rmtree(ROOT/'upstream')
        shutil.copytree(candidate/'upstream', ROOT/'upstream')
        if (ROOT/'pipelines').exists():
            shutil.rmtree(ROOT/'pipelines')
        shutil.copytree(candidate/'pipelines', ROOT/'pipelines')
        shutil.copyfile(candidate/'wolfi-signing.rsa.pub', ROOT/'wolfi-signing.rsa.pub')
        (ROOT/'upstream.lock.json').write_text(json.dumps(lock, indent=2)+'\n')
        print('Updated inputs; prepare/build must pass before merging or releasing')

if __name__ == '__main__':
    main()
