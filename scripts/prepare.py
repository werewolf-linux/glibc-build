#!/usr/bin/env python3
"""Check out the locked source and apply upstream then policy patches strictly."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import yaml

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('destination', type=Path)
    parser.add_argument('--source', type=Path, help='local git repository for offline validation')
    args = parser.parse_args()
    assert not args.destination.exists(), 'use a new destination; never reset an existing checkout'
    lock = json.loads((ROOT/'upstream.lock.json').read_text())
    source = str(args.source) if args.source else 'https://sourceware.org/git/glibc.git'
    subprocess.run(['git', 'init', str(args.destination)], check=True)
    def git(*arguments):
        subprocess.run(['git', '-C', str(args.destination), *arguments], check=True)
    git('fetch', '--depth=1', source, lock['glibc_commit'])
    git('checkout', '--detach', 'FETCH_HEAD')
    config = yaml.safe_load((ROOT/'upstream.yaml').read_text())
    upstream = next(x for x in config['pipeline'] if x.get('uses') == 'patch')['with']['patches'].split()
    for patch in [ROOT/'upstream'/name for name in upstream] + [ROOT/'patches'/name for name in (ROOT/'patches/series').read_text().splitlines()]:
        git('apply', '--check', str(patch))
        git('apply', str(patch))
    shutil.copyfile(ROOT/'upstream/allowed-failures.txt', args.destination/'allowed-failures.txt')
    print('Source prepared at', args.destination)

if __name__ == '__main__':
    main()
