#!/usr/bin/env python3
"""Check out the locked source and apply upstream then policy patches strictly."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import yaml
from inputs import INPUTS
from source import checkout

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('destination', type=Path)
    parser.add_argument('--source', type=Path, help='local git repository for offline validation')
    args = parser.parse_args()
    if args.destination.exists():
        raise ValueError('Use a new destination; never reset an existing checkout')
    lock = json.loads((INPUTS/'upstream.lock.json').read_text())
    options = {'sources': (str(args.source),)} if args.source else {}
    checkout(args.destination, lock['glibc_commit'], **options)
    def git(*arguments):
        subprocess.run(['git', '-C', str(args.destination), *arguments], check=True)
    config = yaml.safe_load((INPUTS/'upstream.yaml').read_text())
    upstream = next(x for x in config['pipeline'] if x.get('uses') == 'patch')['with']['patches'].split()
    for patch in [INPUTS/'upstream'/name for name in upstream] + [ROOT/'patches'/name for name in (ROOT/'patches/series').read_text().splitlines()]:
        git('apply', '--check', str(patch))
        git('apply', str(patch))
    shutil.copyfile(INPUTS/'upstream/allowed-failures.txt', args.destination/'allowed-failures.txt')
    print('Source prepared at', args.destination)

if __name__ == '__main__':
    main()
