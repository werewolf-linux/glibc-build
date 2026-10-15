#!/usr/bin/env python3
"""Use Werewolf's native Melange runners; QEMU boots an Alpine kernel."""
import argparse
import fcntl
import hashlib
import functools
import http.server
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import threading
import yaml
from derive import MIN_KERNEL

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--arch', default=platform.machine())
parser.add_argument('--test-only', action='store_true', help='rerun package checks against existing signed APKs')
args = parser.parse_args()
arch = {'arm64': 'aarch64', 'aarch64': 'aarch64', 'x86_64': 'x86_64'}[args.arch]
os.chdir(ROOT)
melange = os.environ.get('MELANGE', 'melange')
version = json.loads((ROOT/'tools.lock.json').read_text())['melange']['version']
reported = subprocess.check_output([melange, 'version'], text=True)
if f'v{version}' not in reported:
    raise SystemExit(f'Install pinned Melange v{version} with scripts/install-melange.py')
runner = 'bubblewrap' if platform.system() == 'Linux' and shutil.which('bwrap') else 'qemu'
scratch = ROOT/'build/runner'
scratch.mkdir(parents=True, exist_ok=True)
env = os.environ.copy()
env['TMPDIR'] = str(scratch)
manifest = {'runner': runner, 'arch': arch, 'melange_version': version}
def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024*1024), b''):
            digest.update(block)
    return digest.hexdigest()

if runner == 'bubblewrap':
    # The test suite runs on this kernel, and the built glibc refuses older ones.
    host = tuple(int(x) for x in re.match(r'(\d+)\.(\d+)', platform.release()).groups())
    if host < tuple(int(x) for x in MIN_KERNEL.split('.')):
        raise SystemExit(f'host kernel {platform.release()} is older than glibc minimum {MIN_KERNEL}')
    manifest['kernel'] = platform.release()
    executable = Path(shutil.which('bwrap')).resolve()
    manifest['bubblewrap_sha256'] = sha256(executable)
    profile = executable.with_suffix('.apparmor')
    if profile.is_file():
        manifest['apparmor_profile_sha256'] = sha256(profile)

with (scratch/'lock').open('w') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    if runner == 'qemu':
        build = os.environ.get('WEREWOLF_BUILD')
        if not build:
            raise SystemExit('Set WEREWOLF_BUILD to Werewolf build/ARCH (kernel and modules)')
        build = Path(build).resolve()
        kernel = build/'vmlinuz'
        modules = build/'kernel/x/lib/modules'
        if not kernel.is_file() or not modules.is_dir():
            raise SystemExit(f'{build}: expected vmlinuz and kernel/x/lib/modules')
        guest = scratch/f'guest-{arch}.cpio'
        base = scratch/f'base-{arch}.cpio'
        # Always regenerate with the pinned Melange, rather than reusing a
        # Werewolf guest made by another version of Melange.
        subprocess.run([melange, 'initramfs', '--arch', arch, '--output', str(base)], check=True, env=env)
        with guest.open('wb') as output:
            with base.open('rb') as source:
                shutil.copyfileobj(source, output)
            # Prefix usr/: replacing /lib destroys the guest loader symlink.
            names = ['lib/modules'] + [str(p.relative_to(modules.parent.parent))
                for p in sorted(modules.rglob('*')) if not p.is_symlink()]
            listing = scratch/'modules.list'
            listing.write_text('\n'.join(names)+'\n')
            subprocess.run(['bsdtar', '--format', 'newc', '--uid', '0', '--gid', '0',
                '--numeric-owner', '-s', ',^lib/,usr/lib/,', '-cf', '-', '--no-recursion',
                '-T', str(listing)], cwd=modules.parent.parent, stdout=output, check=True)
        env.pop('QEMU_KERNEL_MODULES', None)
        env['QEMU_KERNEL_IMAGE'] = str(kernel)
        env['QEMU_BASE_INITRAMFS'] = str(guest)
        env['QEMU_DISKS_PATH'] = str(scratch)
        for name, path in [('kernel', kernel), ('guest', guest)]:
            manifest[name+'_sha256'] = sha256(path)
        base.unlink()
    packages = ROOT/'build/packages'
    packages.mkdir(parents=True, exist_ok=True)
    provenance = 'test-runner.json' if args.test_only else 'runner.json'
    (packages/provenance).write_text(json.dumps(manifest, indent=2)+'\n')
    if not args.test_only:
        subprocess.run([melange, 'build', 'build/glibc.yaml', '--runner', runner,
            '--source-dir', 'build/context', '--arch', arch, '--cpu', env.get('MELANGE_CPU', '4'),
            '--memory', env.get('MELANGE_MEMORY', '8Gi'), '--namespace', 'werewolf',
            '--pipeline-dir', 'build/inputs/pipelines', '--repository-append', 'https://packages.wolfi.dev/os',
            '--keyring-append', 'build/inputs/wolfi-signing.rsa.pub', '--signing-key', 'build/keys/werewolf-packages.rsa',
            '--cache-dir', str(scratch/'cache'), '--out-dir', str(packages)], check=True, env=env)
    # Build pipelines and package test pipelines are separate Melange commands.
    # Package tests are self-contained. Empty input avoids a QEMU bootstrap
    # copying files with find's implicit execvp("cp") before tests can run.
    test_context = ROOT/'build/test-context'
    test_context.mkdir(exist_ok=True)
    # Fresh-root apk checks need the signed local index inside the runner.
    # QEMU reaches the host loopback through its user-network gateway.
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(packages))
    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        host_repository = f'http://127.0.0.1:{port}'
        guest_host = '10.0.2.2' if runner == 'qemu' else '127.0.0.1'
        test_config = yaml.safe_load((ROOT/'build/glibc.yaml').read_text())
        test_config['vars']['neutered-test-repository'] = f'http://{guest_host}:{port}'
        recipe = ROOT/'build/glibc-test.yaml'
        recipe.write_text(yaml.safe_dump(test_config, sort_keys=False))
        try:
            subprocess.run([melange, 'test', str(recipe), '--runner', runner,
                '--source-dir', str(test_context), '--arch', arch, '--cpu', env.get('MELANGE_CPU', '4'),
                '--memory', env.get('MELANGE_MEMORY', '8Gi'), '--pipeline-dirs', 'build/inputs/pipelines',
                '--test-package-append', 'busybox', '--test-package-append', 'apk-tools',
                '--repository-append', host_repository, '--repository-append', 'https://packages.wolfi.dev/os',
                '--keyring-append', 'build/keys/werewolf-packages.rsa.pub', '--keyring-append', 'build/inputs/wolfi-signing.rsa.pub'],
                check=True, env=env)
        finally:
            server.shutdown()
            thread.join()
