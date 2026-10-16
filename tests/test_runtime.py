import io
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import runtime


class RuntimePublication(unittest.TestCase):
    def parts(self, name):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            archive.addfile(tarfile.TarInfo(name))
        return [None, None, (b'', data.getvalue())]

    def test_no_package_can_ship_its_own_exception(self):
        for name in ('etc/runtime-hardening', './etc/runtime-hardening/build-root',
                     '/etc/runtime-hardening/build-root', 'usr/../etc/runtime-hardening/build-root',
                     'etc/runtime-hardening/allow/all/node/exec'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                runtime.check_apk(None, 'runtime.apk', self.parts(name))
        runtime.check_apk(None, 'runtime.apk', self.parts('usr/bin/node'))


@unittest.skipUnless(shutil.which('cc'), 'C compiler required')
class RootGuard(unittest.TestCase):
    def test_each_shipped_guard_uses_effective_uid_and_refuses_non_regular_markers(self):
        patches = list((ROOT / 'packages').glob('*/patches/*-refuse-effective-root.patch'))
        self.assertEqual({'node', 'python', 'php', 'openjdk'}, {p.parents[1].name for p in patches})
        for patch in patches:
            with self.subTest(runtime=patch.parents[1].name), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                # Compile the actual new header from each runtime's patch. Only
                # the effective identity and file owner are simulated here;
                # package probes exercise real setresuid mismatches on Linux.
                added_file = next(block for block in patch.read_text().split('diff --git ')
                                  if any(line.startswith('+++ b/') and line.endswith('/runtime_hardening_root.h')
                                         for line in block.splitlines()))
                header = '\n'.join(line[1:] for line in added_file.splitlines()
                                   if line.startswith('+') and not line.startswith('+++')) + '\n'
                (work / 'guard.h').write_text(header)
                (work / 'probe.c').write_text(r'''
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
static uid_t effective;
static uid_t test_euid(void) { return effective; }
static int test_lstat(const char *path, struct stat *st) {
    int result = lstat(path, st);
    if (!result) st->st_uid = 0;
    return result;
}
#define geteuid test_euid
#define getuid forbidden_real_uid
#define lstat test_lstat
#include "guard.h"
int main(int argc, char **argv) {
    effective = (uid_t)strtoul(argv[1], NULL, 10);
    return runtime_hardening_root_refused();
}
''')
                marker = work / 'marker'
                subprocess.run(['cc', '-Wall', '-Werror', '-DRUNTIME_HARDENING_BUILD_ROOT="' + str(marker) + '"',
                                str(work / 'probe.c'), '-o', str(work / 'probe')], check=True)

                def run(uid):
                    return subprocess.run([str(work / 'probe'), str(uid)]).returncode

                self.assertEqual(1, run(0))
                self.assertEqual(0, run(65534))
                marker.touch(mode=0o600)
                self.assertEqual(0, run(0))
                marker.chmod(0o666)
                self.assertEqual(1, run(0))
                marker.unlink()
                target = work / 'target'
                target.touch()
                marker.symlink_to(target)
                self.assertEqual(1, run(0))
                marker.unlink()
                marker.mkdir()
                self.assertEqual(1, run(0))


if __name__ == '__main__':
    unittest.main()
