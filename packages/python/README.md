# python

Werewolf's CPython: Wolfi's newest stable `python-3.15` recipe, captured unchanged,
plus policy patches
([design](https://github.com/werewolf-linux/werewolf/blob/main/docs/design/hardened-interpreters.md)).
Packages keep Wolfi's names, so forms that install `python-3.15` or `python3` get it.

## Differences from Wolfi's build

Same as Wolfi: source commit, Wolfi's patches, toolchain, configure options but one, the
PGO run, the free-threaded and JIT builds, every subpackage and package test.

- **Patches** (`patches/series`), applied after Wolfi's and before the free-threaded and
  JIT builds copy the tree:
  1. `-E -s` by default: `PYTHON*` variables are ignored unless the image allows the
     environment; the user site always is.
  2. No working directory on `sys.path` for `-m`, `-c` or stdin; a script keeps its own
     directory.
  3. `native`: `_ctypes` loads only when allowed, since native code removes any check.
  4. `deserialize`: `pickle` reconstructs an object only when allowed; plain data still
     unpickles. The pure-Python unpickler is gated too.
  5. `inline` and `writable-source` (in `main.c`): refuse `-c` and piped stdin, and a
     main script whose file is on a writable mount (so `/data` and `/tmp` are refused).
- **Configure**: no `--enable-loadable-sqlite-extensions`; `sqlite3` loads no native
  code.
- **Allowances**: a capability group is an empty file, never a symlink, at
  `/etc/runtime-hardening/allow/<ns>/python/GROUP` or `.../all/python/GROUP`, read with
  `lstat`. `<ns>` is the service from `/proc/self/cgroup`. The build guest grants every
  group so CPython builds and its suite passes; packages ship nothing there.
- **Tests**: Wolfi's tests, then `tests/probe.sh`, which holds each protection and sees
  each group, and only a regular file, take its own back.
- **Packaging**: epoch `1000 × policy.json revision + Wolfi epoch` sorts above every
  Wolfi rebuild; each package provides `wolfi-origin:python-3.15:VERSION-rEPOCH` for CVE
  matching. Derivation stops for review when the checkout, the patch or clone order, the
  removed option or the package identity changes.

## Behavior changes for applications

- `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONUNBUFFERED` and the rest have no
  effect. Use the matching option (`-u`, `-B`, `-X utf8`) or put code where `sys.path`
  looks.
- `pip install --user` and `~/.local` site-packages are not used; use a virtual
  environment, whose `pyvenv.cfg` still works.
- `python -c`, a piped-in script, and a script under `/data` or `/tmp` are refused; a
  form grants `python:inline` or `python:writable-source` to permit one.
- `import ctypes` raises `ImportError` unless `allow: [python:native]`.
- `pickle.load` of an object raises `UnpicklingError` unless `python:deserialize`.
  This does not reach third-party loaders such as PyYAML's `UnsafeLoader`.
- `sqlite3.Connection` has no `enable_load_extension`.
- Programs that embed CPython through the legacy `Py_Initialize` keep CPython's defaults
  for the environment and the user site; the other patches still apply.

## Building

`make PACKAGE=python refresh check derive prepare build` captures Wolfi's recipe,
verifies it, applies every patch and builds with Melange ([README](../../README.md)).
Unit tests, from the repository root:

    python3 -m unittest discover -s packages/python/tests -p 'test_*.py'

Patches are PSF-2.0, as CPython; Wolfi inputs keep their license.
