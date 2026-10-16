# python

Werewolf's CPython: Wolfi's newest stable `python-3.15` recipe, captured unchanged,
plus three policy patches
([design](https://github.com/werewolf-linux/werewolf/blob/main/docs/design/hardened-interpreters.md)).
Packages keep Wolfi's names, so forms that install `python-3.15` or `python3` get it.

## Differences from Wolfi's build

Same as Wolfi: source commit, Wolfi's four patches, toolchain, configure options but
one, the PGO run, the free-threaded and JIT builds, every subpackage and package test.

- **Patches** (`patches/series`), applied after Wolfi's and before the free-threaded and
  JIT builds copy the tree:
  1. `-E -s` by default: `PYTHON*` variables are ignored unless
     `/etc/werewolf/allow/python/environment` exists; the user site always is.
  2. No working directory on `sys.path` for `-m`, `-c` or stdin; a script keeps its own
     directory.
  3. `_ctypes` refuses to load unless `/etc/werewolf/allow/python/ctypes` is a regular
     file, never a link.
- **Configure**: no `--enable-loadable-sqlite-extensions`; `sqlite3` loads no native
  code.
- **Build**: a step writes the ctypes and environment allowances in the build guest
  only: CPython's extension check drops a module that refuses to import, and its PGO
  run's tests set `PYTHON*` variables for the interpreters they start. Packages hold
  nothing under `/etc/werewolf`, and werewolf's forms cannot allow the environment.
- **Tests**: Wolfi's tests, then `tests/probe.sh`, which checks each protection and
  that each allowance, and only a regular file, takes back what it names.
- **Packaging**: epoch `1000 × policy.json revision + Wolfi epoch` sorts above every
  Wolfi rebuild; each package provides `wolfi-origin:python-3.15:VERSION-rEPOCH` for
  CVE matching. Derivation stops for review when the checkout, the patch and clone
  order, the removed option or the package identity changes.

## Behavior changes for applications

- `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONUNBUFFERED`,
  `PYTHONDONTWRITEBYTECODE`, `PYTHONMALLOC`, `PYTHONUTF8` and the rest have no effect.
  Use the matching option (`-u`, `-B`, `-X utf8`) or put code where `sys.path` looks.
- `pip install --user` and `~/.local` site-packages are not used; use a virtual
  environment, whose `pyvenv.cfg` still works.
- `python -m app` from a data directory no longer imports modules from it; install the
  application, or run it as a script.
- `import ctypes` raises `ImportError` naming the allowance; a form that needs it
  declares `allow: [python:ctypes]` in `form.yaml`.
- `sqlite3.Connection` has no `enable_load_extension`.
- Programs that embed CPython through the legacy `Py_Initialize` keep CPython's
  defaults for the environment and the user site; patches 2 and 3 still apply.

## Building

`make PACKAGE=python refresh check derive prepare build` captures Wolfi's recipe,
verifies it, applies every patch and builds with Melange ([README](../../README.md)).
Unit tests, from the repository root:

    python3 -m unittest discover -s packages/python/tests -p 'test_*.py'

Patches are PSF-2.0, as CPython; Wolfi inputs keep their license.
