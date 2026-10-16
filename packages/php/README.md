# php

Werewolf's PHP: Wolfi's newest stable `php-8.5` recipe, captured unchanged, plus seven
policy patches
([design](https://github.com/werewolf-linux/werewolf/blob/main/docs/design/hardened-interpreters.md)).
Packages keep Wolfi's names, so forms that install `php-8.5` or its extensions get it.

## Differences from Wolfi's build

Same as Wolfi: source commit, Wolfi's two patches, toolchain, configure flags but two,
every extension and package test.

- **Patches** (`patches/series`), applied after Wolfi's:
  1. `PHPRC` and `PHP_INI_SCAN_DIR` are ignored; configuration comes from the root.
  2. Allowances: `/etc/werewolf/allow/php/NAME`, a regular file, never a link.
  3. `exec`, `system`, `passthru`, `shell_exec`, `proc_open`, `popen`, `pcntl_exec` and
     `dl` stay disabled, whatever `php.ini` or `-d` says, unless each is allowed.
  4. `unserialize` makes objects only of classes `allowed_classes` names, unless
     `unserialize` is allowed.
  5. `allow_url_include` is always off.
  6. OPcache never loads compiled scripts from a file cache.
  7. The `phar://` wrapper is registered only when `phar` is allowed.
- **Configure**: no phpdbg (`--enable-phpdbg`) and no PEAR (`--with-pear`); their
  subpackages are gone.
- **Tests**: Wolfi's tests, then `tests/probe.sh`, which checks each protection with
  `php.ini-production` in place and that each allowance, and only a regular file, takes
  its function back.
- **Packaging**: epoch `1000 × policy.json revision + Wolfi epoch` sorts above every
  Wolfi rebuild; each package provides `wolfi-origin:php-8.5:VERSION-rEPOCH` for CVE
  matching. Derivation stops for review when the checkout, Wolfi's patches, a removed
  flag, a subpackage or the package identity changes.

## Behavior changes for applications

- Composer, WordPress plugins and the like that shell out fail with "has been disabled
  for security reasons"; a form that needs one declares `allow: [php:proc_open]` (or
  the function's name) in `form.yaml`.
- `unserialize($data)` without `allowed_classes` yields `__PHP_Incomplete_Class` for
  objects; name the classes, or declare `allow: [php:unserialize]`.
- `phar://` paths fail unless `allow: [php:phar]`; `.phar` tools such as `composer.phar`
  need it.
- `PHPRC` and `PHP_INI_SCAN_DIR` do nothing; put settings in the image's `php.ini`.
- No `phpdbg` and no `pear`/`pecl`; build extensions into the image instead.

## Building

`make PACKAGE=php refresh check derive prepare build` captures Wolfi's recipe, verifies
it, applies every patch and builds with Melange ([README](../../README.md)). Unit tests,
from the repository root:

    python3 -m unittest discover -s packages/php/tests -p 'test_*.py'

Patches are PHP-3.01, as PHP (`LICENSES/PHP-3.01.txt`); Wolfi inputs keep their license.
