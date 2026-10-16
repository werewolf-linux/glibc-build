# php

Werewolf's PHP: Wolfi's newest stable `php-8.5` recipe, captured unchanged, plus
policy patches
([design](https://github.com/werewolf-linux/werewolf/blob/main/docs/design/hardened-interpreters.md)).
Packages keep Wolfi's names, so forms that install `php-8.5` or its extensions get it.

## Differences from Wolfi's build

Same as Wolfi: source commit, Wolfi's two patches, toolchain, and the retained CLI,
FPM and extension build options and tests.

- **Patches** (`patches/series`), applied after Wolfi's:
  1. `PHPRC` and `PHP_INI_SCAN_DIR` are ignored; configuration comes from the root.
  2. Allowances: `/etc/werewolf/allow/php/NAME`, a regular file, never a link.
  3. `exec`, `system`, `passthru`, `shell_exec`, `proc_open`, `popen`, `pcntl_exec` and
     `dl` stay disabled, whatever `php.ini` or `-d` says, unless each is allowed.
  4. `unserialize` makes objects only of classes `allowed_classes` names, unless
     `unserialize` is allowed.
  5. `allow_url_include` is always off.
  6. OPcache never loads compiled scripts from a file cache.
  7. A `phar://` wrapper guard remains in the source; this build disables Phar
     entirely, so an allowance cannot enable it.
- **Packages**: keep CLI, FPM, their configuration, development headers and the
  extensions current Werewolf forms use. Headers support building native extensions
  such as APCu and Redis for this PHP. Omit Apache's `mod_php`, CGI, phpdbg, PEAR/PECL
  and documentation. CGI is explicitly disabled, the Apache install steps are removed,
  and manpages are discarded before splitting packages.
- **Extensions**: retain `bcmath`, `calendar`, `ctype`, `curl`, `dom`, `exif`,
  `fileinfo`, `gd`, `gmp`, `iconv`, `intl`, `ldap`, `mbstring`, `mysqli`, `mysqlnd`,
  `openssl`, `pcntl`, `pdo`, `pdo_mysql`, `pdo_pgsql`, `pdo_sqlite`, `pgsql`, `posix`,
  `simplexml`, `soap`, `sodium`, `sysvsem`, `xml`, `xmlreader`, `xmlwriter` and `zip`,
  with their configuration packages. These serve the WordPress, MediaWiki,
  Nextcloud, Moodle and LimeSurvey forms. Omit `bz2`, `ftp`, `gettext`, `odbc`,
  `pdo_dblib`, `pdo_odbc`, `phar`, `sockets`, `sysvshm`, `tidy` and `xsl`; no current
  form requires them. Phar is explicitly disabled because it defaults to enabled;
  removing only its shared-extension flag would compile it into the main executable.
- **Tests**: Wolfi's retained tests, then `tests/probe.sh`, which checks each protection with
  `php.ini-production` in place and that each allowance, and only a regular file, takes
  its function back. The omitted Tidy extension's test and test dependency are
  removed. The probe verifies that Phar's extension, class and wrapper remain absent,
  even with a Phar allowance.
- **Packaging**: epoch `1000 × policy.json revision + Wolfi epoch` sorts above every
  Wolfi rebuild; each package provides `wolfi-origin:php-8.5:VERSION-rEPOCH` for CVE
  matching. Derivation stops for review when the checkout, Wolfi's patches, a removed
  flag, the extension or subpackage names, or the package identity changes. A new
  extension needs an existing or almost-certain Werewolf consumer before inclusion.

## Behavior changes for applications

- Composer, WordPress plugins and the like that shell out fail with "has been disabled
  for security reasons"; a form that needs one declares `allow: [php:proc_open]` (or
  the function's name) in `form.yaml`.
- `unserialize($data)` without `allowed_classes` yields `__PHP_Incomplete_Class` for
  objects; name the classes, or declare `allow: [php:unserialize]`.
- Phar is unavailable, including `phar://` and tools such as `composer.phar`.
  Our current app recipes use releases with dependencies already included.
- `PHPRC` and `PHP_INI_SCAN_DIR` do nothing; put settings in the image's `php.ini`.
- No `phpdbg` and no `pear`/`pecl`; build extensions into the image instead.
- No `mod_php` or `php-cgi`; serve PHP with FPM, and use CLI for background jobs.

## Building

`make PACKAGE=php refresh check derive prepare build` captures Wolfi's recipe, verifies
it, applies every patch and builds with Melange ([README](../../README.md)). Unit tests,
from the repository root:

    python3 -m unittest discover -s packages/php/tests -p 'test_*.py'

Patches are PHP-3.01, as PHP (`LICENSES/PHP-3.01.txt`); Wolfi inputs keep their license.
