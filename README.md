# hardened-packages

Werewolf's rebuilds of Wolfi packages. Each one is Wolfi's newest stable recipe,
captured unchanged, plus a few policy patches that remove or deny what attacks need.
Releases follow Wolfi's within minutes, signed with Werewolf's package key.

Consumers use one feed: **https://dist.werewolf-linux.org/apk/hardened**, with
`x86_64/APKINDEX.tar.gz` and `aarch64/APKINDEX.tar.gz` signed by
[release/packages.pub](release/packages.pub).

| Package | Follows | Policy |
|---|---|---|
| [glibc](packages/glibc) | newest `glibc-2.*` | libc ignores its environment, no loader injection |
| [php](packages/php) | newest `php-8.*` | no PEAR/Phar; exec, native, deserialize, inline and writable scripts require allowances |
| [openjdk](packages/openjdk) | newest `openjdk-*` | no deserialize or native (Unsafe, FFM, JNI) unless allowed |
| [python](packages/python) | newest `python-3.*` | no environment, user site, native, deserialize, inline or writable scripts unless allowed |

Package snapshots and release notes remain under `apk/NAME/builds/BUILD-ID/`.
Legacy `apk/NAME` feeds are maintained for compatibility. Packages keep Wolfi's names;
our version outranks the Wolfi build it rebuilds, and each provides
`wolfi-origin:NAME:VERSION` so Werewolf's updater matches Wolfi's CVE fixes. Allowances
are grouped by capability, pledge-style: an empty file at
`/etc/runtime-hardening/allow/<ns>/LANG/GROUP`, or `.../all/LANG/GROUP` for every
service, read off the read-only root, never from argv or the environment. `<ns>` is the
service, from `/proc/self/cgroup`. Any distro shipping these packages gets the same
default-deny and relaxes a knob by creating one file.

## How it works

Every ten minutes `refresh.yml` takes one Wolfi snapshot and, for each package:

1. **Capture** (`scripts/refresh.py`): the newest stable stream's recipe, its directory,
   pipelines and Wolfi's key, locked by hash. Only the latest stream is followed;
   `policy.json` may pin one with `"stream"` when an upgrade must wait.
2. **Verify and derive** (`verify.py`, `derive.py`): the package's `derive` hook edits
   the recipe; `check` refuses an upstream change nobody has reviewed. Its source is
   fetched at Wolfi's exact commit by one shared step, with mirrors and retries.
3. **Prepare** (`prepare.py`): every patch applies at that commit as the build will
   apply it, GNU patch with fuzz 2.
4. **Build** (`build.yml`): Melange on native x86_64 and aarch64 runners, then Wolfi's
   package tests and our own probes against the signed packages.
5. **Publish** (`publish.py`, `feed.py`): a GitHub draft, immutable APKs, signed indexes,
   then the release. Each index update is conditional on the version read; a concurrent
   publisher re-reads and merges. Existing versions stay available, and a failed
   package leaves its previous release available while others publish. `feed.py`
   backfills existing signed releases even when no rebuild is needed. See
   [publishing](docs/design/publishing.md).

Repository order and higher epochs alone do not prevent fallback to a newer Wolfi
package. Consumers must verify covered package names against the signed hardened
index, including their versions and control checksums, and fail if the feed is
unavailable. Explicit older runtime streams and runtimes inside OCI images need their
own migration; adding this feed does not replace them.

A step that stops a package opens an issue labelled `drift` and `package/NAME`, with the
version and what failed: a patch that no longer applies quotes patch's output. A patch
that needed fuzz still ships, and opens an advisory `fuzz` issue to refresh it. Issues
close when the step passes again. One package's failure holds back no other.

## Building locally

On macOS Melange boots a QEMU guest, built once into `build/guest/ARCH` with apko; on
Linux it uses bubblewrap. You need Python 3 with PyYAML, git, GNU or BSD patch, and:

```sh
brew install apko qemu libarchive          # Linux: apko, bubblewrap, bsdtar
python3 scripts/install-melange.py --dest build/tools/melange
make test                                  # every unit test, no network
make discover                              # capture, verify, derive and patch all
make PACKAGE=php build                     # one package, this machine's arch
```

`make PACKAGE=NAME` also takes `refresh`, `verify`, `derive` and `prepare`; `WOLFI=DIR`
uses a local Wolfi checkout. Local builds sign with a throwaway key in `build/keys/`.
`MELANGE_CPU` and `MELANGE_MEMORY` size the guest. Packages land in
`build/NAME/packages/ARCH/`.

## Adding a package

Make `packages/NAME/` with `package.py`, `policy.json` (`{"revision": 1}`),
`patches/series` and `tests/`. Copy the closest package. `package.py` defines:

| Hook | Required | Purpose |
|---|---|---|
| `FAMILY` | yes | recipe prefix, such as `php-`; the newest stable stream wins |
| `SOURCES` or `sources(lock)` | yes | git URLs for the locked commit, first choice first |
| `PATCHES` | yes | patch directory inside the build context |
| `source_commit(config)` | yes | the commit Wolfi's recipe pins |
| `full_version(lock)` | yes | the version we publish |
| `context(pkg, dir)` | yes | copy patches and probes into the build context |
| `derive(pkg, config, lock)` | yes | Wolfi's recipe to ours |
| `check(pkg, upstream, derived)` | yes | refuse a derivation that lost a protection |
| `TITLE`, `UPSTREAM` | no | names for issues and release notes |
| `stable`, `check_policy`, `prepared` | no | refresh and prepare checks |
| `test_recipe`, `TEST_PACKAGES`, `MIN_KERNEL` | no | package tests |
| `check_apk`, `check_apks`, `gather`, `notes` | no | publication checks and notes |

Raise `policy.json`'s revision whenever patches, packaging or tests change behaviour:
it moves the version above our previous build of the same Wolfi release.

## Writing patches

Patches must survive upgrades, so keep them small and fuzzy-tolerant:

- Change a default or add one early check rather than rewrite a function.
- Anchor hunks on code upstream rarely touches, with short context.
- Fail closed: if the code a patch expects is gone, the build or a probe must fail.
- Prove each protection in the package's probe, run against the installed package.

Each patch starts with `Subject:`, `Upstream-Status:` and `Reference:` headers and is
numbered in `series`. Patches carry the license of what they patch (`LICENSES/`); the
tooling is under `LICENSE`.
