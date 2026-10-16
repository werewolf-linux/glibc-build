# node

Wolfi's newest stable `nodejs-*` recipe, currently Node.js 26.12.0, captured unchanged
and rebuilt with Werewolf's compiled policy. The scheduled discovery, native builds
and tests on both architectures, signed releases and combined hardened feed are the
same as Python, PHP and Java. Package identity stays `nodejs-26`, with a higher epoch
and `wolfi-origin` metadata for CVE matching.

It also provides `nodejs-hardened=VERSION`. Werewolf's Node form requires this alias
to follow the newest published stream and refuse an unhardened fallback, including
before the first Node release appears in the combined index.

The default restrictions are:

- Effective UID 0 refuses process initialization and embedded environment creation.
  Services drop privileges before starting Node. The shared build-only marker is
  never packaged, and there is no root allowance for forms.
- `node:exec` is required for child-process APIs, including their native bindings,
  and for the built-in `node --run` task runner. Normal flags, permission audit mode,
  environment variables and worker options cannot grant this capability.
- `node:native` is required for native addons, binary addon loading, FFI, WASI,
  OpenSSL STORE loaders, SQLite extensions and explicit OpenSSL configuration files.
  Without it, OpenSSL configuration/module environment variables are removed before
  initialization because OpenSSL also reads them directly.
- `node:inline` is required for `-e`, `-p`, stdin, REPL input, worker `eval` and
  ordinary `data:` module imports.
- `node:writable-source` is required for main scripts and ordinary CommonJS/ESM
  code modules on writable mounts, and for disk compilation caches. Unknown mount
  provenance also refuses. JSON data modules, data read through `fs` and ordinary
  SQLite operations remain available.
- `NODE_OPTIONS` support is compiled out. Internal environment options are ignored;
  `NODE_PATH` and home-directory module searches are removed. Application environment
  variables remain available apart from the native-loading variables above.
- Inspector, npm/npx, single executable application support and its LIEF dependency
  are omitted. Custom startup snapshots and security-revert flags refuse.

The only package is the ordinary runtime, including Wolfi's headers for application
builds. Omit the duplicate minimal runtime, minimal compatibility links, shared
libnode, OCI entrypoint and documentation subpackages. New subpackages need a use case.

Install hooks belong to package managers. This package ships none, and its default
process-execution floor also blocks an independently installed npm/pnpm/yarn from
launching lifecycle scripts or implicit `node-gyp` builds. There is no claim of a
separate npm lifecycle policy when a form grants `node:exec`; builds should still use
`--ignore-scripts` and run reviewed build commands explicitly.

Allowances use `/etc/runtime-hardening/allow/<service>/node/GROUP`, with `all` as the
image-wide namespace, exactly as the other runtimes. Only a regular file grants one;
argv, JS configuration and symlinks grant nothing. The `environment` group exists
only for build compatibility and is not exposed by Werewolf forms.

This is a capability floor alongside leash, not a sandbox for hostile JavaScript.
`eval`, `Function`, `vm`, custom loader-generated source and in-process bytecode
remain the deferred code-provenance work shared with the other interpreters. The
writable-source checks cover ordinary module loaders, not a general bytecode seal.
JIT and ordinary worker threads remain available; Werewolf's Node form grants `jit`.

`tests/probe.sh` exercises the installed runtime, native addon loading, SQLite,
all child-process APIs, task scripts, environment injection, worker behavior and
each allowance. The shared identity probe checks both real/effective UID mismatches.
Builds grant capabilities only inside the build guest; publication rejects APKs
that contain any runtime-hardening exception files.
