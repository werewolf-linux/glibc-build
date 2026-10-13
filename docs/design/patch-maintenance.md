# Maintaining the glibc policy patches

## Summary

Treat this repository as a small downstream port: unchanged upstream inputs, an ordered patch series, and a narrow packaging delta. Keep each policy change easy to apply, review, and retire if upstream supplies an equivalent.

## Background

The [FreeBSD Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/slow-porting/) describes keeping local changes as patch files separate from source releases. We use that principle with Melange, while deriving packaging from Wolfi instead of maintaining a parallel recipe.

## Goals

- Preserve byte-for-byte upstream recipe/support files with source and input hashes.
- Apply one patch per protection mechanism in a declared order, without fuzz or automatic conflict repair.
- Require explicit reasons and review for every added hunk or compatibility exception.

## Non-Goals

- A separately maintained glibc branch, copied configure/build logic, automatic patch rebasing, or runtime feature profiles.

## Detailed design

`patches/series` lists four source patches. The fifth protection, nscd removal, uses existing build switches. Headers identify the intended change, inspected base, upstream applicability and audit/design references. Keep allocator/string/math implementations out of these patches.

`scripts/refresh.py` copies the tracked Wolfi release stream's recipe and supporting directory as a complete unit and regenerates provenance hashes. It increments the downstream revision when inputs change. Unchanged inputs do not create updates. Major release-stream changes are explicit migrations.

`scripts/prepare.py` fetches the exact locked glibc commit into a new directory, applies Wolfi patches first, and runs `git apply --check` before each policy patch. Context mismatches stop preparation. It never resets a developer checkout or substitutes a newer source commit. Unchanged-context offsets are acceptable; fuzzy context matching is not.

On patch drift, prepare an unmodified new source, apply the old series one patch at a time, and manually revise only the failing mechanism. Compare the final diff and behavior with the previous validated release; update each patch's base/reference as appropriate. Retain explanatory context rather than generating zero-context patches. Increment `upstream.lock.json`'s revision for policy/packaging changes before releasing new package bytes under an existing upstream version.

`scripts/derive.py` holds the package naming, added flags, application gates, and omitted facilities. It must preserve compiler environment and existing upstream hardening, tests, and ABI checks. `scripts/verify.py` checks these invariants and input hashes before any package build.

Test binaries use upstream's hardcoded test interpreter/RPATH option. Build utilities use the installed build-host libc. Neither gets a policy bypass; the shipped loader rejects the same overrides under test. Record failures individually with their output and a verified policy reason before accepting them as expected.

## Drawbacks

Upstream refactors can require manual work. Generated YAML is longer than the packaging delta. Native package checks take longer than checking patch application; patch cleanliness alone is insufficient.

## Alternatives Considered

- Maintain full downstream source: makes the security delta harder to review and can hide missed upstream fixes.
- Reimplement the recipe: duplicates Wolfi's toolchain, ABI and packaging fixes.
- Apply with patch fuzz or automatically regenerate failed hunks: may place a restriction at the wrong lifecycle point and silently reopen a bypass.

## Security Considerations

Review all input paths for a changed activation point, including static startup and later loads. Preserve public getters and real secure-execution cleanup. A successful context match does not prove the semantics remain correct after upstream refactoring.

## Reliability Considerations

Native builds, injection probes, upstream results, ABI checks and performance gates must pass before promotion. Drift leaves the previous validated release intact. Candidate releases are immutable; update/rollback must keep loader, libc and package trust coherent.
