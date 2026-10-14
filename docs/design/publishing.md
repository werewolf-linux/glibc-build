# Publishing Wolfi glibc updates

## Summary

Check Wolfi every ten minutes and build its latest stable glibc recipe with our fixed policy. Publish matching signed APK repositories for both native architectures to Werewolf's R2 bucket and GitHub.

## Background

A maintained version pin delays security updates and duplicates Wolfi's release work. We need immutable captured inputs for each build, without keeping a glibc version in this tree.

## Goals

- Discover the newest primary stable glibc recipe numerically.
- Skip inputs already published; recover staged releases without rebuilding.
- Require native x86_64/aarch64 checks before publication.
- Preserve Wolfi compiler protections, source patches, test coverage and ABI checks.
- Retain every raw failure while applying the requested downstream 5.5% ceiling.

## Non-Goals

- Automatic source patch rebasing, runtime security exceptions or production deployment.
- Altering Werewolf's existing APK repository index.

## Detailed design

`refresh.yml` runs at minutes 7, 17, 27, 37, 47 and 57, on main pushes and manually. GitHub schedules are best effort. One concurrency group serializes discovery, both builds and publication; redundant pending checks can be replaced.

`refresh.py` clones Wolfi and selects the highest numeric stable version that provides the primary glibc virtual. It requires the latest recipe's exact source pin; invalid new inputs stop rather than falling back. It captures the unchanged recipe, complete supporting directory, pipelines and signing public key under `build/inputs/`.

The input lock hashes those files, records upstream file modes, and hashes our patches, scripts, tests, profile, workflow, tool pins and policy. The shared input artifact is a tar archive: GitHub artifact ZIP extraction otherwise removes executable bits from Wolfi helpers. Native builders and the publisher unpack it before verification; any mode change fails verification. Its build identity excludes unrelated Wolfi commits and our documentation. Both builders download the same captured artifact and verify every input. Nothing discovers a second upstream version during that build.

`policy.json` maintains a downstream revision, independent of glibc's version. The package epoch is Wolfi's epoch plus this revision. Increment it when policy, packaging or test behavior changes; patches and input hashes also distinguish releases. No maintained glibc version is needed.

The native builders retain Wolfi's compiler environment and flags. Strict patch application, focused hardening probes, full upstream tests, ABI checks and installed-package checks must succeed. The raw failure ceiling is explicitly changed from Wolfi's 2% to the requested 5.5%. The publisher recounts raw PASS/FAIL files using exact integer arithmetic; UNSUPPORTED and XFAIL cannot dilute the denominator. No failure is reclassified.

The successful build record includes hashes, source/recipe/tool pins, patched source and public signing key. The publisher verifies these records, APK control signatures, payload hashes, signed index coverage and matching versions/architectures. Ephemeral CI keys cannot be published.

Validated archives are first uploaded to a GitHub draft tagged `build-<full-input-hash>`. Its manifest is uploaded last. A complete draft lets the next check resume publication using the original bytes, including after a documentation-only commit. Partial staging failures require rerunning the original failed job.

R2 uses bucket `werewolf` and prefix `apk/glibc-neutered/`, via the existing account endpoint. Each immutable snapshot has `builds/<input-hash>/<arch>/` containing APKs and a signed index. Objects upload before the index; both architectures and source archives precede the completion manifest. Existing objects must match byte-for-byte.

`current.json` points to the complete snapshot. It updates only after both repositories exist, and an older workflow cannot replace a pointer from a newer run. The GitHub draft becomes public last. The public repository URL is `https://dist.werewolf-linux.org/apk/glibc-neutered/builds/<input-hash>`; APK clients append the architecture.

Jobs use the `release` environment and existing `WEREWOLF_PACKAGES_KEY`, `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY` secrets. Signing happens in its own step, so the private key environment does not reach the build. The public key must equal the committed Werewolf trust root, and its APK key filename remains `werewolf-packages.rsa.pub`.

## Drawbacks

Native suites are expensive and deliberate feature removal causes upstream failures. A 5.5% count gate can admit new failures within its remaining budget; it does not establish that failures are harmless. Application/IPE/performance checks still govern deployment.

## Alternatives Considered

- Daily version-update PRs: create a separate pinned recipe stream and delay publication.
- Reusing one mutable APK index: risks collisions, partial updates and changes to Werewolf's packages.
- Rebuilding after publication fails: changes package bytes and makes safe retries harder.
- Ignoring intentional failures: obscures raw evidence and requires an evolving exception list.

## Security Considerations

Publication reads artifacts from its own trusted workflow run, never PR artifacts. PR validation uses ephemeral keys. Every native gate must pass; drift stops the update and leaves the previous release available. Bucket reads use the authenticated S3 API, and authentication errors never mean an object is absent. CI is the single writer to this prefix.

A published package passes these package gates; it is not evidence that every Werewolf form is ready to adopt it. Loader/libc coherence, IPE coverage, service performance and PostgreSQL migration remain deployment requirements.

## Reliability Considerations

A complete GitHub draft preserves validated bytes across R2 failures. Uploads are idempotent and reject conflicting bytes. The completion manifest and public GitHub release appear after both signed repositories. The ten-minute schedule is a check interval, not a release-latency guarantee.

Sources: [GitHub schedules](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule), [R2 S3 compatibility](https://developers.cloudflare.com/r2/api/s3/api/).

Artifact transport: [GitHub permission preservation](https://github.com/actions/upload-artifact#permission-loss).
