These are candidate packages from the unchanged pinned Wolfi recipe plus the fixed Werewolf policy patches. Both native architecture builds, hardening probes, the inherited upstream test gates, and the ABI gate must succeed before this release is emitted.

Archives include signed APKs and indexes, the CI signing public key, corresponding patched glibc source, source/recipe/tool pins, patch series, and hashes. Keys are ephemeral CI keys: do not automatically trust a downloaded public key or install these on production machines. Candidate releases are immutable and are not automatically deployed.

Production promotion requires a stable authenticated APK key/repository, Werewolf IPE and form checks, performance comparisons, and the separate PostgreSQL migration. No preload, locale-environment, external NSS, or external converter exception is supplied. The strict IPE profile does not support JIT-dependent forms.
