# Compiler hardening beyond Wolfi

## Summary

Preserve current Wolfi hardening as the release floor. Evaluate stricter flexible-array interpretation and clearing used general-purpose registers as build-time additions, without runtime opt-outs or extra source patches.

## Background

Chainguard's [2025 investigation](https://www.chainguard.dev/unchained/this-shit-is-hard-hardening-glibc) describes unwinding and early IFUNC failures exposed by hardening. Current Wolfi specs are newer than that article: GCC 16 uses `-fhardened` and `-fzero-init-padding-bits=all`, with architecture-specific protection. The [OpenSSF guide](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html), dated 2026-08-20 when inspected, also recommends strict flexible arrays and clearing used GPRs. This is an evaluation proposal, not a claim that extra flags have passed glibc compatibility or performance gates.

## Goals

- Keep Wolfi's compiler wrapper, configure flags, upstream corrections, ABI and unwinding tests.
- Check compiler invocations and resulting ELF properties, rather than infer protection from a flag name.
- Add an extra only after native x86_64/aarch64 correctness and performance validation.

## Non-Goals

- Replace glibc's per-file bootstrap/fortification rules with a blanket flag list.
- Add runtime controls or disable optimized CPU dispatch, tcache, or arenas.
- Claim compiler hardening prevents arbitrary code execution.

## Detailed design

| Mechanism | Current Wolfi floor | Additional evaluation |
| --- | --- | --- |
| Bounds checks | Highest supported glibc fortification, currently level 3 | `-fstrict-flex-arrays=3` improves interpretation of trailing arrays; test legacy layouts and object-size assumptions. |
| Initialization | Automatic-variable zeroing and GCC 16 padding initialization | Already present; preserve rather than advertise as an addition. |
| Stack protection | Strong canaries, clash probes, non-executable ELF stack | `--enable-stack-protector=all` adds canaries to more functions; assess benefit versus work in small frequent calls. |
| Return state | x86 CET; ARM PAC/BTI; normal register lifetime | `-fzero-call-used-regs=used-gpr` clears used caller-saved GPRs at returns; benchmark calls and allocator paths. It does not instrument handwritten assembly. |
| Relocations | RELRO and eager binding | Verify actual ELF properties; no extra relaxation for startup speed. |
| Control-flow redundancy | Hardware-aware protections | GCC software redundancy flags add checks; defer unless a measured workload justifies their cost and coverage. |
| Shadow stacks | Upstream CET/GCS behavior | Fleet-wide strict enforcement needs supporting CPUs, kernels, libraries, signal handling and unwinding; not an isolated compiler change. |

`scripts/verify.py` checks the derived recipe retains every upstream configure option and the exact compiler environment. Package builds use `openssf-compiler-options`; glibc still controls fortification and bootstrap exclusions. Record compiler versions, resolved specs, configuration and ELF results with releases. Plain Ubuntu/GCC builds validate patch behavior but do not establish equivalence to Wolfi's complete toolchain.

GCC documents [strict flexible arrays](https://gcc.gnu.org/onlinedocs/gcc/C-Dialect-Options.html), [register clearing](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html), and [hardening/stack protection](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html). Candidate flags affect generated code, including optimizer assumptions; compile success alone is insufficient. Preserve glibc's existing file-specific exemptions.

The guide's `-z nodlopen` marks a particular shared object unavailable for new explicit loads; it is not a global ban on `dlopen` and does not replace loader/NSS/converter restrictions or IPE. Do not blanket-apply it to libc or plugins without namespace and loader compatibility tests. PIE belongs on executables, PIC on shared libraries. C++ library assertion flags do not independently harden glibc's C implementation.

## Drawbacks

Extra instructions can increase code size and call overhead. New assumptions can expose old source idioms; fixing them downstream could expand the patch set. Hardware enforcement can reject otherwise usable packaged software. No overhead percentage is assumed.

## Alternatives Considered

- Copy the OpenSSF command line verbatim: its application guidance needs adaptation for libc, early loader code, shared libraries, and architecture-specific assembly.
- Add every available GCC check: more checks alone do not establish useful protection or acceptable performance.
- Only inspect build flags: a later override or a mixed dependency can defeat the intended protection; inspect outputs and run failure-path tests too.

## Security Considerations

Retain upstream early-loader/IFUNC and unwinding fixes. Test backtrace, C++ exceptions, cancellation, signals and static startup with the hardened library. The five feature restrictions remain fixed regardless of any compiler experiment.

## Reliability Considerations

Compare the same source, toolchain and workload with one added mechanism at a time. Gate on upstream and injection-test results, ABI stability, native supported-CPU tests, and no repeatable regression over 5% in required workloads. Keep additional flags out of release builds until evidence supports them; record a rejected candidate's reason.
