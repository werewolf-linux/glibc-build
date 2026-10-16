# openjdk

Werewolf's OpenJDK: Wolfi's newest stable `openjdk-27` recipe, captured unchanged,
plus six policy patches
([design](https://github.com/werewolf-linux/werewolf/blob/main/docs/design/hardened-interpreters.md)).
Packages keep Wolfi's names, so forms that install `openjdk-27` or its `-jre` and
`-default-jdk` subpackages get it.

## Differences from Wolfi's build

Same as Wolfi: source commit, Wolfi's patch, toolchain, configure options, JDK/JRE
image builds and the retained packages' tests.

- **Source**: the locked commit is fetched from `jdk27u`, then from mainline `jdk`,
  which holds each GA tag, in place of Wolfi's checkout.
- **Packages**: keep `openjdk-27` (the full JDK), `openjdk-27-jre`,
  `openjdk-27-default-jdk` and `openjdk-27-default-jvm`. App forms install the JRE;
  application builds need the JDK, and the selectors support the usual tool paths.
  Omit `-demos`, `-jmods` and `-oci-entrypoint-compat`: none has a current consumer.
  Demo files are discarded from the JDK before packaging; the separate `jmods`
  build target and container entrypoint download are removed. The JVM's normal JIT
  remains part of both the JDK and JRE. New subpackages require an identified use case.
- **Patches** (`patches/series`), applied after Wolfi's:
  1. HotSpot ignores `_JAVA_OPTIONS` and `JAVA_TOOL_OPTIONS`; the launcher ignores
     `JDK_JAVA_OPTIONS` and `JDK_ALTERNATE_VM`, which loads any directory's `libjvm.so`.
  2. `DisableAttachMechanism` defaults to true: no `jcmd`, `jstack` or agent attach.
  3. `jdk.internal.misc.WerewolfAllowance` reads allowances: an allowance is a regular
     file, never a link, in `/etc/werewolf/allow/java`.
  4. `ObjectInputStream` refuses every class but primitive arrays, as the filter `!*`
     would, unless `deserialize` is allowed. No filter, filter factory or
     `jdk.serialFilter` takes this back.
  5. `native` gates reaching native code or memory as one group: `sun.misc.Unsafe`
     memory access is denied whatever `--sun-misc-unsafe-memory-access` says, and
     illegal
     native access (JNI, FFM restricted methods) is denied whatever
     `--illegal-native-access` says, with `--enable-native-access` granting nothing. A
     JAR manifest's `Enable-Native-Access` still grants, as the image's own jars may.
- **Tests**: Wolfi's tests, then `tests/probe.sh` with `tests/Probe.java`, which check
  each protection, that the environment and argv lift none, that a manifest still
  grants native access, and that each allowance, and only a regular file, takes back
  what it names and nothing else.
- **Allowances**: a capability group is an empty file, never a symlink, at
  `/etc/runtime-hardening/allow/<ns>/java/GROUP` or `.../all/java/GROUP`, read with
  `Files.isRegularFile(NOFOLLOW_LINKS)`. `<ns>` is the service from `/proc/self/cgroup`.
- **Packaging**: epoch `1000 × policy.json revision + Wolfi epoch` sorts above every
  Wolfi rebuild; each package provides `wolfi-origin:openjdk-27:VERSION-rEPOCH` for CVE
  matching. Derivation stops for review when the checkout, the patch order, the test
  environment, image build step, subpackage names or the package identity changes.

## Behavior changes for applications

- `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS` and `JDK_ALTERNATE_VM` have
  no effect. Put the options on the command line or in an `@argfile` the command names.
- `--enable-native-access` on the command line grants nothing; use
  `allow: [java:native]` or an `Enable-Native-Access` manifest entry.
- Libraries that reach native code or memory, `sun.misc.Unsafe`, the Foreign Function
  and Memory API or JNI (older Netty, Kryo, Chronicle, Kafka, zstd-jni), need
  `allow: [java:native]`.
- RMI, JMX remoting, and anything that reads Java serialization need
  `allow: [java:deserialize]`.
- `jcmd`, `jstack`, `jmap` and attach agents need the target started with
  `-XX:-DisableAttachMechanism`; that flag opens attach for that process alone.

`inline` (jshell) and `writable-source` (a class or jar on a writable mount) are not
yet gated for Java: jshell goes with the jlink JRE and writable code with the phase-2
`defineClass` seal, both deferred (see the design doc). Packages hold nothing under
`/etc/runtime-hardening`.

## Still read from the environment

- `CLASSPATH`, when no `-cp` or `-jar` is given; set the class path explicitly.
- `JDK_AOT_VM_OPTIONS`, only with `-XX:AOTMode=create`.
- `_JAVA_LAUNCHER_DEBUG`, which traces the launcher to standard output.
- `_JAVA_SPLASH_FILE` and `_JAVA_SPLASH_JAR`, a splash image, shown only with a display.

## Deferred

- A jlink-built runtime without `jdk.attach`, `java.rmi`, `java.management.rmi` and
  `jdk.jdwp.agent`; today these modules ship, and only argv or an allowance opens them.
  Revisit a separate `-jmods` package when a concrete runtime build needs it; Wolfi's
  linkable-runtime build and existing jlink tests remain enabled.

## Building

`make PACKAGE=openjdk refresh check derive prepare build` captures Wolfi's recipe,
verifies it, applies every patch and builds with Melange ([README](../../README.md)).
Unit tests, from the repository root:

    python3 -m unittest discover -s packages/openjdk/tests -p 'test_*.py'

Patches are GPL-2.0-only WITH Classpath-exception-2.0, as OpenJDK; Wolfi inputs keep
their license.
