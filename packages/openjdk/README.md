# openjdk

Werewolf's OpenJDK: Wolfi's newest stable `openjdk-27` recipe, captured unchanged,
plus six policy patches
([design](https://github.com/werewolf-linux/werewolf/blob/main/docs/design/hardened-interpreters.md)).
Packages keep Wolfi's names, so forms that install `openjdk-27` or its `-jre` and
`-default-jdk` subpackages get it.

## Differences from Wolfi's build

Same as Wolfi: source commit, Wolfi's patch, toolchain, configure options, build and
install steps, every subpackage and package test.

- **Source**: the locked commit is fetched from `jdk27u`, then from mainline `jdk`,
  which holds each GA tag, in place of Wolfi's checkout.
- **Patches** (`patches/series`), applied after Wolfi's:
  1. HotSpot ignores `_JAVA_OPTIONS` and `JAVA_TOOL_OPTIONS`; the launcher ignores
     `JDK_JAVA_OPTIONS` and `JDK_ALTERNATE_VM`, which loads any directory's `libjvm.so`.
  2. `DisableAttachMechanism` defaults to true: no `jcmd`, `jstack` or agent attach.
  3. `jdk.internal.misc.WerewolfAllowance` reads allowances: an allowance is a regular
     file, never a link, in `/etc/werewolf/allow/java`.
  4. `ObjectInputStream` refuses every class but primitive arrays, as the filter `!*`
     would, unless `deserialize` is allowed. No filter, filter factory or
     `jdk.serialFilter` takes this back.
  5. `sun.misc.Unsafe` memory access is denied unless `unsafe` is allowed, whatever
     `--sun-misc-unsafe-memory-access` says.
  6. Illegal native access (JNI, FFM restricted methods) is denied unless
     `native-access` is allowed, whatever `--illegal-native-access` says, and
     `--enable-native-access` grants nothing without it. A JAR manifest's
     `Enable-Native-Access` still grants, as the image's own jars may.
- **Tests**: Wolfi's tests, then `tests/probe.sh` with `tests/Probe.java`, which check
  each protection, that the environment and argv lift none, that a manifest still
  grants native access, and that each allowance, and only a regular file, takes back
  what it names and nothing else.
- **Packaging**: epoch `1000 × policy.json revision + Wolfi epoch` sorts above every
  Wolfi rebuild; each package provides `wolfi-origin:openjdk-27:VERSION-rEPOCH` for CVE
  matching. Derivation stops for review when the checkout, the patch order, the test
  environment or the package identity changes.

## Behavior changes for applications

- `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS` and `JDK_ALTERNATE_VM` have
  no effect. Put the options on the command line or in an `@argfile` the command names.
- Native code from the class path needs `allow: [java:native-access]` in `form.yaml`, or
  an `Enable-Native-Access` manifest entry. Kafka, OpenSearch, Netty's native
  transports and zstd-jni users need one or the other.
- Libraries that use `sun.misc.Unsafe` memory access (older Netty, Kryo, Chronicle,
  some serializers) need `allow: [java:unsafe]`.
- RMI, JMX remoting, and anything that reads Java serialization need
  `allow: [java:deserialize]`.
- `jcmd`, `jstack`, `jmap` and attach agents need the target started with
  `-XX:-DisableAttachMechanism`; that flag opens attach for that process alone.

Allowances are build-time: `allow: [java:NAME]` writes
`/etc/werewolf/allow/java/NAME` on the read-only root. Packages hold nothing under
`/etc/werewolf`.

## Still read from the environment

- `CLASSPATH`, when no `-cp` or `-jar` is given; set the class path explicitly.
- `JDK_AOT_VM_OPTIONS`, only with `-XX:AOTMode=create`.
- `_JAVA_LAUNCHER_DEBUG`, which traces the launcher to standard output.
- `_JAVA_SPLASH_FILE` and `_JAVA_SPLASH_JAR`, a splash image, shown only with a display.

## Deferred

- A jlink-built runtime without `jdk.attach`, `java.rmi`, `java.management.rmi` and
  `jdk.jdwp.agent`; today these modules ship, and only argv or an allowance opens them.

## Building

`make PACKAGE=openjdk refresh check derive prepare build` captures Wolfi's recipe,
verifies it, applies every patch and builds with Melange ([README](../../README.md)).
Unit tests, from the repository root:

    python3 -m unittest discover -s packages/openjdk/tests -p 'test_*.py'

Patches are GPL-2.0-only WITH Classpath-exception-2.0, as OpenJDK; Wolfi inputs keep
their license.
