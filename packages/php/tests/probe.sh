#!/bin/sh
# probe.sh PROBE: hold the installed php to the protections in patches/series,
# then grant each capability group and see it return. The package test runs it
# as root with /etc/runtime-hardening/allow free to use. PHP names another
# binary and ALLOW another tree, for a dev build off the read-only root.
set -eu
probe=$1
php=${PHP:-php}
allowdir=${ALLOW:-/etc/runtime-hardening/allow}
base=$allowdir/all/php
work=$(mktemp -d)
trap 'rm -rf "$work" "$allowdir"' EXIT

grant() { mkdir -p "$base"; : > "$base/$1"; }
revoke() { rm -f "$base/$1"; }

expect() {
	name=$1; want=$2; shift 2
	got=$("$@" 2>"$work/err") || true
	if [ "$got" = "$want" ]; then echo "probe: ok: $name"; return; fi
	echo "probe: FAIL: $name" >&2
	echo "  want $want" >&2
	echo "  got  $got" >&2
	cat "$work/err" >&2
	exit 1
}

refuse() {
	name=$1; token=$2; shift 2
	if "$@" >/dev/null 2>"$work/err"; then
		echo "probe: FAIL: $name ran" >&2
		exit 1
	fi
	if ! grep -q "$token" "$work/err"; then
		echo "probe: FAIL: $name refusal does not name $token" >&2
		cat "$work/err" >&2
		exit 1
	fi
	echo "probe: ok: $name"
}

echo '<?php echo "script ran";' > "$work/child.php"
report() { "$php" "$probe"; }

# The probe is a script on a writable mount, so running it needs writable-source;
# that is the harness enabler, tested on its own with a child below.
rm -rf "$allowdir"
grant writable-source

closed='{"deserialize":false,"exec":false,"native":false,"phar":false,"phar_class":false,"phar_extension":false}'
expect 'closed: no exec, native, deserialize or phar' "$closed" report

# inline: -r gives code, refused unless php:inline.
refuse '-r is refused' php:inline "$php" -r 'echo 1;'
grant inline
expect '-r returns once inline is allowed' '1' "$php" -r 'echo 1;'
revoke inline

# writable-source: a script whose file is on a writable mount, refused unless allowed.
revoke writable-source
refuse 'a script on a writable mount is refused' php:writable-source "$php" "$work/child.php"
grant writable-source
expect 'the same script runs once writable-source is allowed' 'script ran' "$php" "$work/child.php"

# exec, native and deserialize each return with their group alone.
for group in exec native deserialize; do
	grant "$group"
	expect "$group is taken back alone" \
		"$(printf '%s' "$closed" | sed 's/"'"$group"'":false/"'"$group"'":true/')" report
	revoke "$group"
done

# Phar is not built; an allowance cannot restore its extension, class or wrapper.
grant phar
expect 'Phar stays absent even with an allowance' "$closed" report
revoke phar

# A link is not an allowance, even to a regular file: lock times will be links.
: > "$work/target"
ln -s "$work/target" "$base/exec"
expect 'a link is not an allowance' "$closed" report
rm -f "$base/exec"

echo "probe: ok: every php protection holds, and each group takes its own back"
