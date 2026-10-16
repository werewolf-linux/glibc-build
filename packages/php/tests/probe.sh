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
server_pid=
cleanup() {
    if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
    rm -rf "$work" "$allowdir"
}
trap cleanup EXIT

grant() { mkdir -p "$base"; : > "$base/$1"; }
revoke() { rm -f "$base/$1"; }

expect() {
	name=$1; want=$2; shift 2
	if got=$("$@" 2>"$work/err") && [ "$got" = "$want" ]; then echo "probe: ok: $name"; return; fi
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
echo '<?php @eval('"'"'echo "eval ran";'"'"');' > "$work/eval.php"

cat > "$work/user-stream.php" <<'SOURCE'
<?php
class Source {
    public $context;
    function stream_open($p, $m, $o, &$opened) { return true; }
    private $code = "<?php echo 123;";
    function stream_read($n) { $code = $this->code; $this->code = ""; return $code; }
    function stream_stat() { return []; }
    function url_stat($p, $f) { return []; }
    function stream_eof() { return $this->code === ""; }
}
stream_wrapper_register("unverified", Source::class);
include "unverified://source";
SOURCE
printf '<?php include "php://filter/resource=%s/child.php";\n' "$work" > "$work/filter.php"

report() { "$php" "$probe"; }

# The probe is a script on a writable mount, so running it needs writable-source;
# that is the harness enabler, tested on its own with a child below.
rm -rf "$allowdir"
grant writable-source

closed='{"deserialize":false,"exec":false,"native":false,"phar":false,"phar_class":false,"phar_extension":false}'
expect 'closed: no exec, native, deserialize or phar' "$closed" report
grep -F '"group":"deserialize"' "$work/err" | grep -F '"detail":"stdClass"'

cat > "$work/caught.php" <<'PHP'
<?php
ini_set('display_errors', '0');
ini_set('log_errors', '0');
foreach (['system', 'dl'] as $function) {
    try { $function('denied-argument'); } catch (Throwable $e) { }
}
try { system('denied-argument'); } catch (Throwable $e) { }
echo "blocked";
PHP
expect 'caught function denials bypass PHP error settings' blocked "$php" "$work/caught.php"
grep -F '"group":"exec"' "$work/err" | grep -F '"operation":"system"'
grep -F '"group":"native"' "$work/err" | grep -F '"operation":"dl"'
test "$(grep -c '"operation":"system"' "$work/err")" = 2

# inline: -r gives code, refused unless php:inline.
refuse '-r is refused' php:inline "$php" -r 'echo 1;'
grant inline
expect '-r returns once inline is allowed' '1' "$php" -r 'echo 1;'
revoke inline
refuse 'eval, even suppressed, needs inline' php:inline "$php" "$work/eval.php"
cat > "$work/caught-eval.php" <<'PHP'
<?php
ini_set('display_errors', '0');
ini_set('log_errors', '0');
try { @eval('return 7;'); } catch (Error $error) { }
echo "blocked";
PHP
expect 'caught eval denial bypasses PHP error settings' blocked "$php" "$work/caught-eval.php"
grep -F '"group":"inline"' "$work/err" | grep -F '"operation":"eval"'

grant inline
expect 'eval returns only with inline' 'eval ran' "$php" "$work/eval.php"
revoke inline

standard_input() { printf '%s\n' '<?php echo "stdin ran";' | "$php"; }
refuse 'writable-source does not grant stdin' php:inline standard_input
standard_input_path() { printf '%s\n' '<?php echo "stdin ran";' | "$php" -f php://stdin; }
refuse 'CLI rejects php://stdin as a filesystem path' 'input file' standard_input_path
refuse 'writable-source does not grant filters' php:inline "$php" "$work/filter.php"
refuse 'writable-source does not grant user streams' php:inline "$php" "$work/user-stream.php"
refuse 'auto_prepend_file cannot load a generated stream' php:inline \
    "$php" -d "auto_prepend_file=\"php://filter/resource=$work/child.php\"" "$work/child.php"
grant inline
expect 'filters need the inline group' 'script ran' "$php" "$work/filter.php"
expect 'user streams need the inline group' '123' "$php" "$work/user-stream.php"
revoke inline
revoke writable-source
refuse 'stdin needs inline' php:inline standard_input
grant inline
expect 'stdin returns with inline alone' 'stdin ran' standard_input
revoke inline

# writable-source: a script whose file is on a writable mount, refused unless allowed.
revoke writable-source
refuse 'a script on a writable mount is refused' php:writable-source "$php" "$work/child.php"
# A trusted entrypoint does not make the files it includes trusted. Inline is
# the harness enabler here; it must not grant writable-source or stream wrappers.
grant inline
for construct in include include_once require require_once; do
    refuse "$construct refuses writable code" php:writable-source \
        "$php" -r "$construct '$work/child.php';"
done
refuse 'include_path cannot hide writable code' php:writable-source \
    "$php" -d "include_path=$work" -r "include 'child.php';"
ln -s "$work/child.php" "$work/alias.php"
refuse 'a source symlink is checked by its target descriptor' php:writable-source \
    "$php" -r "include '$work/alias.php';"
refuse 'file:// cannot hide writable code' php:writable-source \
    "$php" -r "include 'file://$work/child.php';"
# auto_prepend_file must not bypass the gate.
refuse 'auto_prepend_file refuses writable code' php:writable-source \
    "$php" -d "auto_prepend_file=$work/child.php" "$work/child.php"
grant writable-source
expect 'inline and writable-source grants compose' 'script ran' \
    "$php" -r "include '$work/child.php';"
revoke inline
expect 'the same script runs once writable-source is allowed' 'script ran' "$php" "$work/child.php"

# Warm the shared OPcache in a persistent process, then remove only the file
# allowance. A cache hit must still cross the source guard, without a restart.
printf '%s\n' '<?php $s = opcache_get_status(false); echo $s && $s["opcache_statistics"]["num_cached_scripts"] > 0 ? "cached" : "uncached";' > "$work/cache.php"
port=$((18000 + $$ % 30000))
"$php" -d opcache.enable=1 -d opcache.enable_cli=1 -d opcache.validate_timestamps=0 \
    -d opcache.file_update_protection=0 -d display_errors=stderr \
    -S "127.0.0.1:$port" -t "$work" >"$work/server.log" 2>&1 &
server_pid=$!
ready=false
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --max-time 1 -o /dev/null "http://127.0.0.1:$port/child.php"; then ready=true; break; fi
    sleep 0.1
done
[ "$ready" = true ] || { cat "$work/server.log" >&2; exit 1; }
expect 'OPcache really holds compiled code' cached curl -fsS --max-time 5 "http://127.0.0.1:$port/cache.php"
expect 'warm script executes' 'script ran' curl -fsS --max-time 5 "http://127.0.0.1:$port/child.php"
revoke writable-source
: > "$work/cache-response"
: > "$work/server.log"
# PHP may preserve HTTP 200 when display_errors=stderr. Judge execution and
# the refusal diagnostic, not just the HTTP status.
if curl -fsS --max-time 5 -o "$work/cache-response" "http://127.0.0.1:$port/child.php"; then
    :
else
    [ "$?" = 22 ] || { cat "$work/server.log" >&2; exit 1; }
fi
grep -q php:writable-source "$work/server.log"
if grep -q 'script ran' "$work/cache-response"; then
    echo 'probe: FAIL: cached writable code ran without its allowance' >&2; exit 1
fi
echo 'probe: ok: cached writable code is refused without a restart'
grant writable-source
expect 'the running cache observes the restored allowance' 'script ran' \
    curl -fsS --max-time 5 "http://127.0.0.1:$port/child.php"
kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=

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
