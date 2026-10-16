#!/bin/sh
# probe.sh PROBE holds the installed python3 to the protections patches/series
# compiles in, then takes back ctypes with an allowance and sees it return.
# The package test runs it as root, with /etc/werewolf/allow/python free to
# use (scripts/derive.py embeds it). PYTHON names another interpreter, and
# ALLOW another allowance directory, for a test build of the patched source.
set -eu
probe=$1
python=${PYTHON:-python3}
allow=${ALLOW:-/etc/werewolf/allow/python}
work=$(mktemp -d)
trap 'rm -rf "$work" "$allow"' EXIT

expect() {
	name=$1
	want=$2
	shift 2
	got=$("$@" 2>"$work/stderr") || true
	if [ "$got" != "$want" ]; then
		echo "probe: FAIL: $name" >&2
		echo "  want $want" >&2
		echo "  got  $got" >&2
		cat "$work/stderr" >&2
		exit 1
	fi
	echo "probe: ok: $name"
}

# Every PYTHON* variable that would add code: a path, a user base, a startup file.
version=$("$python" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
mkdir -p "$work/script" "$work/path" "$work/userbase/lib/python$version/site-packages" "$work/cwd"
cp "$probe" "$work/script/probe.py"
echo 'NAME = "sibling"' >"$work/script/sibling.py"
echo 'print("pathevil")' >"$work/path/pathevil.py"
echo 'print("userevil")' >"$work/userbase/lib/python$version/site-packages/userevil.py"
echo 'print("startup ran")' >"$work/startup.py"
echo 'print("cwdevil")' >"$work/cwd/cwdevil.py"
: >"$work/cwd/-"
run() {
	env PYTHONPATH="$work/path" PYTHONUSERBASE="$work/userbase" PYTHONSTARTUP="$work/startup.py" \
		"$python" "$@"
}

closed='{"ctypes": false, "ignore_environment": 1, "no_user_site": 1, "pythonpath": false, "sibling": true, "sqlite_extensions": false, "user_site": false, "userbase": false}'
rm -rf "$allow"
expect 'closed without allowances; PYTHON* variables ignored' "$closed" run "$work/script/probe.py"
expect 'PYTHONSTARTUP is ignored' '' run -i </dev/null
"$python" -c 'import ctypes' 2>"$work/refused" && { echo "probe: FAIL: ctypes imported" >&2; exit 1; }
grep -q 'python:ctypes' "$work/refused" || { echo "probe: FAIL: the refusal names no allowance" >&2; cat "$work/refused" >&2; exit 1; }
echo "probe: ok: the ctypes refusal names its allowance"

# The working directory, a service's writable data, is never on sys.path.
cd "$work/cwd"
expect '-m finds no module in the working directory' 'refused' \
	sh -c '"$1" -m cwdevil >/dev/null 2>&1 && echo found || echo refused' sh "$python"
expect '-c finds no module in the working directory' 'refused' \
	sh -c '"$1" -c "import cwdevil" >/dev/null 2>&1 && echo found || echo refused' sh "$python"
expect 'stdin finds no module in the working directory, even beside a file named -' 'refused' \
	sh -c 'echo "import cwdevil" | "$1" - >/dev/null 2>&1 && echo found || echo refused' sh "$python"
cd /

# The allowance takes back ctypes, and nothing else.
mkdir -p "$allow"
: >"$allow/ctypes"
expect 'the ctypes allowance takes back ctypes' \
	'{"ctypes": true, "ignore_environment": 1, "no_user_site": 1, "pythonpath": false, "sibling": true, "sqlite_extensions": false, "user_site": false, "userbase": false}' \
	run "$work/script/probe.py"

# The build guest's environment allowance takes back PYTHON* variables, never
# the user site; werewolf's forms cannot grant it.
rm -f "$allow/ctypes"
: >"$allow/environment"
expect 'the environment allowance takes back PYTHON* variables alone' \
	'pathevil
{"ctypes": false, "ignore_environment": 0, "no_user_site": 1, "pythonpath": true, "sibling": true, "sqlite_extensions": false, "user_site": false, "userbase": false}' \
	run "$work/script/probe.py"
rm -f "$allow/environment"

# A link is not an allowance, even to a file: lock times will be links.
: >"$work/target"
ln -s "$work/target" "$allow/ctypes"
ln -s "$work/target" "$allow/environment"
expect 'a link is not an allowance' "$closed" run "$work/script/probe.py"
