# What this Python lets a program do, as one JSON line; tests/probe.sh compares
# it with what the protections in patches/series and the image's allowances say.
import importlib
import json
import site
import sqlite3
import sys


def imports(name):
    try:
        importlib.import_module(name)
    except ImportError:
        return False
    return True


print(json.dumps({
    'ignore_environment': sys.flags.ignore_environment,
    'no_user_site': sys.flags.no_user_site,
    'user_site': bool(site.ENABLE_USER_SITE),
    'sibling': imports('sibling'),          # beside this script: still on sys.path
    'pythonpath': imports('pathevil'),      # in PYTHONPATH
    'userbase': imports('userevil'),        # in PYTHONUSERBASE's site-packages
    'sqlite_extensions': hasattr(sqlite3.Connection, 'enable_load_extension'),
    'ctypes': imports('ctypes'),
}, sort_keys=True))
