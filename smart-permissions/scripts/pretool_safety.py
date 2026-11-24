#!/usr/bin/env python3
"""PreToolUse hook entry point. The code is smart_permissions/core.py: a
script run as __main__ is compiled on every call, an imported module runs
from its cached bytecode."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    try:
        from smart_permissions import core
        core.main()
    except Exception as e:  # a missing or broken package blocks the call, as a missing script does
        sys.stderr.write(f"smart-permissions could not start ({type(e).__name__}: {e}). The call is "
                         "blocked: the smart_permissions folder beside this script is missing or "
                         "broken; reinstall it.\n")
        sys.exit(2)
else:  # `import pretool_safety` is the real module, so a rebound global reaches its code
    from smart_permissions import core
    sys.modules[__name__] = core
