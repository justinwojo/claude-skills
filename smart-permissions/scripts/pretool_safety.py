#!/usr/bin/env python3
"""PreToolUse hook entry point. The code is smart_permissions/core.py: a
script run as __main__ is compiled on every call, an imported module runs
from its cached bytecode."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

if __name__ == "__main__":
    try:
        from smart_permissions import core
        found = os.path.dirname(core.__file__)
        if os.path.realpath(found) != os.path.realpath(os.path.join(HERE, "smart_permissions")):
            raise ImportError(f"smart_permissions was loaded from {found}")
        core.main()
    except Exception as e:  # a missing, broken or foreign package blocks the call, as a missing script does
        sys.stderr.write(f"smart-permissions could not start ({type(e).__name__}: {e}). The call is "
                         "blocked: the smart_permissions folder beside this script is missing or "
                         "broken; reinstall it.\n")
        sys.exit(2)
else:  # `import pretool_safety` is the real module, so a rebound global reaches its code
    from smart_permissions import core
    sys.modules[__name__] = core
