#!/usr/bin/env python3
"""PreToolUse hook entry point. The code is smart_permissions/core.py: a
script run as __main__ is compiled on every call, an imported module runs
from its cached bytecode."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smart_permissions import core  # noqa: E402

if __name__ == "__main__":
    core.main()
else:  # `import pretool_safety` is the real module, so a rebound global reaches its code
    sys.modules[__name__] = core
