#!/usr/bin/env python3
"""PermissionRequest hook entry point. The code is smart_permissions/learner.py
(see pretool_safety.py for why the hooks run through a shim)."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from smart_permissions import learner  # noqa: E402

if __name__ == "__main__":
    # Only the package beside this script; any other copy is no decision
    # (exit 1: Claude Code shows its own dialog).
    found = os.path.dirname(learner.__file__)
    if os.path.realpath(found) != os.path.realpath(os.path.join(HERE, "smart_permissions")):
        sys.exit(f"smart-permissions: smart_permissions was loaded from {found}, not from beside this script")
    learner.main()
else:  # `import permission_learner` is the real module
    sys.modules[__name__] = learner
