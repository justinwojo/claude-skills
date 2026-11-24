#!/usr/bin/env python3
"""PermissionRequest hook entry point. The code is smart_permissions/learner.py
(see pretool_safety.py for why the hooks run through a shim)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smart_permissions import learner  # noqa: E402

if __name__ == "__main__":
    learner.main()
else:  # `import permission_learner` is the real module
    sys.modules[__name__] = learner
