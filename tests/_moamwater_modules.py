"""Import the moamwater integration's ``auth``/``api``/``const`` modules
directly, bypassing ``custom_components/moamwater/__init__.py`` (which pulls
in the ``homeassistant`` package). This lets the auth/api logic be unit
tested without installing all of Home Assistant.

Both ``auth.py`` and ``api.py`` only use relative imports (``from .const
import ...``) and (in auth.py) a ``TYPE_CHECKING``-only import of
``homeassistant.core.HomeAssistant``, so loading them under a synthetic
package name satisfies those relative imports without ever executing the
real package ``__init__.py``.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

_COMPONENT_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "moamwater"
_PKG_NAME = "_moamwater_under_test"


def _load(name: str) -> types.ModuleType:
    full_name = f"{_PKG_NAME}.{name}"
    if full_name in sys.modules:
        return sys.modules[full_name]
    spec = importlib.util.spec_from_file_location(full_name, _COMPONENT_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


if _PKG_NAME not in sys.modules:
    pkg = types.ModuleType(_PKG_NAME)
    pkg.__path__ = [str(_COMPONENT_DIR)]
    sys.modules[_PKG_NAME] = pkg

const = _load("const")
auth = _load("auth")
api = _load("api")
