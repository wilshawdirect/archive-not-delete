import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from helpers import Env, make_env  # noqa: E402


@pytest.fixture
def env(tmp_path) -> Env:
    """One root named ``data`` (files must be at least a day old), a local archive, a manifest."""
    return make_env(tmp_path)
