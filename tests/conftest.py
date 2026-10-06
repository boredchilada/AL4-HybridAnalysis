"""All tests run offline against the fake Hybrid Analysis client."""

import os
from pathlib import Path

os.environ.setdefault("SERVICE_MANIFEST_PATH", str(Path(__file__).resolve().parent.parent / "service_manifest.yml"))

from tests import fake_ha  # noqa: E402

fake_ha.install()
