"""The `mock` fixture of the end-to-end tests (`-m e2e`): one `nc-mock` for the whole run.

`NOBLECLOAK_E2E_URL` names a mock that is already listening (CI starts one on port 8787 and sets it); without it the
fixture starts one from the frozen install in `conformance/`. Either way a mock that cannot be reached fails the run.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from e2e_support import Mock, attach, spawn_mock


@pytest.fixture(scope="session")
def mock() -> Iterator[Mock]:
    url = os.environ.get("NOBLECLOAK_E2E_URL")
    if url:
        yield attach(url)
    else:
        with spawn_mock() as started:
            yield started
