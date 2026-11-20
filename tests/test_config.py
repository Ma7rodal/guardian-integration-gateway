import base64
import os

import pytest
from pydantic import ValidationError

from app.config import DEFAULT_DEMO_ENCRYPTION_KEY, Settings


def _custom_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def test_production_rejects_default_encryption_key():
    with pytest.raises(ValidationError, match="default demo key is forbidden"):
        Settings(
            environment="production",
            encryption_key=DEFAULT_DEMO_ENCRYPTION_KEY,
        )


def test_production_with_custom_key_disables_failure_simulation():
    settings = Settings(
        environment="production",
        encryption_key=_custom_key(),
        allow_failure_simulation=True,  # Must still be ignored in production
    )
    assert settings.can_simulate_failures is False


def test_development_respects_allow_failure_simulation_flag():
    enabled = Settings(environment="development", allow_failure_simulation=True)
    disabled = Settings(environment="development", allow_failure_simulation=False)

    assert enabled.can_simulate_failures is True
    assert disabled.can_simulate_failures is False
