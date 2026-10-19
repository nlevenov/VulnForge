"""The bind guard must refuse to serve to anything but loopback unless the
operator has explicitly, knowingly opted into exposure."""

import pytest

from vulnforge.config import Config
from vulnforge.safety import ExposureRefused, check_bind


def test_loopback_is_allowed():
    for host in ("127.0.0.1", "::1", "localhost"):
        check_bind(Config(host=host))  # must not raise


def test_non_loopback_is_refused_by_default():
    with pytest.raises(ExposureRefused):
        check_bind(Config(host="0.0.0.0"))  # noqa: S104 - testing the guard
    with pytest.raises(ExposureRefused):
        check_bind(Config(host="192.168.1.10"))


def test_explicit_optin_allows_exposure():
    check_bind(Config(host="0.0.0.0", allow_exposure=True))  # noqa: S104 - explicit opt-in


def test_from_env_requires_exact_optin_phrase(monkeypatch):
    monkeypatch.setenv("VULNFORGE_HOST", "0.0.0.0")
    monkeypatch.setenv("VULNFORGE_ALLOW_EXPOSURE", "true")   # wrong phrase
    assert Config.from_env().allow_exposure is False
    monkeypatch.setenv("VULNFORGE_ALLOW_EXPOSURE", "yes-i-understand")
    assert Config.from_env().allow_exposure is True
