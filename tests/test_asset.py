# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import pytest
from pydantic import ValidationError

from src.asset import Asset


@pytest.mark.parametrize(
    "base_url",
    [
        "wildfire.example.com",
        "/wildfire",
        "ftp://wildfire.example.com",
        "https://",
        "https://wildfire.example.com:invalid",
        "https://wild fire.example.com",
    ],
)
def test_asset_rejects_invalid_base_url(base_url: str) -> None:
    with pytest.raises(
        ValidationError, match=r"base_url must be an absolute HTTP\(S\) URL"
    ):
        Asset(base_url=base_url, api_key="redacted")  # pragma: allowlist secret


@pytest.mark.parametrize(
    "base_url",
    [
        "http://wildfire.example.com",
        "https://wildfire.example.com",
        "https://wildfire.example.com:8443/service/",
    ],
)
def test_asset_accepts_absolute_http_base_url_without_modification(
    base_url: str,
) -> None:
    asset = Asset(base_url=base_url, api_key="redacted")  # pragma: allowlist secret

    assert asset.base_url == base_url


@pytest.mark.parametrize("timeout", [-7, 0, 1.5])
def test_asset_rejects_non_positive_or_fractional_timeout(timeout: float) -> None:
    with pytest.raises(ValidationError):
        Asset(
            base_url="https://example.invalid",
            api_key="redacted",  # pragma: allowlist secret
            timeout=timeout,
        )


@pytest.mark.parametrize("timeout", [2, 2.0, "2"])
def test_asset_accepts_positive_integer_timeout(timeout: object) -> None:
    asset = Asset(
        base_url="https://example.invalid",
        api_key="redacted",  # pragma: allowlist secret
        timeout=timeout,
    )

    assert asset.timeout == 2
    assert isinstance(asset.timeout, int)
