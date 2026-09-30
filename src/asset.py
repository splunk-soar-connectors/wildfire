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
from urllib.parse import urlsplit

from pydantic import PositiveInt, field_validator
from soar_sdk.asset import AssetField, BaseAsset


class Asset(BaseAsset):
    base_url: str = AssetField(
        description="Base URL to WildFire service",
        default="https://wildfire.paloaltonetworks.com",
    )
    verify_server_cert: bool | None = AssetField(
        description="Verify server certificate", default=True
    )
    api_key: str = AssetField(description="API Key", sensitive=True)
    timeout: PositiveInt = AssetField(
        description="Detonate timeout in mins", default=10
    )

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        """Require an absolute HTTP(S) URL without changing the configured value."""
        if any(character.isspace() for character in value):
            raise ValueError("base_url must be an absolute HTTP(S) URL")

        parsed_url = urlsplit(value)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
            raise ValueError("base_url must be an absolute HTTP(S) URL")

        try:
            _ = parsed_url.port
        except ValueError as error:
            raise ValueError("base_url must be an absolute HTTP(S) URL") from error

        return value
