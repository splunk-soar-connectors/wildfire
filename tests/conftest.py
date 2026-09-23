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
import os
from collections.abc import Callable
from typing import Any, TypedDict

import pytest
from dotenv import find_dotenv, load_dotenv
from soar_sdk.app import App
from soar_sdk.shims.phantom.encryption_helper import encryption_helper

from src.app import create_wildfire_connector_app


class WildFireAssetConfig(TypedDict):
    base_url: str
    api_key: str
    verify_server_cert: bool


WildFireActionInputFactory = Callable[[str, str, list[dict[str, Any]]], dict[str, Any]]


@pytest.fixture(scope="session")
def wildfire_asset_config() -> WildFireAssetConfig:
    """Load the real WildFire asset configuration without logging credentials."""
    if not os.getenv("WILDFIRE_BASE_URL") or not os.getenv("WILDFIRE_API_KEY"):
        env_path = find_dotenv(usecwd=True)
        if env_path:
            load_dotenv(env_path, override=False)

    missing = [
        name
        for name in ("WILDFIRE_BASE_URL", "WILDFIRE_API_KEY")
        if not os.getenv(name)
    ]
    if missing:
        pytest.fail(
            "Missing required WildFire live-test environment variables: "
            + ", ".join(missing)
        )

    verify_value = os.getenv("WILDFIRE_VERIFY_SERVER_CERT", "true").strip().lower()
    if verify_value not in {"true", "false"}:
        pytest.fail("WILDFIRE_VERIFY_SERVER_CERT must be 'true' or 'false'")

    return {
        "base_url": os.environ["WILDFIRE_BASE_URL"],
        "api_key": os.environ["WILDFIRE_API_KEY"],
        "verify_server_cert": verify_value == "true",
    }


@pytest.fixture
def wildfire_app() -> App:
    """Create an isolated connector app for one test."""
    return create_wildfire_connector_app()


@pytest.fixture
def wildfire_action_input(
    wildfire_asset_config: WildFireAssetConfig,
) -> WildFireActionInputFactory:
    """Build a connector action payload from the real WildFire asset config."""
    asset_id = "wildfire-live-test"

    def create(
        identifier: str, action: str, parameters: list[dict[str, Any]]
    ) -> dict[str, Any]:
        return {
            "identifier": identifier,
            "action": action,
            "asset_id": asset_id,
            "container_id": 456,
            "config": {
                "app_version": "4.0.0",
                "directory": ".",
                "main_module": "src.app:app",
                "base_url": wildfire_asset_config["base_url"],
                "verify_server_cert": wildfire_asset_config["verify_server_cert"],
                "api_key": encryption_helper.encrypt(
                    wildfire_asset_config["api_key"], salt=asset_id
                ),
            },
            "parameters": parameters,
        }

    return create
