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
from collections.abc import Iterator, Mapping
from contextlib import contextmanager

from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.input_spec import EnvironmentVariable, InputSpecification

from .actions import register_actions
from .asset import Asset
from .test_connectivity import run_test_connectivity


PROXY_ENVIRONMENT_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY")


@contextmanager
def _apply_soar_proxy_environment(
    environment_variables: Mapping[str, EnvironmentVariable],
) -> Iterator[None]:
    """Expose SOAR-managed proxy values to httpx for one synchronous app run."""
    supplied_proxies = {
        name: environment_variables[name].value
        for name in PROXY_ENVIRONMENT_VARIABLES
        if name in environment_variables
    }
    previous_values = {name: os.environ.get(name) for name in supplied_proxies}

    try:
        os.environ.update(supplied_proxies)
        yield
    finally:
        for name, previous_value in previous_values.items():
            if previous_value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous_value


class WildFireApp(App):
    """WildFire app with legacy-compatible SOAR proxy propagation."""

    def handle(self, raw_input_data: str, handle: int | None = None) -> str:
        """Run an action with SOAR-managed HTTP proxies visible to httpx."""
        input_data = InputSpecification.model_validate_json(raw_input_data)
        with _apply_soar_proxy_environment(input_data.environment_variables):
            return super().handle(raw_input_data, handle)


def create_wildfire_connector_app() -> App:
    """Create the WildFire connector app and register its actions."""
    app = WildFireApp(
        name="WildFire",
        app_type="sandbox",
        logo="logo_paloaltonetworks.svg",
        logo_dark="logo_paloaltonetworks_dark.svg",
        product_vendor="Palo Alto Networks",
        product_name="WildFire",
        publisher="Splunk",
        appid="c5aa8f59-6a3e-4031-b321-69068c725c68",
        fips_compliant=True,
        encrypt_cache_state=True,
        encrypt_ingest_state=True,
        asset_cls=Asset,
    )

    @app.test_connectivity()
    def test_connectivity(soar: SOARClient, asset: Asset) -> None:
        """Upload the bundled test PDF to verify WildFire connectivity."""
        run_test_connectivity(soar, asset)

    return register_actions(app)


app: App = create_wildfire_connector_app()


if __name__ == "__main__":
    app.cli()
