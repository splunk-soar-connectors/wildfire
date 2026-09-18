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
from soar_sdk.app import App

from .actions import register_actions
from .asset import Asset


def create_wildfire_connector_app() -> App:
    """Create the WildFire connector app and register its actions."""
    app = App(
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
    return register_actions(app)


app: App = create_wildfire_connector_app()


if __name__ == "__main__":
    app.cli()
