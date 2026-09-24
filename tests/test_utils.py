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
from src.utils import WILDFIRE_HTTP_TIMEOUT


def test_wildfire_http_timeout_is_bounded() -> None:
    assert WILDFIRE_HTTP_TIMEOUT.connect == 10.0
    assert WILDFIRE_HTTP_TIMEOUT.read == 60.0
    assert WILDFIRE_HTTP_TIMEOUT.write == 60.0
    assert WILDFIRE_HTTP_TIMEOUT.pool == 10.0
